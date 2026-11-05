"""argparse CLI: ideas | inventory | run | publish (§9, §10); the article-to-idea tool lives here (§7.1)."""

import argparse
import re
import sys
import time
import uuid
from pathlib import Path

import pypdf
import trafilatura
import yaml
from pydantic import ValidationError

from . import llm, prompts, spl
from . import splunk as splunk_mod
from .models import Detection, Idea, IdeasOut, Inventory
from .pipeline import EXIT_CODES, Config, Pipeline

MITRE = re.compile(r"^T\d{4}(\.\d{3})?$")
FILTER_MACRO = re.compile(r"`(\w+_filter)`\s*$")  # the trailing filter macro `with_filter` appends to every search
MAX_TEXT = 100_000


def extract_text(src: str) -> tuple[str, str]:
    """Return (article text, source_url) for a URL or a local .html/.htm/.txt/.md/.pdf file."""
    extract = lambda html: trafilatura.extract(html or "", output_format="markdown", include_comments=False, favor_recall=True) or ""
    if src.startswith(("http://", "https://")):
        return extract(trafilatura.fetch_url(src)), src
    path = Path(src)
    if path.suffix.lower() == ".pdf":
        return "\n".join(p.extract_text() or "" for p in pypdf.PdfReader(path).pages), src
    if path.suffix.lower() in (".txt", ".md"):
        return path.read_text(), src
    return extract(path.read_text()), src


def ideas(src: str, out_dir: Path, model: str | None = None) -> list[Path]:
    text, url = extract_text(src)
    if len(text) < 200:
        raise ValueError(f"{src}: extracted text is empty (< 200 chars)")
    if len(text) > MAX_TEXT:
        print(f"warning: article text truncated to {MAX_TEXT} chars", file=sys.stderr)
    out, _ = llm.ask("ideas", {"text": text[:MAX_TEXT]}, IdeasOut, model=model)
    out_dir.mkdir(parents=True, exist_ok=True)
    written = []
    for d in out.ideas:
        if not d.attack_steps or not d.log_sources:
            print(f"warning: skipping '{d.title}': no attack_steps or log_sources", file=sys.stderr)
            continue
        data = d.model_dump() | {"title": d.title[:99], "summary": d.summary[:600],
                                 "mitre_attack_id": [m for m in d.mitre_attack_id if MITRE.match(m)]}
        try:
            idea = Idea(id=str(uuid.uuid4()), source_url=url, **data)
        except ValidationError as e:
            print(f"warning: skipping '{d.title}': {e}", file=sys.stderr)
            continue
        path = out_dir / f"{idea.stem}.yml"
        if path.exists():
            print(f"{path} exists")
            continue
        path.write_text(yaml.safe_dump(idea.model_dump(exclude_none=True), sort_keys=False, allow_unicode=True))
        print(path)
        written.append(path)
    return written


def load_inventory(path: Path, splunk, window: str, refresh: bool, max_age_h: int = 24, max_sourcetypes: int = 200) -> Inventory:
    if not refresh and path.exists() and time.time() - path.stat().st_mtime < max_age_h * 3600:
        return Inventory.model_validate_json(path.read_text())
    inv = splunk.inventory(window=window, max_sourcetypes=max_sourcetypes)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(inv.model_dump_json(indent=2))
    return inv


def publish(paths: list[Path], splunk, es: bool, dry_run: bool) -> int:
    missing = [p for p in paths if not p.exists()]
    for p in missing:
        print(f"{p}: not found, skipping", file=sys.stderr)
    files = [f for p in paths if p not in missing for f in (sorted(p.glob("*.yml")) if p.is_dir() else [p])]
    rc = 0
    for f in files:
        try:
            det = Detection.model_validate(yaml.safe_load(f.read_text()))
            props = det.conf_props(es)
            # the sibling macros/<stem>_filter.yml must exist on Splunk before the search can run; publish it first
            m = FILTER_MACRO.search(det.search)
            macro = (m[1], yaml.safe_load((f.parent / "macros" / f"{m[1]}.yml").read_text())["definition"]) if m else None
            if dry_run:
                if macro:
                    print(f"[{macro[0]}]", f"definition = {macro[1]}", "", sep="\n")
                print(f"[{det.name}]", f"search = {det.search}", *(f"{k} = {v}" for k, v in props.items()), sep="\n")
            else:
                if macro:
                    splunk.publish_macro(*macro)
                print(splunk.publish(det.name, det.search, props))
        except Exception as e:
            print(f"{f}: {e}", file=sys.stderr)
            rc = 1
    return rc


def _model_spec(value: str) -> tuple[str, str]:
    step, sep, model = value.partition("=")
    if not sep or step not in prompts.MODEL or not model:
        raise argparse.ArgumentTypeError(f"expected STEP=MODEL with STEP in {sorted(prompts.MODEL)}, got {value!r}")
    return step, model


def _window(value: str) -> str:
    try:
        spl.window_seconds(value)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e)) from None
    return value


def _run(args) -> int:
    idea = Idea.load(args.idea)
    splunk = splunk_mod.get(args.splunk)
    inventory = load_inventory(args.inventory, splunk, args.window, args.refresh)
    config = Config(max_tunes=args.tunes, max_remakes=args.remakes, max_reviews=args.reviews, max_cost_usd=args.max_cost,
                    window=args.window, attack_index=args.attack_index, out_dir=str(args.out),
                    max_scan_count=args.max_scan, models=dict(args.model), verbose=args.verbose)
    run_dir = args.runs / idea.id
    if args.resume and (run_dir / "state.json").exists():
        pipe = Pipeline.load(run_dir, idea, inventory, splunk, config)
    else:
        pipe = Pipeline(idea, inventory, splunk, config, run_dir, args.idea)
    state = pipe.drive()
    print(f"{state}  tunes={pipe.tunes} remakes={pipe.remakes} reviews={pipe.reviews} cost_usd={pipe.cost_usd:.2f}")
    extra = pipe.outputs or ([str(run_dir / "coverage.md")] if state == "infeasible" else pipe.gates.get("problems", []))
    for line in extra:
        print(line)
    if pipe.error:
        print(pipe.error, file=sys.stderr)
    return EXIT_CODES[state]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="dea")
    sub = p.add_subparsers(dest="cmd", required=True)

    pi = sub.add_parser("ideas", help="article (url | .html | .pdf | .txt | .md) -> idea YAMLs")
    pi.add_argument("src")
    pi.add_argument("-o", "--out", default="ideas", type=Path)
    pi.add_argument("--model")

    pv = sub.add_parser("inventory", help="fetch (or print cached) Splunk inventory")
    pr = sub.add_parser("run", help="idea YAML -> detection YAML")
    pp = sub.add_parser("publish", help="detection YAML(s) -> scheduled saved search")
    for sp in (pv, pr, pp):
        sp.add_argument("--splunk", choices=("mock", "real"))
    d = Config()
    for sp in (pv, pr):
        sp.add_argument("--window", default=d.window, type=_window, help="Splunk relative time, written as --window=-7d")
        sp.add_argument("--refresh", action="store_true")
    pv.add_argument("-o", "--out", default="inventory.json", type=Path)
    pv.add_argument("--max-sourcetypes", type=int, default=200)

    pr.add_argument("idea")
    pr.add_argument("--inventory", default="inventory.json", type=Path)
    pr.add_argument("--resume", action="store_true")
    pr.add_argument("--tunes", type=int, default=d.max_tunes)
    pr.add_argument("--remakes", type=int, default=d.max_remakes)
    pr.add_argument("--reviews", type=int, default=d.max_reviews)
    pr.add_argument("--max-cost", type=float, default=d.max_cost_usd)
    pr.add_argument("--attack-index", default=d.attack_index)
    pr.add_argument("--max-scan", type=int, default=d.max_scan_count)
    pr.add_argument("--model", type=_model_spec, action="append", default=[], help="STEP=MODEL (repeatable)")
    pr.add_argument("-o", "--out", default=Path(d.out_dir), type=Path)
    pr.add_argument("--runs", default="runs", type=Path)
    pr.add_argument("-v", "--verbose", action="store_true", help="print one line per state transition to stderr")

    pp.add_argument("paths", nargs="+", type=Path)
    pp.add_argument("--es", action="store_true")
    pp.add_argument("--dry-run", action="store_true")

    args = p.parse_args(argv)
    try:
        if args.cmd == "ideas":
            ideas(args.src, args.out, args.model)
            return 0
        if args.cmd == "inventory":
            inv = load_inventory(args.out, splunk_mod.get(args.splunk), args.window, args.refresh, max_sourcetypes=args.max_sourcetypes)
            print(*(f"{ix.name}\t{st.name}\t{st.count}" for ix in inv.indexes for st in ix.sourcetypes), sep="\n")
            return 0
        if args.cmd == "run":
            return _run(args)
        return publish(args.paths, None if args.dry_run else splunk_mod.get(args.splunk), args.es, args.dry_run)
    except Exception as e:
        print(f"error: {e}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
