"""Pipeline: one explicit `transitions` state machine driven by `drive()` (§5)."""

import re
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

from pydantic import BaseModel, ConfigDict
from transitions import Machine

from . import llm, prompts, spl
from .llm import CostCapExceeded
from .models import SOURCETYPE_META, Detection, Draft, Example, Idea, Inventory, ReviewOut, ReviewRound, Source, SplOut
from .splunk import Run, Splunk


class Config(BaseModel):
    model_config = ConfigDict(extra="forbid")
    max_tunes: int = 3
    max_remakes: int = 1
    max_reviews: int = 2
    max_cost_usd: float = 5.0
    window: str = "-7d"
    attack_index: str = "dea_attack"
    out_dir: str = "detections"
    max_scan_count: int = 50_000_000
    models: dict[str, str] = {}
    verbose: bool = False  # `dea run -v`: one stderr line per state transition


class PipelineState(BaseModel):
    model_config = ConfigDict(extra="forbid")
    state: str
    prior_state: str | None = None
    error: str | None = None
    idea_path: str
    splunk_kind: str
    run_id: str
    config: Config
    tunes: int = 0
    remakes: int = 0
    reviews: int = 0
    cost_usd: float = 0.0
    status_cap: str | None = None
    sources: list[Source] = []
    examples: list[Example] = []
    drafts: list[Draft] = []
    gates: dict = {}
    review_log: list[ReviewRound] = []
    failed_attempts: list[dict] = []
    history: list[dict] = []
    outputs: list[str] = []


STATE_FIELDS = tuple(PipelineState.model_fields)
STATES = ["start", "matched", "drafted", "tuning", "clean", "revising", "approved",
          "done", "infeasible", "failed_noisy", "failed_review", "error"]
TERMINAL = {"done", "infeasible", "failed_noisy", "failed_review", "error"}
EXIT_CODES = {"done": 0, "error": 1, "infeasible": 2, "failed_noisy": 3, "failed_review": 4}
TRANSITIONS = [
    {"trigger": "match", "source": "start", "dest": "matched", "prepare": "do_match", "conditions": "has_sources"},
    {"trigger": "match", "source": "start", "dest": "infeasible", "after": "write_coverage_note"},
    {"trigger": "author", "source": "matched", "dest": "drafted", "prepare": "do_author"},
    {"trigger": "test", "source": "drafted", "dest": "clean", "prepare": "do_test", "conditions": "is_clean"},
    {"trigger": "test", "source": "drafted", "dest": "tuning", "conditions": "can_tune", "after": "bump_tune"},
    {"trigger": "test", "source": "drafted", "dest": "matched", "conditions": "can_remake", "after": "bump_remake"},
    {"trigger": "test", "source": "drafted", "dest": "failed_noisy"},
    {"trigger": "tune", "source": "tuning", "dest": "drafted", "prepare": "do_tune"},
    {"trigger": "review", "source": "clean", "dest": "approved", "prepare": "do_review", "conditions": "review_pass"},
    {"trigger": "review", "source": "clean", "dest": "revising", "conditions": "can_refine", "after": "bump_review"},
    {"trigger": "review", "source": "clean", "dest": "approved", "conditions": "residual_acceptable", "after": "cap_experimental"},
    {"trigger": "review", "source": "clean", "dest": "failed_review"},
    {"trigger": "refine", "source": "revising", "dest": "drafted", "prepare": "do_refine"},
    {"trigger": "render", "source": "approved", "dest": "done", "prepare": "do_render"},
    {"trigger": "fail", "source": "*", "dest": "error", "before": "remember_prior"},
]
NEXT = {"start": "match", "matched": "author", "drafted": "test", "tuning": "tune", "clean": "review",
        "revising": "refine", "approved": "render"}


def finding_key(rnd: ReviewRound) -> list[tuple[str, str]]:
    return sorted((f.category, f.severity) for f in rnd.findings)


def _meta(sourcetype: str) -> tuple[str, str, str]:
    return next(((d, a, s) for rx, d, a, s in SOURCETYPE_META if re.search(rx, sourcetype, re.I)), (sourcetype, "Endpoint", "endpoint"))


def _matched(run: Run) -> int:
    """Events a recall search matched. resultCount alone lies: `| stats count` yields one row with count=0 on no match."""
    if not run.rows:
        return run.count or 0
    hits = 0
    for r in run.rows:
        c = str(r.get("count", 1))  # a row without a count column (| table) is one matched event
        hits += int(c) if c.isdigit() else 0  # count 0 or unreadable proves nothing
    return hits


def event_fields(raw: str | None) -> set[str]:
    """Field names an XML event carries (`<Data Name='X'>`); empty for non-XML samples, which are not checked."""
    return set(re.findall(r"<Data Name=['\"](\w+)['\"]>", raw or ""))


def strip_fields(raw: str, names: set[str]) -> str:
    return re.sub(rf"<Data Name=['\"](?:{'|'.join(map(re.escape, names))})['\"]>.*?</Data>", "", raw, flags=re.S) if names else raw


class Pipeline:
    def __init__(self, idea: Idea, inventory: Inventory, splunk: Splunk, config: Config, run_dir: Path, idea_path: str):
        self._setup(idea, inventory, splunk, run_dir, PipelineState(
            state="start", idea_path=idea_path, splunk_kind=splunk.kind, run_id=uuid.uuid4().hex[:8], config=config))

    def _setup(self, idea: Idea, inventory: Inventory, splunk: Splunk, run_dir: Path, st: PipelineState) -> None:
        self.idea, self.inventory, self.splunk, self.run_dir = idea, inventory, splunk, Path(run_dir)
        self._line: list[tuple[str, str]] = []  # (spl, reason) per draft of the current author line
        for k in STATE_FIELDS:
            setattr(self, k, getattr(st, k))
        self._prev, self._t0 = self.state, time.monotonic()  # for `report`: transitions passes no event data without send_event
        Machine(model=self, states=STATES, transitions=TRANSITIONS, initial=self.state, auto_transitions=False,
                ignore_invalid_triggers=False, after_state_change="report" if self.config.verbose else None)

    @classmethod
    def load(cls, run_dir: Path, idea: Idea, inventory: Inventory, splunk: Splunk, config: Config) -> "Pipeline":
        st = PipelineState.model_validate_json((Path(run_dir) / "state.json").read_text())
        st.config = config  # the CLI config wins; the persisted one is informational
        if st.state == "error":
            st.state, st.error, st.prior_state = st.prior_state, None, None
        p = cls.__new__(cls)
        p._setup(idea, inventory, splunk, run_dir, st)
        return p

    def save(self) -> None:
        self.run_dir.mkdir(parents=True, exist_ok=True)
        state = PipelineState(**{k: getattr(self, k) for k in STATE_FIELDS})
        (self.run_dir / "state.json").write_text(state.model_dump_json(indent=2))

    def drive(self) -> str:
        while self.state in NEXT:
            try:
                getattr(self, NEXT[self.state])()
            except Exception as e:  # includes CostCapExceeded, subprocess errors, Splunk errors
                self.error = repr(e)
                self.fail()
            self.save()
        return self.state

    # --- helpers -------------------------------------------------------------

    def report(self) -> None:  # `  matched -> drafted   author  $0.04  0:12`: from, to, last history step + its cost, elapsed
        prev, self._prev, last = self._prev, self.state, (self.history[-1] if self.history else {})
        m, s = divmod(int(time.monotonic() - self._t0), 60)
        print(f"{prev:>10} -> {self.state:<8}  {last.get('step', ''):<7} ${last.get('cost_usd', 0.0):.2f}  {m}:{s:02d}", file=sys.stderr)

    def _log(self, step: str, model: str | None = None, cost: float = 0.0) -> None:
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        self.history.append({"ts": ts, "step": step, "model": model, "cost_usd": cost})

    def _ask(self, step: str, payload: dict, out: type, model: str | None = None, effort: str | None = None):
        model = model or self.config.models.get(step) or prompts.MODEL[step]
        obj, cost = llm.ask(step, payload, out, model=model, effort=effort)
        self.cost_usd += cost
        self._log(step, model, cost)
        if self.cost_usd > self.config.max_cost_usd:
            raise CostCapExceeded(f"cost {self.cost_usd:.2f} USD exceeds cap {self.config.max_cost_usd:.2f} USD")
        return obj

    def _add_draft(self, origin: str, text: str) -> None:
        self.drafts.append(Draft(n=len(self.drafts) + 1, origin=origin, spl=text,
                                 group_fields=spl.group_fields(text), fields_used=sorted(spl.referenced_fields(text))))

    def _ingest(self, sourcetype: str, raw: str) -> None:
        host = f"dea-{self.run_id}-{len(self.examples)}"
        self.splunk.ingest(self.config.attack_index, sourcetype, [raw], host)
        self.examples.append(Example(sourcetype=sourcetype, raw=raw, host=host))

    def _sourcetypes(self, text: str) -> list[str]:
        return sorted(spl.sourcetypes_in(text)) or [s.sourcetype for s in self.sources]

    def _available_fields(self, text: str) -> dict[str, list[str]]:
        return {k: v for st in self._sourcetypes(text) for k, v in self.inventory.fields_for(st).items()}

    def _common(self) -> dict:  # payload values shared by author / tune / refine
        return {"max_hits_per_day": self.idea.threshold, "false_positive_notes": self.idea.false_positive_notes,
                "schedule": prompts.SCHEDULE}

    # --- steps ---------------------------------------------------------------

    def do_match(self) -> None:
        idea = self.idea
        self.examples = []  # rebuilt from idea.attack_examples so hosts are dea-<run_id>-<i> even on resume
        # never the attack index: its sourcetypes mirror production's, so author would search it and the gate would count planted events
        pairs = [(ix.name, st) for ix in self.inventory.indexes if ix.name != self.config.attack_index for st in ix.sourcetypes]
        if idea.sourcetypes:
            first = {}
            for ix, st in pairs:
                first.setdefault(st.name, (ix, st))
            scored = [(*first[n], 100) for n in idea.sourcetypes if n in first]
        else:
            kws = [kw.lower() for ls in idea.log_sources for kw in ls.keywords]
            want = {f for ls in idea.log_sources for f in ls.fields}
            scored = [(ix, st, hits * 10 + len(want & set(st.fields)))
                      for ix, st in pairs if (hits := sum(kw in st.name.lower() for kw in kws))]
            scored = sorted(scored, key=lambda p: (p[2], p[1].count), reverse=True)[:4]
        self.sources = [Source(index=ix, sourcetype=st.name, score=score, data_source=d, asset_type=a, security_domain=sd)
                        for ix, st, score in scored for d, a, sd in [_meta(st.name)]]
        if not idea.attack_examples:
            self.status_cap = "experimental"
        for ex in idea.attack_examples if self.sources else []:
            st = next((s.sourcetype for s in self.sources if ex.keyword.lower() in s.sourcetype.lower()), self.sources[0].sourcetype)
            self._ingest(st, ex.raw)
        self._log("match")

    def do_author(self) -> None:
        inv, have = self.inventory, {e.sourcetype for e in self.examples}
        payload = {
            "summary": self.idea.summary, "attack_steps": self.idea.attack_steps, "indicators": self.idea.indicators, **self._common(),
            # only sourcetypes the ingested examples carry: recall runs every example, so a remake that switches sourcetype
            # can never pass it (real run 3: Sysmon evasion events, remake on WinEventLog:Security)
            "sources": [{"index": s.index, "sourcetype": s.sourcetype, "fields": inv.fields_for(s.sourcetype),
                         "sample": inv.sample_for(s.sourcetype)} for s in self.sources if not have or s.sourcetype in have],
            "failed_attempts": self.failed_attempts,
        }
        out = self._ask("author", payload, SplOut)
        self._line = []
        self._add_draft("author", out.spl)

    def _absent_group_fields(self, d: Draft, counts: list[int]) -> list[str]:
        """`stats by` drops an event that lacks a group field, so an example missing one can never hit and the 0-hit line
        alone sends the tuner after the predicates (real idea run: 7 drafts grouped by ProcessGuid, which the article's
        example lacks). Splunk's own extraction is the ground truth; the mock never evaluates events (recall.json)."""
        if self.splunk.kind != "real" or not d.group_fields:
            return []
        out = []
        for i, (ex, c) in enumerate(zip(self.examples, counts)):
            if c < 1:
                rows = self.splunk.run(f'search index={self.config.attack_index} host="{ex.host}" | head 1 | fields host {" ".join(d.group_fields)}',
                                       earliest="0", latest="now").rows
                if rows and (absent := [f for f in d.group_fields if f not in rows[0]]):
                    out.append(f"recall: example {i} lacks {', '.join(absent)}, so `stats by` drops it; group only by fields it carries")
        return out

    def do_test(self) -> None:
        d, cfg = self.drafts[-1], self.config
        lint = spl.lint(d.spl, self.inventory, self.idea.stem, [s.sourcetype for s in self.sources])
        gate_spl = spl.runnable(spl.bucketed(d.spl, prompts.SCHEDULE["window"])) + " | sort 0 - count"
        run, counts, no_index = Run(count=None), [], None
        if not lint.errors:
            run = self.splunk.run(gate_spl, earliest=cfg.window)
            if self.examples and not spl.indexes_in(d.spl):  # macro-only search: rewrite_index cannot isolate the attack index
                counts = [0] * len(self.examples)  # never run it: an all-time production search would satisfy recall on live data
                no_index = "recall: search has no index= term, so the attack index cannot be substituted; start with index=<idx> sourcetype=..."
            else:
                counts = [_matched(self.splunk.run(spl.rewrite_index(spl.runnable(d.spl), cfg.attack_index, host=ex.host),
                                                   earliest="0", latest="now")) for ex in self.examples]
        recall = {"ran": bool(counts), "counts": counts, "ok": all(c >= 1 for c in counts)}
        threshold, count = self.idea.threshold, run.count
        window = spl.window_seconds(cfg.window)
        rate = None if count is None else count * 86400 / window
        noisy = count is not None and rate > threshold
        if count == 0 and not recall["ran"]:
            lint.warnings.append(f"warning: 0 hits in {cfg.window}; cannot distinguish quiet from broken")
            self.status_cap = "experimental"
        if run.scan_count > cfg.max_scan_count:
            lint.warnings.append(f"performance: scanned {run.scan_count} events in {cfg.window}; "
                                 "narrow with index/sourcetype/EventCode or use tstats")
        rows = [{k: v for k, v in r.items() if k != "_time"} for r in run.rows]
        tv = spl.top_values(rows, d.group_fields)
        noise = f"{count} alerts in {cfg.window} = {rate:.1f}/day > {threshold}/day threshold" if noisy else None
        hard = [f"lint: {e}" for e in lint.errors] + [f"splunk: {e}" for e in run.errors]  # the gate failures (§5.3 reason)
        if not recall["ok"]:
            zero = ",".join(str(i) for i, c in enumerate(counts) if c < 1)
            hard.append(no_index or f"recall: examples {zero} produced 0 hits (every example must hit)")
            hard += [] if no_index else self._absent_group_fields(d, counts)
        problems = hard + ([noise] if noise else [])
        if hc := spl.high_cardinality(rows, d.group_fields):
            problems.append("high-cardinality group fields: " + ", ".join(f"{f} ({n} distinct / {r} rows)" for f, n, r in hc))
        problems += [f"top {f} values: " + ", ".join(f"{v} ({n})" for v, n in vals) for f, vals in tv.items()]
        problems += [w if w.startswith(("warning:", "performance:")) else f"warning: {w}" for w in lint.warnings]
        self.gates = {
            "draft": d.n, "lint": lint.model_dump(), "gate_spl": gate_spl, "run": run.model_dump(exclude={"rows"}),
            "recall": recall, "rate_per_day": rate, "threshold": threshold, "window_seconds": window,
            "top_values": tv, "sample_rows": spl.project(rows, d.group_fields + ["count"]), "problems": problems,
            "ok": not lint.errors and not run.errors and recall["ok"] and count is not None and not noisy,
        }
        self._line.append((d.spl, noise or next(iter(hard), "")))  # never a cardinality/top-values/warning line
        self._log("test")

    def do_tune(self) -> None:
        d, g = self.drafts[-1], self.gates
        payload = {
            "spl": d.spl, "problems": g["problems"], "attack_steps": self.idea.attack_steps,
            "available_fields": self._available_fields(d.spl), "sample_rows": g["sample_rows"], **self._common(),
            # every round's evasion notes: exactly what recall executes. Never finding details: they describe the previous
            # draft's weaknesses, and a false_positive one reads as "remove this" (run 3: the last tune dropped -e/-ec)
            "must_keep": [ev.note for rnd in self.review_log for ev in rnd.evasion_events],
        }
        opus = self.tunes == self.config.max_tunes  # last allowed round: the run's opus (author) model at high effort
        model = (self.config.models.get("author") or prompts.MODEL["author"]) if opus else None
        out = self._ask("tune", payload, SplOut, model=model, effort="high" if opus else None)
        self._add_draft("tune", out.spl)

    def do_review(self) -> None:
        d, g = self.drafts[-1], self.gates
        prior = self.review_log[-1].findings if self.review_log else []
        payload = {
            "spl": d.spl, "attack_steps": self.idea.attack_steps, "indicators": self.idea.indicators,
            "available_fields": self._available_fields(d.spl),
            "samples": {st: self.inventory.sample_for(st) for st in self._sourcetypes(d.spl)},
            "warnings": g["lint"]["warnings"], "hits_per_day": g["rate_per_day"], "sample_rows": g["sample_rows"],
            "top_values": g["top_values"], "exclusions": spl.exclusions(d.spl), "schedule": prompts.SCHEDULE,
            "prior_findings": [f.model_dump(include={"category", "severity", "detail"}) for f in prior],
        }
        out = self._ask("review", payload, ReviewOut)
        self.review_log.append(ReviewRound(round=len(self.review_log) + 1, draft=d.n,
                                           findings=out.findings, evasion_events=out.evasion_events))

    def do_refine(self) -> None:
        last, d = self.review_log[-1], self.drafts[-1]
        names = {s.sourcetype for s in self.sources}
        have = {(e.sourcetype, e.raw) for e in self.examples}  # already ingested (a --resume re-enters this step)
        events = []
        # every round's events, not only the latest: recall executes all of them, so refine must see all of them
        # (run 2: a round-2 fix_hint dropped the `-ec` case round 1 had made an example of, and refine followed it)
        for ev in (ev for rnd in self.review_log for ev in rnd.evasion_events):  # executed, not trusted
            st = ev.sourcetype if ev.sourcetype in names else self.sources[0].sourcetype
            real = set(self.inventory.fields_for(st)) | event_fields(self.inventory.sample_for(st))
            raw = strip_fields(ev.raw, event_fields(ev.raw) - real)  # a field the environment lacks must not satisfy recall
            if (st, raw) not in have:
                self._ingest(st, raw)
                have.add((st, raw))
            events.append({**ev.model_dump(), "sourcetype": st, "raw": raw})  # the sourcetype it was ingested under
        findings = sorted(last.findings, key=lambda f: f.severity not in ("high", "critical"))
        payload = {
            "spl": d.spl, "findings": [f.model_dump() for f in findings], "evasion_events": events,
            "available_fields": self._available_fields(d.spl), **self._common(),
        }
        out = self._ask("refine", payload, SplOut)
        self._add_draft("refine", out.spl)

    def do_render(self) -> None:
        stem, out = self.idea.stem, Path(self.config.out_dir)
        status = "production" if self.status_cap is None and self.gates["recall"]["ran"] else "experimental"
        findings = self.review_log[-1].findings if self.review_log else []
        det = Detection.from_run(self.idea, self.drafts[-1], self.sources, findings, status, out)
        (out / "macros").mkdir(parents=True, exist_ok=True)
        files = {out / f"{stem}.yml": det.to_yaml(), out / "macros" / f"{stem}_filter.yml": Detection.macro_yaml(stem)}
        for path, text in files.items():
            path.write_text(text)
        self.outputs = [str(p) for p in files]
        self._log("render")

    # --- guards and callbacks (§5.3) -------------------------------------------

    def has_sources(self) -> bool:
        return len(self.sources) > 0

    def is_clean(self) -> bool:
        return bool(self.gates["ok"])

    def can_tune(self) -> bool:
        seen = {spl.normalise(d.spl) for d in self.drafts[:-1]}
        return self.tunes < self.config.max_tunes and spl.normalise(self.drafts[-1].spl) not in seen

    def can_remake(self) -> bool:
        return self.remakes < self.config.max_remakes

    def review_pass(self) -> bool:
        return not any(f.severity != "low" for f in self.review_log[-1].findings)

    def can_refine(self) -> bool:
        log = self.review_log
        return self.reviews < self.config.max_reviews and (len(log) < 2 or finding_key(log[-1]) != finding_key(log[-2]))

    def residual_acceptable(self) -> bool:
        return not any(f.severity in ("high", "critical") for f in self.review_log[-1].findings)

    def bump_tune(self) -> None:
        self.tunes += 1

    def bump_remake(self) -> None:
        self.remakes += 1
        self.tunes = 0
        self.failed_attempts += [{"spl": s, "reason": r} for s, r in self._line[-4:]]

    def bump_review(self) -> None:
        self.reviews += 1

    def cap_experimental(self) -> None:
        self.status_cap = "experimental"

    def remember_prior(self) -> None:
        self.prior_state = self.state

    def write_coverage_note(self) -> None:
        lines = ["# Coverage note", "", f"No inventory sourcetype matched the log sources of '{self.idea.title}'.", "",
                 "## Wanted log sources", ""]
        lines += [f"- {ls.product}: keywords={ls.keywords} fields={ls.fields}" for ls in self.idea.log_sources]
        lines += ["", "## Inventory sourcetypes", ""] + [f"- {n}" for n in sorted(self.inventory.sourcetype_names())]
        self.run_dir.mkdir(parents=True, exist_ok=True)
        (self.run_dir / "coverage.md").write_text("\n".join(lines) + "\n")
