import itertools
import json
import os
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from pydantic import BaseModel
from splunklib import binding, client, results
from splunklib.binding import HTTPError

from .models import Index, Inventory, Sourcetype

REQUEST_TIMEOUT = 900  # seconds per HTTP request; blocking searches hold the response until they finish
INTERNAL_FIELD = re.compile(r"^(_|date_|tag|punct$|linecount$|splunk_server$|timestamp$|eventtype$)")


class Run(BaseModel):
    count: int | None  # resultCount; None when the search errored
    scan_count: int = 0
    rows: list[dict] = []
    errors: list[str] = []


class Splunk(Protocol):
    kind: str  # "mock" | "real"

    def inventory(self, window: str = "-7d", max_sourcetypes: int = 200) -> Inventory: ...
    def run(self, spl: str, earliest: str = "-7d", latest: str = "now", rows: int = 200) -> Run: ...
    def ingest(self, index: str, sourcetype: str, raws: list[str], host: str) -> int: ...
    def publish(self, name: str, search: str, props: dict[str, str | int]) -> str: ...
    def publish_macro(self, name: str, definition: str) -> str: ...  # returns macro name


class MockSplunk:
    kind = "mock"

    def __init__(self, fixture_dir: Path):
        self.dir = Path(fixture_dir)
        self._runs = self._queue("runs.json", [{"count": 0}])
        self._recall = self._queue("recall.json", [1])

    def _queue(self, name: str, default: list):
        path = self.dir / name
        items = json.loads(path.read_text()) if path.exists() else default
        if not items:
            raise ValueError(f"{path} must contain at least one entry")
        return itertools.chain(items, itertools.repeat(items[-1]))  # call order, then the last entry repeats

    def inventory(self, window: str = "-7d", max_sourcetypes: int = 200) -> Inventory:
        return Inventory.model_validate_json((self.dir / "inventory.json").read_text())

    def run(self, spl: str, earliest: str = "-7d", latest: str = "now", rows: int = 200) -> Run:
        if earliest == "0":
            return Run(count=next(self._recall))
        entry = next(self._runs)
        return Run(**{**entry, "rows": entry.get("rows", [])[:rows], "count": None if entry.get("errors") else entry.get("count")})

    def ingest(self, index: str, sourcetype: str, raws: list[str], host: str) -> int:
        with (self.dir / "ingested.jsonl").open("a") as f:
            f.writelines(json.dumps({"index": index, "sourcetype": sourcetype, "host": host, "raw": r}) + "\n" for r in raws)
        return len(raws)

    def publish(self, name: str, search: str, props: dict[str, str | int]) -> str:
        lines = [f"[{name}]", f"search = {search}", *(f"{k} = {v}" for k, v in props.items()), "", ""]
        with (self.dir / "published.conf").open("a") as f:
            f.write("\n".join(lines))
        return name

    def publish_macro(self, name: str, definition: str) -> str:
        with (self.dir / "published.conf").open("a") as f:
            f.write(f"[{name}]\ndefinition = {definition}\n\n")
        return name


class RealSplunk:
    kind = "real"

    def __init__(self, svc):
        self.svc = svc

    @classmethod
    def from_env(cls) -> "RealSplunk":
        env = os.environ
        missing = [k for k in ("SPLUNK_HOST", "SPLUNK_TOKEN") if not env.get(k)]
        if missing:
            raise ValueError(f"--splunk real needs {', '.join(missing)} set (see README: SPLUNK_HOST/PORT/TOKEN/APP/OWNER/VERIFY)")
        verify = env.get("SPLUNK_VERIFY", "1") != "0"
        return cls(client.connect(
            # splunk-sdk's connect() never forwards a timeout; only an explicit handler sets one (and it then owns `verify`)
            handler=binding.handler(timeout=REQUEST_TIMEOUT, verify=verify),
            host=env["SPLUNK_HOST"], port=int(env.get("SPLUNK_PORT", "8089")), scheme="https",
            splunkToken=env["SPLUNK_TOKEN"], autologin=True, app=env.get("SPLUNK_APP", "search"),
            owner=env.get("SPLUNK_OWNER", "nobody"), verify=verify,
        ))

    def _q(self, spl: str, earliest: str = "-7d", latest: str = "now") -> list[dict]:
        rr = results.JSONResultsReader(self.svc.jobs.oneshot(spl, output_mode="json", count=0, earliest_time=earliest, latest_time=latest))
        return [r for r in rr if isinstance(r, dict)]

    def _fields(self, idx: str, st: str) -> dict[str, list[str]]:
        rows = self._q(f'search index={idx} sourcetype="{st}" | head 2000 | dedup 100 EventCode keepempty=true | fieldsummary maxvals=3 | fields field count values')
        floor = 0.05 * max((int(r["count"]) for r in rows), default=0)
        keep = sorted((r for r in rows if int(r["count"]) >= floor and not INTERNAL_FIELD.match(r["field"])), key=lambda r: -int(r["count"]))[:60]
        return {r["field"]: [v["value"][:80] for v in json.loads(r["values"])][:3] for r in keep}

    def _sample(self, idx: str, st: str) -> str | None:
        rows = self._q(f'search index={idx} sourcetype="{st}" | head 1 | fields _raw')
        return rows[0]["_raw"][:600] if rows else None

    def inventory(self, window: str = "-7d", max_sourcetypes: int = 200) -> Inventory:
        indexes = [(i.name, int(i["totalEventCount"])) for i in self.svc.indexes if not i.name.startswith("_") and int(i["totalEventCount"]) > 0]
        pairs = [(idx, r["sourcetype"], int(r["count"])) for idx, _ in indexes
                 for r in self._q(f"| tstats count where index={idx} by sourcetype", earliest=window) if int(r["count"]) > 0]
        by_index: dict[str, list[Sourcetype]] = {}
        for idx, st, n in sorted(pairs, key=lambda p: -p[2])[:max_sourcetypes]:
            by_index.setdefault(idx, []).append(Sourcetype(name=st, count=n, fields=self._fields(idx, st), sample=self._sample(idx, st)))
        return Inventory(
            fetched_at=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"), window=window,
            # confs["macros"] titles carry the argcount (`security_content_ctime(1)`); lint compares bare names
            macros=sorted({m.name.split("(")[0] for m in self.svc.confs["macros"]}),
            indexes=[Index(name=i, events=e, sourcetypes=by_index.get(i, [])) for i, e in indexes],
        )

    def run(self, spl: str, earliest: str = "-7d", latest: str = "now", rows: int = 200) -> Run:
        try:
            job = self.svc.jobs.create(spl, exec_mode="blocking", earliest_time=earliest, latest_time=latest)
        except HTTPError as e:
            if e.status != 400:
                raise
            return Run(count=None, errors=[str(e)])
        try:
            # Splunk 10 accepts a search that fails at dispatch (bad regex, parse error) as a job: dispatchState=FAILED,
            # the text under the job's `messages` (fatal/error), and results() answers 400 (real run 2 crashed there)
            msgs = job.content.get("messages") or {}
            if failed := list(dict.fromkeys([*msgs.get("fatal", []), *msgs.get("error", [])])):
                return Run(count=None, scan_count=int(job["scanCount"]), errors=failed)
            # parsed by hand: JSONResultsReader (splunk-sdk 3.0.1) yields only the last message of each document
            docs = [json.loads(line) for line in job.results(output_mode="json", count=rows).read().splitlines() if line.strip()]
            errors = [m.get("text", "") for d in docs for m in d.get("messages", []) if m.get("type") == "ERROR"]
            return Run(
                count=None if errors else int(job["resultCount"]), scan_count=int(job["scanCount"]),
                rows=[r for d in docs for r in d.get("results", [])], errors=errors,
            )
        finally:
            job.cancel()

    def ingest(self, index: str, sourcetype: str, raws: list[str], host: str) -> int:
        idx = self.svc.indexes[index] if index in self.svc.indexes else self.svc.indexes.create(index)
        for raw in raws:
            # bytes: splunk-sdk hands a str body to http.client, which encodes Latin-1 and raises on e.g. U+2013
            idx.submit(raw.encode("utf-8"), sourcetype=sourcetype, host=host)
        return len(raws)

    def publish(self, name: str, search: str, props: dict[str, str | int]) -> str:
        ss = self.svc.saved_searches
        if name in ss:
            ss[name].update(search=search, **props).refresh()
        else:
            ss.create(name, search, **props)
        return name

    def publish_macro(self, name: str, definition: str) -> str:
        macros = self.svc.macros
        if name in macros:
            macros[name].update(definition=definition)
        else:
            macros.create(name, definition)
        return name


def get(kind: str | None = None) -> Splunk:
    """kind or env DEA_SPLUNK ('mock'|'real'); default 'real' if SPLUNK_TOKEN is set else 'mock'."""
    kind = kind or os.environ.get("DEA_SPLUNK") or ("real" if os.environ.get("SPLUNK_TOKEN") else "mock")
    if kind not in ("mock", "real"):
        raise ValueError(f"unknown Splunk kind {kind!r} (expected 'mock' or 'real')")
    if kind == "real":
        return RealSplunk.from_env()
    return MockSplunk(Path(os.environ.get("DEA_FIXTURES", "tests/fixtures/splunk")))
