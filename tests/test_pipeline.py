"""Machine paths with stubbed do_* callbacks; resume; cost cap; stall; tune ladder; bucketed gate search (§11.2)."""

import json
from itertools import count

import pytest

from detection_engineering_agent import pipeline as pl
from detection_engineering_agent.models import Draft, EvasionEvent, Example, Finding, Index, LogSource, ReviewRound, Source, SplOut
from detection_engineering_agent.pipeline import EXIT_CODES, STATE_FIELDS, TERMINAL, Config, Pipeline

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"
SPL = (f'index=wineventlog sourcetype="{SYSMON}" EventCode=1 Image="*\\\\powershell.exe" '
       "| stats count by Computer User ParentImage Image CommandLine")
SRC = Source(index="wineventlog", sourcetype=SYSMON, score=24, data_source="Sysmon EventID 1", asset_type="Endpoint", security_domain="endpoint")
_n = count()


def finding(category="evasion", severity="medium") -> Finding:
    return Finding(category=category, severity=severity, detail=f"{category} {severity} #{next(_n)}", fix_hint="fix")


def spy_run(mock_splunk, monkeypatch) -> list:
    """Record (spl, earliest) of every Splunk run while delegating to the real MockSplunk.run."""
    seen, real = [], mock_splunk.run
    monkeypatch.setattr(mock_splunk, "run", lambda spl, earliest="-7d", latest="now", rows=200: (seen.append((spl, earliest)), real(spl, earliest, latest, rows))[1])
    return seen


class Stub:
    """Canned do_* callbacks: scripted gate verdicts (True=clean) and review findings; unique SPLs unless given."""

    def __init__(self, p: Pipeline, gates=(), reviews=(), spls=None):
        self.p, self.calls, self.gates, self.reviews = p, [], iter(gates), iter(reviews)
        self.spls = iter(spls) if spls else (f"{SPL} draft={i}" for i in count())
        for step in ("match", "author", "test", "tune", "review", "refine", "render"):
            setattr(p, f"do_{step}", getattr(self, step))

    def _draft(self, origin):
        self.p.drafts.append(Draft(n=len(self.p.drafts) + 1, origin=origin, spl=next(self.spls), group_fields=["Computer"], fields_used=["Computer"]))

    def match(self):
        self.calls.append("match")
        self.p.sources = [SRC]

    def author(self):
        self.calls.append("author")
        self.p._line = []
        self._draft("author")

    def tune(self):
        self.calls.append("tune")
        self._draft("tune")

    def refine(self):
        self.calls.append("refine")
        self._draft("refine")

    def test(self):
        self.calls.append("test")
        ok = next(self.gates, True)
        self.p.gates = {"draft": self.p.drafts[-1].n, "lint": {"errors": [], "warnings": []}, "recall": {"ran": True, "counts": [1], "ok": True},
                        "rate_per_day": 1.0, "threshold": 5, "top_values": {}, "sample_rows": [], "problems": [] if ok else ["noisy"], "ok": ok}
        self.p._line.append((self.p.drafts[-1].spl, "noisy"))

    def review(self):
        self.calls.append("review")
        self.p.review_log.append(ReviewRound(round=len(self.p.review_log) + 1, draft=self.p.drafts[-1].n, findings=next(self.reviews, []), evasion_events=[]))

    def render(self):
        self.calls.append("render")
        self.p.outputs = ["x.yml"]


@pytest.fixture
def pipe(idea, inventory, mock_splunk, tmp_runs):
    return lambda config=None: Pipeline(idea, inventory, mock_splunk, config or Config(), tmp_runs / idea.id, "idea.yml")


def test_constants():
    assert set(EXIT_CODES) == TERMINAL and EXIT_CODES["done"] == 0 and EXIT_CODES["failed_noisy"] == 3
    assert STATE_FIELDS[0] == "state" and "config" in STATE_FIELDS and set(pl.NEXT) == set(pl.STATES) - TERMINAL


def test_happy_path(pipe):
    p = pipe()
    s = Stub(p)
    assert p.drive() == "done"
    assert s.calls == ["match", "author", "test", "review", "render"]
    assert (p.tunes, p.remakes, p.reviews, p.status_cap) == (0, 0, 0, None)
    assert json.loads((p.run_dir / "state.json").read_text())["state"] == "done"


def test_noisy_three_times_then_remake_then_clean(pipe):
    p = pipe()
    s = Stub(p, gates=[False] * 4 + [True])
    assert p.drive() == "done"
    assert s.calls == ["match", "author", "test", "tune", "test", "tune", "test", "tune", "test", "author", "test", "review", "render"]
    assert (p.remakes, p.tunes, len(p.drafts)) == (1, 0, 5)
    assert [a["spl"] for a in p.failed_attempts] == [d.spl for d in p.drafts[:4]] and p.failed_attempts[0]["reason"] == "noisy"


def test_noisy_forever_fails_noisy(pipe):
    p = pipe()
    s = Stub(p, gates=[False] * 20)
    assert p.drive() == "failed_noisy"
    assert (s.calls.count("author"), s.calls.count("tune"), s.calls.count("review")) == (2, 6, 0)
    assert len(p.failed_attempts) == 4 and (p.tunes, p.remakes) == (3, 1)


def test_fixed_point_tune_triggers_remake(pipe):
    p = pipe()
    s = Stub(p, gates=[False, False, True], spls=["A", "A", "B"])
    assert p.drive() == "done"
    assert s.calls == ["match", "author", "test", "tune", "test", "author", "test", "review", "render"]
    assert (p.remakes, p.tunes, len(p.failed_attempts)) == (1, 0, 2)


def test_medium_findings_for_z_rounds_end_experimental(pipe):
    p = pipe()
    s = Stub(p, reviews=[[finding("evasion", "medium")], [finding("false_positive", "medium")], [finding("logic", "medium")]])
    assert p.drive() == "done"
    assert (s.calls.count("review"), s.calls.count("refine"), p.reviews, p.status_cap) == (3, 2, 2, "experimental")


def test_identical_findings_twice_stop_refining(pipe):
    p = pipe()
    s = Stub(p, reviews=[[finding("evasion", "medium")], [finding("evasion", "medium")]])
    assert p.drive() == "done"
    assert (s.calls.count("review"), s.calls.count("refine"), p.reviews, p.status_cap) == (2, 1, 1, "experimental")


def test_high_residual_after_z_fails_review(pipe):
    p = pipe()
    s = Stub(p, reviews=[[finding("evasion", "high")], [finding("logic", "high")], [finding("evasion", "critical")]])
    assert p.drive() == "failed_review"
    assert (s.calls.count("review"), s.calls.count("refine"), p.reviews, p.status_cap) == (3, 2, 2, None)


def test_review_pass_is_computed_from_findings_only(pipe):
    p = pipe()
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding("brittleness", "low"), finding("logic", "low")], evasion_events=[]))
    assert p.review_pass() and p.residual_acceptable()
    p.review_log.append(ReviewRound(round=2, draft=1, findings=[finding("evasion", "medium")], evasion_events=[]))
    assert not p.review_pass() and p.residual_acceptable()
    assert p.can_refine()  # different (category, severity) key than round 1
    p.review_log.append(ReviewRound(round=3, draft=1, findings=[finding("evasion", "medium")], evasion_events=[]))
    assert not p.can_refine()


def test_no_sources_is_infeasible_with_coverage_note(idea, inventory, mock_splunk, tmp_runs):
    bad = idea.model_copy(update={"log_sources": [LogSource(product="Zeek conn", keywords=["nonexistent"], fields=["id.orig_h"])]})
    p = Pipeline(bad, inventory, mock_splunk, Config(), tmp_runs / idea.id, "idea.yml")
    p._ask = lambda *a, **k: pytest.fail("no inference expected")
    assert p.drive() == "infeasible"
    note = (tmp_runs / idea.id / "coverage.md").read_text()
    assert "nonexistent" in note and SYSMON in note and "squid:access" in note
    assert [h["step"] for h in p.history] == ["match"] and p.status_cap == "experimental"


def test_do_match_scores_and_meta(pipe):
    p = pipe()
    p.do_match()
    assert [s.sourcetype for s in p.sources] == [SYSMON, "WinEventLog:Security"]
    assert p.sources[0].score == 24 and p.sources[0].data_source == "Sysmon EventID 1"
    assert p.sources[1].data_source == "Windows Event Log Security 4688" and p.examples == []


def test_do_match_override_yields_one_source_per_name(idea, inventory, mock_splunk, tmp_runs):
    sysmon = next(st for ix in inventory.indexes for st in ix.sourcetypes if st.name == SYSMON)
    inv = inventory.model_copy(update={"indexes": inventory.indexes + [Index(name="other", events=1, sourcetypes=[sysmon])]})
    p = Pipeline(idea.model_copy(update={"sourcetypes": [SYSMON]}), inv, mock_splunk, Config(), tmp_runs / idea.id, "idea.yml")
    p.do_match()
    assert [(s.index, s.sourcetype, s.score) for s in p.sources] == [("wineventlog", SYSMON, 100)]


def test_do_match_rebuilds_examples_on_resume(idea, inventory, mock_splunk, tmp_runs, monkeypatch):
    """Ingest fails on example 1 -> error with prior_state=start; resume re-enters match and must not duplicate examples (SS5.5)."""
    from detection_engineering_agent.models import AttackExample
    idea = idea.model_copy(update={"attack_examples": [AttackExample(keyword="sysmon", raw="<Event>a</Event>"),
                                                       AttackExample(keyword="sysmon", raw="<Event>b</Event>")]})
    p = Pipeline(idea, inventory, mock_splunk, Config(), tmp_runs / idea.id, "idea.yml")
    real = mock_splunk.ingest
    monkeypatch.setattr(mock_splunk, "ingest", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("hec down")) if a[2] == ["<Event>b</Event>"] else real(*a, **k))
    assert p.drive() == "error" and p.prior_state == "start" and len(p.examples) == 1
    monkeypatch.setattr(mock_splunk, "ingest", real)
    q = Pipeline.load(tmp_runs / idea.id, idea, inventory, mock_splunk, Config())
    q.do_match()
    assert [(e.host, e.raw) for e in q.examples] == [(f"dea-{q.run_id}-0", "<Event>a</Event>"), (f"dea-{q.run_id}-1", "<Event>b</Event>")]


def test_error_then_resume_continues_to_done(pipe, idea, inventory, mock_splunk, tmp_runs):
    p = pipe()
    Stub(p)

    def boom():
        raise RuntimeError("claude down")

    p.do_author = boom
    assert p.drive() == "error"
    assert p.prior_state == "matched" and "claude down" in p.error
    run_dir = tmp_runs / idea.id
    q = Pipeline.load(run_dir, idea, inventory, mock_splunk, Config(max_tunes=7))
    assert (q.state, q.error, q.prior_state, q.config.max_tunes, q.run_id) == ("matched", None, None, 7, p.run_id)
    assert q.sources == [SRC]
    t = Stub(q)
    assert q.drive() == "done" and t.calls == ["author", "test", "review", "render"]
    r = Pipeline.load(run_dir, idea, inventory, mock_splunk, Config())
    assert r.state == "done" and r.drafts and all(isinstance(d, Draft) for d in r.drafts)
    assert isinstance(r.review_log[0], ReviewRound) and isinstance(r.sources[0], Source)


def test_cost_cap_inside_ask_routes_to_error(pipe, monkeypatch):
    p = pipe(Config(max_cost_usd=1.0))
    Stub(p)
    del p.do_author  # real do_author -> real _ask -> patched llm.ask
    monkeypatch.setattr(pl.llm, "ask", lambda step, payload, out, model=None, effort=None: (SplOut(spl=SPL), 1.5))
    assert p.drive() == "error"
    assert "CostCapExceeded" in p.error and p.prior_state == "matched" and p.cost_usd == 1.5
    assert p.history[-1] == {**p.history[-1], "step": "author", "model": "claude-opus-5-5", "cost_usd": 1.5}


def test_ask_model_precedence(pipe, monkeypatch):
    p = pipe(Config(models={"tune": "claude-haiku-5-5"}))
    seen = []
    monkeypatch.setattr(pl.llm, "ask", lambda step, payload, out, model=None, effort=None: (seen.append((model, effort)), (SplOut(spl=SPL), 0.0))[1])
    p._ask("tune", {}, SplOut)
    p._ask("tune", {}, SplOut, model="claude-opus-5-5", effort="high")
    p._ask("author", {}, SplOut)
    assert seen == [("claude-haiku-5-5", None), ("claude-opus-5-5", "high"), ("claude-opus-5-5", None)]


def test_save_has_exactly_state_fields(pipe):
    p = pipe()
    p.save()
    assert tuple(json.loads((p.run_dir / "state.json").read_text())) == STATE_FIELDS


def test_tune_ladder_uses_opus_on_last_round(pipe):
    p = pipe()
    Stub(p, gates=[False] * 4 + [True])
    del p.do_tune  # real do_tune with a stubbed _ask
    asked = []

    def ask(step, payload, out, model=None, effort=None):
        asked.append((step, model, effort))
        return SplOut(spl=SPL.replace("EventCode=1", f"EventCode=1 tuned={len(asked)}"))

    p._ask = ask
    assert p.drive() == "done"
    assert [(m, e) for s, m, e in asked if s == "tune"] == [(None, None), (None, None), ("claude-opus-5-5", "high")]
    assert p.drafts[1].origin == "tune" and p.drafts[1].group_fields == ["Computer", "User", "ParentImage", "Image", "CommandLine"]
    assert "tuned" in p.drafts[1].fields_used and p.drafts[1].fields_used == sorted(p.drafts[1].fields_used)


def test_tune_ladder_follows_author_model_override(pipe):
    """--model author=X also governs the opus round of the tune ladder (the hard-coded id is rejected by older CLIs)."""
    p = pipe(Config(models={"author": "claude-opus-4-6", "tune": "claude-haiku-5-5"}))
    Stub(p, gates=[False] * 4 + [True])
    del p.do_tune
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append((step, model, effort)), SplOut(spl=f"{SPL} tuned={len(asked)}"))[1]
    assert p.drive() == "done"
    assert [(m, e) for s, m, e in asked if s == "tune"] == [(None, None), (None, None), ("claude-opus-4-6", "high")]


def test_do_refine_resume_does_not_reingest_evasions(pipe, idea, inventory, mock_splunk, tmp_runs):
    """refine raising after its ingest -> error with prior_state=revising; resume re-enters refine and must not duplicate examples."""
    p = pipe()
    Stub(p, gates=[True])
    ev = EvasionEvent(sourcetype=SYSMON, raw="<Event>pwsh -ec AAAA</Event>", note="short flag")
    p.do_review = lambda: p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding("evasion", "high")], evasion_events=[ev]))
    del p.do_refine  # real do_refine; its _ask fails after the ingest
    p._ask = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("claude down"))
    assert p.drive() == "error" and p.prior_state == "revising" and len(p.examples) == 1
    q = Pipeline.load(tmp_runs / idea.id, idea, inventory, mock_splunk, Config())
    q._ask = lambda step, payload, out, model=None, effort=None: SplOut(spl=f"{SPL} refined=1")
    q.do_refine()
    assert [(e.host, e.raw) for e in q.examples] == [(f"dea-{q.run_id}-0", ev.raw)]
    assert len((mock_splunk.dir / "ingested.jsonl").read_text().splitlines()) == 1


def test_do_test_runs_bucketed_gate_search(pipe, mock_splunk, monkeypatch):
    p = pipe()
    asked, seen = [], spy_run(mock_splunk, monkeypatch)
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append((step, payload)), SplOut(spl=SPL))[1]
    p.match()
    p.author()
    p.test()
    assert p.state == "tuning" and p.tunes == 1  # runs.json entry 1: 412 hits in 7d
    gate, earliest = seen[0]
    assert gate.startswith("search index=wineventlog") and gate.endswith("| sort 0 - count") and earliest == "-7d"
    assert "| bin _time span=20m | stats count by _time Computer User ParentImage Image CommandLine" in gate
    assert gate == p.gates["gate_spl"]
    assert asked[0][0] == "author" and asked[0][1]["max_hits_per_day"] == p.gates["threshold"] == 5
    assert p.gates["rate_per_day"] == pytest.approx(412 * 86400 / 604800) and p.gates["recall"] == {"ran": False, "counts": [], "ok": True}
    assert p.gates["problems"][0] == "412 alerts in -7d = 58.9/day > 5/day threshold" and not p.gates["ok"]
    assert p.gates["top_values"]["ParentImage"][0][0] == "C:\\Windows\\explorer.exe"
    assert list(p.gates["sample_rows"][0]) == ["Computer", "User", "ParentImage", "Image", "CommandLine", "count"]
    assert p.gates["lint"] == {"errors": [], "warnings": []} and p.gates["run"]["count"] == 412
    assert [h["step"] for h in p.history] == ["match", "test"]  # "author" is logged by the real _ask, stubbed here


def test_do_test_reason_ignores_advisory_problems(pipe, mock_splunk, monkeypatch):
    # §5.3: a draft's failed_attempts reason is its noise line or its first lint/splunk/recall problem; a clean
    # draft with a small result set (10 rows, 10 distinct Computers) must not be blamed for "high-cardinality".
    from detection_engineering_agent.splunk import Run
    rows = [{"Computer": f"WS{i:02}", "User": "CORP\\jdoe", "ParentImage": "WINWORD.EXE", "Image": "powershell.exe",
             "CommandLine": "powershell.exe -enc AAAA", "count": "1"} for i in range(10)]
    monkeypatch.setattr(mock_splunk, "run", lambda *a, **k: Run(count=10, rows=rows))
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    p.do_test()
    assert p.gates["ok"] and p.gates["problems"][0].startswith("high-cardinality group fields: Computer (10 distinct / 10 rows)")
    assert p._line == [(SPL, "")]
    monkeypatch.setattr(mock_splunk, "run", lambda *a, **k: Run(count=0, errors=["Error in 'search' command: boom"]))
    p._add_draft("tune", f"{SPL} | eval draft=2")
    p.do_test()
    assert p._line[-1] == (f"{SPL} | eval draft=2", "splunk: Error in 'search' command: boom")


def test_do_test_lint_error_skips_splunk(pipe, mock_splunk, monkeypatch):
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", 'index=wineventlog sourcetype="nope" | stats count by Computer')
    monkeypatch.setattr(mock_splunk, "run", lambda *a, **k: pytest.fail("Splunk must not run on lint errors"))
    p.do_test()
    assert p.gates["run"]["count"] is None and p.gates["rate_per_day"] is None and not p.gates["ok"]
    assert p.gates["problems"][0].startswith("lint: unknown sourcetype 'nope'")


@pytest.mark.parametrize("rows, matched", [
    ([{"count": "0"}], 0),             # `| stats count` with no match: one row, resultCount=1, zero events
    ([{"count": "abc"}], 0),           # unreadable count proves nothing
    ([{"count": "2"}, {"count": "1"}], 3),
    ([{"Computer": "WS01"}], 1),       # `| table` shape: each row is a matched event
    ([], 4),                           # no rows: resultCount (MockSplunk's scripted recall counts)
])
def test_recall_counts_matched_events_not_result_rows(pipe, mock_splunk, monkeypatch, rows, matched):
    p = pipe()
    p.sources = [SRC]
    p.examples = [Example(sourcetype=SYSMON, raw="<Event>a</Event>", host=f"dea-{p.run_id}-0")]
    p._add_draft("author", SPL)
    real = mock_splunk.run
    monkeypatch.setattr(mock_splunk, "run", lambda s, earliest="-7d", latest="now", n=200:
                        pl.Run(count=len(rows) or 4, rows=rows) if earliest == "0" else real(s, earliest, latest, n))
    p.do_test()
    assert p.gates["recall"] == {"ran": True, "counts": [matched], "ok": matched >= 1}
    assert ("recall: examples 0 produced 0 hits (every example must hit)" in p.gates["problems"]) == (matched < 1)


def test_recall_names_group_fields_the_example_lacks(pipe, mock_splunk, monkeypatch):
    """Real idea run: every draft ended `| stats ... by ..., ProcessGuid`, the article example has no ProcessGuid, so stats
    dropped it and 7 tunes rewrote regexes against a 0-hit line. On real Splunk a 0-hit example is probed with
    `| head 1 | fields host <group fields>`; the fields the row omits are named. The mock never probes (recall.json)."""
    p = pipe()
    p.sources = [SRC]
    p.examples = [Example(sourcetype=SYSMON, raw="<Event>a</Event>", host=f"dea-{p.run_id}-0")]
    p._add_draft("author", SPL.replace("by Computer", "by Computer IntegrityLevel"))
    seen = []
    real = mock_splunk.run
    def run(s, earliest="-7d", latest="now", n=200):
        if earliest != "0":
            return real(s, earliest, latest, n)
        seen.append(s)
        return pl.Run(count=1, rows=[{"host": p.examples[0].host, "Computer": "WS01", "User": "u", "ParentImage": "p", "Image": "i", "CommandLine": "c"}]) if "| head 1 | fields host" in s else pl.Run(count=1, rows=[{"count": "0"}])
    monkeypatch.setattr(mock_splunk, "run", run)
    p.do_test()  # mock kind: no probe
    assert p.gates["recall"] == {"ran": True, "counts": [0], "ok": False} and len(seen) == 1
    assert [x for x in p.gates["problems"] if x.startswith("recall:")] == ["recall: examples 0 produced 0 hits (every example must hit)"]
    monkeypatch.setattr(mock_splunk, "kind", "real")
    p.do_test()
    assert seen[2] == f'search index=dea_attack host="{p.examples[0].host}" | head 1 | fields host Computer IntegrityLevel User ParentImage Image CommandLine'
    assert [x for x in p.gates["problems"] if x.startswith("recall:")] == [
        "recall: examples 0 produced 0 hits (every example must hit)",
        "recall: example 0 lacks IntegrityLevel, so `stats by` drops it; group only by fields it carries",
    ]
    assert not p.gates["ok"]


def test_do_refine_ingests_evasions_and_recall_runs_per_example(pipe, mock_splunk, monkeypatch):
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding("evasion", "medium"), finding("logic", "high")],
                                    evasion_events=[EvasionEvent(sourcetype="not-a-source", raw="<Event>pwsh -ec AAAA</Event>", note="pwsh short flag")]))
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append((step, payload)), SplOut(spl=f"{SPL} | eval refined=1"))[1]
    p.do_refine()
    host = f"dea-{p.run_id}-0"
    assert [(e.sourcetype, e.host) for e in p.examples] == [(SYSMON, host)]
    assert json.loads((mock_splunk.dir / "ingested.jsonl").read_text())["host"] == host
    assert asked[0][0] == "refine" and asked[0][1]["evasion_events"][0]["note"] == "pwsh short flag"
    assert asked[0][1]["evasion_events"][0]["sourcetype"] == SYSMON  # the sourcetype it was ingested under, not "not-a-source"
    assert [f["severity"] for f in asked[0][1]["findings"]] == ["high", "medium"]
    assert p.drafts[-1].origin == "refine"
    seen = spy_run(mock_splunk, monkeypatch)
    p.do_test()
    recall = [s for s, e in seen if e == "0"]
    assert len(recall) == 1 and recall[0].startswith("search ") and f'index=dea_attack host="{host}"' in recall[0] and "| bin" not in recall[0]
    assert p.gates["recall"] == {"ran": True, "counts": [1], "ok": True}


def test_refine_draft_with_unknown_field_fails_lint_and_tunes_before_review(pipe, mock_splunk, monkeypatch):
    """A refine draft reaching for a field outside the inventory fails the gate deterministically (no Splunk run) and takes
    the ordinary drafted -> tuning path: the tune payload carries the lint line in problems and the evasion notes in must_keep."""
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    f = finding("evasion", "high")
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[f], evasion_events=[EvasionEvent(sourcetype=SYSMON, raw="<Event/>", note="renamed")]))
    p._add_draft("refine", f'{SPL.replace("EventCode=1", "EventCode=1 OriginalFileName=PowerShell.EXE")}')
    monkeypatch.setattr(mock_splunk, "run", lambda *a, **k: pytest.fail("Splunk must not run on lint errors"))
    p.do_test()
    assert not p.gates["ok"] and p.gates["run"]["count"] is None and p.gates["lint"]["warnings"] == []
    assert p.gates["problems"][0] == "lint: unknown field 'OriginalFileName' (not in available_fields)"
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append((step, payload)), SplOut(spl=SPL))[1]
    p.do_tune()
    assert asked[0][0] == "tune" and asked[0][1]["problems"] == p.gates["problems"]
    assert asked[0][1]["must_keep"] == ["renamed"] and p.drafts[-1].origin == "tune"


def test_do_tune_must_keep_is_every_rounds_evasion_notes_only(pipe):
    """Recall executes every round's evasion events, so a tune after review must be told to keep all of them and nothing
    else. Run 3: a refine draft failed the gate, the last (opus) tune saw only round 2's findings and events; round 2's
    low false_positive detail ("short tokens e, en, ec ... match even when not encoded PowerShell") read as a problem to
    fix, so the tune dropped -e/-ec and re-pinned Image, undoing round-1 coverage (renamed binary) that the final review
    then rated HIGH -> failed_review. Finding details never belong in must_keep; prior_findings is the reviewer's memory."""
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    p.gates = {"problems": ["splunk: parse error"], "sample_rows": []}
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding("evasion", "critical")],
                                    evasion_events=[EvasionEvent(sourcetype=SYSMON, raw="<Event/>", note="renamed binary")]))
    p.review_log.append(ReviewRound(round=2, draft=2, findings=[finding("false_positive", "low"), finding("evasion", "high")],
                                    evasion_events=[EvasionEvent(sourcetype=SYSMON, raw="<Event>cmd</Event>", note="cmd parent")]))
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append(payload), SplOut(spl=SPL))[1]
    p.tunes = 1
    p.do_tune()
    assert asked[0]["must_keep"] == ["renamed binary", "cmd parent"]
    assert not any("false_positive" in k for k in asked[0]["must_keep"])


def test_do_refine_strips_fields_the_environment_lacks(pipe, mock_splunk, inventory):
    """An evasion_event may only carry fields the inventory or the real sample has; a fabricated field (OriginalFileName) is
    removed before ingest and before the refine call so it can neither satisfy recall nor steer refine off the inventory."""
    sample = inventory.sample_for(SYSMON)
    fake = sample.replace("<Data Name='CommandLine'>", "<Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>")
    real = sample.replace("</EventData>", "<Data Name='IntegrityLevel'>Medium</Data></EventData>")  # in the inventory, not the sample
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding()], evasion_events=[
        EvasionEvent(sourcetype=SYSMON, raw=fake, note="renamed"), EvasionEvent(sourcetype=SYSMON, raw=real, note="integrity")]))
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append(payload), SplOut(spl=SPL))[1]
    p.do_refine()
    assert [e.raw for e in p.examples] == [sample, real]
    assert [e["raw"] for e in asked[0]["evasion_events"]] == [sample, real] and asked[0]["evasion_events"][0]["note"] == "renamed"
    assert "OriginalFileName" not in (mock_splunk.dir / "ingested.jsonl").read_text()
    assert p.review_log[-1].evasion_events[0].raw == fake  # the log keeps what the reviewer said
    assert pl.event_fields(None) == set() and pl.strip_fields("<Event/>", set()) == "<Event/>"
    multi = "<E><Data Name='OriginalFileName'>Power\nShell.EXE</Data><Data Name='Image'>p.exe</Data></E>"  # value spans a line
    assert pl.strip_fields(multi, {"OriginalFileName"}) == "<E><Data Name='Image'>p.exe</Data></E>"


def test_do_refine_presents_every_rounds_evasion_events(pipe, mock_splunk):
    """Recall executes every ingested evasion event, so refine must see every round's events, not only the latest round's.
    Run 2: round 2's fix_hint dropped the `-ec` case round 1 had made an example of; refine, shown only round 2's events,
    followed it and the final review spent its last round re-reporting the regression as HIGH -> failed_review."""
    p = pipe()
    p.sources = [SRC]
    p._add_draft("author", SPL)
    r1 = [EvasionEvent(sourcetype=SYSMON, raw="<Event>powershell -ec AAAA</Event>", note="-ec abbreviation")]
    r2 = [EvasionEvent(sourcetype=SYSMON, raw="<Event>powershell -encoded AAAA</Event>", note="-encoded prefix")]
    asked = []
    p._ask = lambda step, payload, out, model=None, effort=None: (asked.append(payload), SplOut(spl=f"{SPL} | eval r={len(asked)}"))[1]
    p.review_log.append(ReviewRound(round=1, draft=1, findings=[finding("evasion", "critical")], evasion_events=r1))
    p.do_refine()
    p.review_log.append(ReviewRound(round=2, draft=2, findings=[finding("evasion", "high")], evasion_events=r2))
    p.do_refine()
    assert [e["note"] for e in asked[1]["evasion_events"]] == ["-ec abbreviation", "-encoded prefix"]
    assert [e.raw for e in p.examples] == [r1[0].raw, r2[0].raw]  # round-1 event ingested once, not again on round 2
    assert len((mock_splunk.dir / "ingested.jsonl").read_text().splitlines()) == 2
    assert [f["severity"] for f in asked[1]["findings"]] == ["high"]  # findings stay last-round only (prior_findings handles those)


def test_do_test_macro_only_search_fails_recall_without_searching_production(pipe, mock_splunk, monkeypatch):
    """Lint rule 3 allows a leading macro, but rewrite_index can only substitute an explicit index= term: with none, the recall
    search would run all-time over production and any live hit would satisfy recall. With examples, such a draft fails recall
    deterministically and no earliest="0" search reaches Splunk; without examples it stays an ordinary clean draft."""
    p = pipe()
    p.sources = [SRC]
    p.examples = [Example(sourcetype=SYSMON, raw="<Event>a</Event>", host=f"dea-{p.run_id}-0")]
    macro_spl = "`sysmon` EventCode=1 Image=\"*\\\\powershell.exe\" | stats count by Computer User"
    p._add_draft("author", macro_spl)
    seen = spy_run(mock_splunk, monkeypatch)
    p.do_test()
    assert [e for _, e in seen] == ["-7d"]  # the gate search only
    assert p.gates["lint"]["errors"] == [] and not p.gates["ok"]
    assert p.gates["recall"] == {"ran": True, "counts": [0], "ok": False}
    assert p.gates["problems"][0] == "recall: search has no index= term, so the attack index cannot be substituted; start with index=<idx> sourcetype=..."
    assert p._line[-1] == (macro_spl, "412 alerts in -7d = 58.9/day > 5/day threshold")  # §5.3: the noise line still wins as the reason
    p.examples = []
    p._add_draft("tune", macro_spl + " | eval draft=2")
    p.do_test()
    assert p.gates["recall"] == {"ran": False, "counts": [], "ok": True} and not any(pr.startswith("recall:") for pr in p.gates["problems"])


def test_do_match_never_selects_the_attack_index(idea, inventory, mock_splunk, tmp_runs):
    """Real-Splunk run 3: dea_attack holds the same Sysmon sourcetype as production, scored equal, and both runs' first drafts
    searched `index IN (wineventlog, dea_attack)`, so the gate counted planted evasion events as benign alerts."""
    sysmon = next(st for ix in inventory.indexes for st in ix.sourcetypes if st.name == SYSMON)
    inv = inventory.model_copy(update={"indexes": inventory.indexes + [Index(name="dea_attack", events=20, sourcetypes=[sysmon])]})
    p = Pipeline(idea, inv, mock_splunk, Config(), tmp_runs / idea.id, "idea.yml")
    p.do_match()
    assert [s.index for s in p.sources] == ["wineventlog", "wineventlog"]
    q = Pipeline(idea, inv, mock_splunk, Config(attack_index="other"), tmp_runs / idea.id, "idea.yml")
    q.do_match()
    assert "dea_attack" in {s.index for s in q.sources}  # only the configured attack index is excluded


def test_do_author_offers_only_sourcetypes_the_examples_carry(pipe, monkeypatch):
    """Real-Splunk run 3: after three Sysmon drafts the remake switched to WinEventLog:Security while the five ingested evasion
    events stayed Sysmon, so recall (every example must hit) could never pass. Without examples every source is offered."""
    p = pipe()
    p.do_match()
    seen = []
    monkeypatch.setattr(p, "_ask", lambda step, payload, out, **kw: (seen.append(payload), SplOut(spl=SPL))[1])
    p.do_author()
    assert [s["sourcetype"] for s in seen[-1]["sources"]] == [SYSMON, "WinEventLog:Security"]
    p.examples = [Example(sourcetype=SYSMON, raw="<Event>a</Event>", host=f"dea-{p.run_id}-0")]
    p.do_author()
    assert [s["sourcetype"] for s in seen[-1]["sources"]] == [SYSMON]
