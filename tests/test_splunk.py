import io
import json
from unittest.mock import MagicMock

import pytest
from splunklib import binding, client
from splunklib.binding import HTTPError

from detection_engineering_agent import splunk
from detection_engineering_agent.models import Inventory
from detection_engineering_agent.splunk import MockSplunk, RealSplunk, Run

# --- MockSplunk ---------------------------------------------------------------


def test_mock_inventory_equals_file(mock_splunk):
    expected = Inventory.model_validate_json((mock_splunk.dir / "inventory.json").read_text())
    assert mock_splunk.inventory() == expected


def test_mock_run_sequence_and_last_repeat(mock_splunk):
    scripted = json.loads((mock_splunk.dir / "runs.json").read_text())
    assert len(scripted) == 4 and not any("errors" in e for e in scripted)  # no call-order trap for real-inference runs (§8.1)
    runs = [mock_splunk.run("search x") for _ in range(12)]
    assert [r.count for r in runs[:4]] == [412, 60, 2, 1]
    assert runs[0].scan_count == 912000 and len(runs[0].rows) == 6
    # Regression: a real-LLM run needs more gate runs than the scripted sequence (two review/refine rounds plus
    # tunes). The entry that repeats after the script must be a clean result, or every later draft is failed by
    # the fixture regardless of its content (runs 1 and 3 each burned their last, opus tune on a scripted error).
    assert all(r == runs[3] and r.count == 1 and not r.errors for r in runs[4:])


def test_mock_run_error_entry_yields_count_none(mock_splunk):
    errors = ["Error in 'search' command: Unable to parse the search"]
    (mock_splunk.dir / "runs.json").write_text(json.dumps([{"count": 2}, {"errors": errors}]))
    fresh = MockSplunk(mock_splunk.dir)  # the fixture instance already read the file
    runs = [fresh.run("search x") for _ in range(3)]
    assert runs[0].count == 2 and runs[1].count is None and runs[1].errors == errors and runs[2] == runs[1]


def test_mock_recall_consumes_recall_json(mock_splunk):
    (mock_splunk.dir / "recall.json").write_text("[3, 0]")
    ms = MockSplunk(mock_splunk.dir)
    assert [ms.run("search x", earliest="0").count for _ in range(3)] == [3, 0, 0]
    assert ms.run("search x").count == 412  # recall queue is separate from the runs queue


def test_mock_run_slices_rows_and_rejects_empty_fixture(mock_splunk):
    assert len(mock_splunk.run("search x", rows=2).rows) == 2
    (mock_splunk.dir / "runs.json").write_text("[]")
    with pytest.raises(ValueError, match="runs.json"):
        MockSplunk(mock_splunk.dir)


def test_mock_recall_missing_file_defaults_to_one(mock_splunk):
    (mock_splunk.dir / "recall.json").unlink()
    assert MockSplunk(mock_splunk.dir).run("search x", earliest="0") == Run(count=1)


def test_mock_ingest_writes_jsonl(mock_splunk):
    assert mock_splunk.ingest("wineventlog", "st", ["<a/>", "<b/>"], host="evil-host") == 2
    lines = [json.loads(l) for l in (mock_splunk.dir / "ingested.jsonl").read_text().splitlines()]
    assert lines == [
        {"index": "wineventlog", "sourcetype": "st", "host": "evil-host", "raw": "<a/>"},
        {"index": "wineventlog", "sourcetype": "st", "host": "evil-host", "raw": "<b/>"},
    ]


def test_mock_publish_appends_stanza(mock_splunk):
    assert not (mock_splunk.dir / "published.conf").exists()  # side-effect files never come along with the fixture copy
    assert mock_splunk.publish("A", "search a", {"is_scheduled": 1}) == "A"
    assert mock_splunk.publish("B", "search b", {"cron_schedule": "*/15 * * * *"}) == "B"
    text = (mock_splunk.dir / "published.conf").read_text()
    assert text == "[A]\nsearch = search a\nis_scheduled = 1\n\n[B]\nsearch = search b\ncron_schedule = */15 * * * *\n\n"


def test_mock_publish_macro_appends_stanza(mock_splunk):
    assert mock_splunk.publish_macro("a_filter", "search *") == "a_filter"
    assert (mock_splunk.dir / "published.conf").read_text() == "[a_filter]\ndefinition = search *\n\n"


def test_get_selects_kind(monkeypatch, mock_splunk):
    monkeypatch.setenv("DEA_FIXTURES", str(mock_splunk.dir))
    monkeypatch.delenv("DEA_SPLUNK", raising=False)
    monkeypatch.delenv("SPLUNK_TOKEN", raising=False)
    assert splunk.get().kind == "mock" and splunk.get("mock").dir == mock_splunk.dir
    monkeypatch.setenv("DEA_SPLUNK", "mock")
    monkeypatch.setenv("SPLUNK_TOKEN", "t")
    assert splunk.get().kind == "mock"
    monkeypatch.delenv("DEA_SPLUNK")
    monkeypatch.setenv("SPLUNK_HOST", "h")
    monkeypatch.setattr(client, "connect", MagicMock())
    assert splunk.get().kind == "real"  # SPLUNK_TOKEN set and DEA_SPLUNK unset => real
    with pytest.raises(ValueError):
        splunk.get("bogus")


# --- RealSplunk ---------------------------------------------------------------


def _stream(**payload) -> io.BytesIO:
    return io.BytesIO(json.dumps(payload).encode())


def test_real_from_env_uses_bearer_token(monkeypatch):
    connect, handler = MagicMock(), MagicMock()
    monkeypatch.setattr(client, "connect", connect)
    monkeypatch.setattr(binding, "handler", handler)
    monkeypatch.setenv("SPLUNK_HOST", "splunk.example")
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    monkeypatch.setenv("SPLUNK_VERIFY", "0")
    real = RealSplunk.from_env()
    assert real.kind == "real" and real.svc is connect.return_value
    kw = connect.call_args.kwargs
    assert kw["splunkToken"] == "tok" and kw["scheme"] == "https" and kw["host"] == "splunk.example"
    assert kw["port"] == 8089 and kw["app"] == "search" and kw["owner"] == "nobody" and kw["verify"] is False
    # no handler => splunk-sdk opens every socket with timeout=None and a blocking search can hang forever
    handler.assert_called_once_with(timeout=splunk.REQUEST_TIMEOUT, verify=False)
    assert kw["handler"] is handler.return_value and splunk.REQUEST_TIMEOUT > 0


def test_real_from_env_names_missing_vars(monkeypatch):
    monkeypatch.setattr(client, "connect", MagicMock())
    monkeypatch.delenv("SPLUNK_HOST", raising=False)
    monkeypatch.setenv("SPLUNK_TOKEN", "")
    with pytest.raises(ValueError, match=r"--splunk real needs SPLUNK_HOST, SPLUNK_TOKEN set \(see README"):
        RealSplunk.from_env()
    monkeypatch.setenv("SPLUNK_TOKEN", "tok")
    with pytest.raises(ValueError, match=r"needs SPLUNK_HOST set"):
        RealSplunk.from_env()


def test_real_run_blocking_job():
    svc = MagicMock()
    job = svc.jobs.create.return_value
    job.__getitem__.side_effect = {"resultCount": "7", "scanCount": "900"}.__getitem__
    job.results.return_value = _stream(preview=False, messages=[{"type": "ERROR", "text": "bad"}, {"type": "INFO", "text": "i"}], results=[{"a": "1"}, {"a": "2"}])
    run = RealSplunk(svc).run("search x", earliest="-1d", latest="now", rows=50)
    svc.jobs.create.assert_called_once_with("search x", exec_mode="blocking", earliest_time="-1d", latest_time="now")
    job.results.assert_called_once_with(output_mode="json", count=50)
    assert run == Run(count=None, scan_count=900, rows=[{"a": "1"}, {"a": "2"}], errors=["bad"])  # ERROR message => count=None
    job.cancel.assert_called_once_with()


def test_real_run_tolerates_empty_and_multi_document_bodies():
    svc = MagicMock()
    job = svc.jobs.create.return_value
    job.__getitem__.side_effect = {"resultCount": "0", "scanCount": "10"}.__getitem__
    job.results.return_value = io.BytesIO(b"")
    assert RealSplunk(svc).run("search x") == Run(count=0, scan_count=10)
    job.results.return_value = io.BytesIO(b'{"preview":false,"results":[{"a":"1"}]}\n\n{"preview":false,"results":[{"a":"2"}]}\n')
    assert RealSplunk(svc).run("search x").rows == [{"a": "1"}, {"a": "2"}]


def test_real_run_http_400_returns_error_run():
    response = MagicMock(status=400, reason="Bad Request", body=io.BytesIO(b"<response><messages><msg>Unable to parse</msg></messages></response>"))
    svc = MagicMock()
    svc.jobs.create.side_effect = HTTPError(response)
    run = RealSplunk(svc).run("search x")
    assert run.count is None and "Unable to parse" in run.errors[0]
    response.status = 500
    svc.jobs.create.side_effect = HTTPError(response)
    with pytest.raises(HTTPError):
        RealSplunk(svc).run("search x")


def test_real_run_failed_job_reports_its_messages_without_fetching_results():
    """Splunk 10.6: a search with a bad regex is accepted as a job (dispatchState=FAILED, messages on the job entry) and
    only results() answers HTTP 400, which escaped run() and killed the pipeline (real run 2)."""
    svc = MagicMock()
    job = svc.jobs.create.return_value
    job.__getitem__.side_effect = {"resultCount": "0", "scanCount": "0", "dispatchState": "FAILED", "isFailed": "1"}.__getitem__
    text = "Error in 'where' command: Regex: unmatched closing parenthesis"
    job.content = {"dispatchState": "FAILED", "isFailed": "1", "messages": {"fatal": [text], "error": [text]}}
    job.results.side_effect = HTTPError(MagicMock(status=400, reason="Bad Request", body=io.BytesIO(b'{"messages":[{"type":"FATAL","text":"..."}]}')))
    run = RealSplunk(svc).run("search x | where match(a, \"(?i)\\\\(b|c)\")")
    assert run == Run(count=None, scan_count=0, errors=[text])  # one error line, not fatal+error twice; count=None fails the gate
    job.results.assert_not_called()
    job.cancel.assert_called_once_with()
    job.content = {"dispatchState": "DONE", "messages": {"warn": ["no results"]}}  # warnings do not fail the run
    job.results.side_effect = None
    job.results.return_value = _stream(preview=False, results=[])
    assert RealSplunk(svc).run("search x") == Run(count=0, scan_count=0)


def test_real_publish_create_or_update():
    svc = MagicMock()
    svc.saved_searches.__contains__.return_value = False
    props = {"is_scheduled": 1, "dispatch.earliest_time": "-25m@m"}
    assert RealSplunk(svc).publish("Det", "search x", props) == "Det"
    svc.saved_searches.create.assert_called_once_with("Det", "search x", is_scheduled=1, **{"dispatch.earliest_time": "-25m@m"})
    svc.saved_searches.__contains__.return_value = True
    RealSplunk(svc).publish("Det", "search y", props)
    entity = svc.saved_searches.__getitem__.return_value
    entity.update.assert_called_once_with(search="search y", is_scheduled=1, **{"dispatch.earliest_time": "-25m@m"})
    entity.update.return_value.refresh.assert_called_once_with()


def test_real_publish_macro_create_or_update():
    svc = MagicMock()
    svc.macros.__contains__.return_value = False
    assert RealSplunk(svc).publish_macro("x_filter", "search *") == "x_filter"
    svc.macros.create.assert_called_once_with("x_filter", "search *")
    svc.macros.__contains__.return_value = True
    RealSplunk(svc).publish_macro("x_filter", "search NOT host=lab")
    svc.macros.__getitem__.return_value.update.assert_called_once_with(definition="search NOT host=lab")
    svc.macros.create.assert_called_once()  # not called again on update


def test_real_ingest_submits_each_raw():
    svc = MagicMock()
    svc.indexes.__contains__.return_value = True
    assert RealSplunk(svc).ingest("idx", "st", ["r1", "r2"], host="h") == 2
    idx = svc.indexes.__getitem__.return_value
    assert idx.submit.call_args_list == [((b"r1",), {"sourcetype": "st", "host": "h"}), ((b"r2",), {"sourcetype": "st", "host": "h"})]
    svc.indexes.create.assert_not_called()
    svc.indexes.__contains__.return_value = False
    RealSplunk(svc).ingest("new", "st", ["r"], host="h")
    svc.indexes.create.assert_called_once_with("new")
    svc.indexes.create.return_value.submit.assert_called_once_with(b"r", sourcetype="st", host="h")


def test_real_ingest_submits_utf8_bytes_for_non_latin1_event():
    """splunk-sdk 3.0.1 passes a str body straight to http.client, which encodes Latin-1 and raised
    UnicodeEncodeError on a reviewer evasion event containing an en dash (`powershell –enc ...`)."""
    svc = MagicMock()
    svc.indexes.__contains__.return_value = True
    raw = "<Event><Data Name='CommandLine'>powershell.exe \u2013enc QUJD</Data></Event>"
    RealSplunk(svc).ingest("idx", "st", [raw], host="h")
    (body,), _ = svc.indexes.__getitem__.return_value.submit.call_args
    assert isinstance(body, bytes) and body == raw.encode("utf-8")
    body.decode("latin-1")  # bytes never reach http.client's str->latin-1 encode


FIELDS_QUERY = 'search index=main sourcetype="st1" | head 2000 | dedup 100 EventCode keepempty=true | fieldsummary maxvals=3 | fields field count values'


def _index(name, total):
    ix = MagicMock()
    ix.name = name
    ix.__getitem__.side_effect = {"totalEventCount": total}.__getitem__
    return ix


def test_real_inventory_field_filtering_and_macros():
    # 65 eligible fields (counts 1000..936); internal names carry max_count 2000 so the floor is 100 (not 50):
    # "mid" (90) is only dropped when the floor is taken before internal fields are removed
    rows = [{"field": f"f{i:02d}", "count": str(1000 - i), "values": json.dumps([{"value": "x" * 100, "count": 1}] * 4)} for i in range(65)]
    rows += [{"field": "mid", "count": "90", "values": "[]"}, {"field": "rare", "count": "40", "values": "[]"}]
    rows += [{"field": n, "count": "2000", "values": "[]"} for n in ("_raw", "date_hour", "punct", "tag::eventtype")]
    streams = {
        "| tstats count where index=main by sourcetype": _stream(results=[{"sourcetype": "st1", "count": "500"}, {"sourcetype": "empty", "count": "0"}, {"sourcetype": "st2", "count": "900"}]),
        "| tstats count where index=other by sourcetype": _stream(results=[{"sourcetype": "st3", "count": "700"}]),
        FIELDS_QUERY: _stream(results=rows),
        'search index=main sourcetype="st1" | head 1 | fields _raw': _stream(results=[{"_raw": "r" * 700}]),
        'search index=main sourcetype="st2" | head 1 | fields _raw': _stream(results=[]),
        'search index=other sourcetype="st3" | head 1 | fields _raw': _stream(results=[{"_raw": "raw3"}]),
    }
    svc = MagicMock()
    svc.indexes.__iter__.return_value = [_index("_internal", "5"), _index("main", "1400"), _index("zero", "0"), _index("other", "700")]
    svc.jobs.oneshot.side_effect = lambda spl, **kw: streams[spl] if spl in streams else _stream(results=[])
    # real confs["macros"] titles carry the argcount; `drop_dm_object_name(1)`/`drop_dm_object_name(2)` collapse to one bare name
    macros = [MagicMock() for _ in range(4)]
    for m, name in zip(macros, ("sysmon", "security_content_ctime(1)", "drop_dm_object_name(1)", "drop_dm_object_name(2)")):
        m.name = name
    svc.confs.__getitem__.return_value = macros

    inv = RealSplunk(svc).inventory(window="-3d", max_sourcetypes=2)

    assert inv.window == "-3d" and inv.macros == ["drop_dm_object_name", "security_content_ctime", "sysmon"]
    svc.confs.__getitem__.assert_called_once_with("macros")
    assert inv.index_names() == {"main", "other"}
    assert inv.sourcetype_names() == {"st2", "st3"}  # cap 2 by count: st2 (900), st3 (700); st1 (500) and empty (0) dropped
    assert inv.find("main", "st2").sample is None and inv.find("other", "st3").sample == "raw3"
    tstats_calls = [c for c in svc.jobs.oneshot.call_args_list if c.args[0].startswith("| tstats")]
    assert len(tstats_calls) == 2 and all(c.kwargs["earliest_time"] == "-3d" for c in tstats_calls)

    fields = RealSplunk(svc)._fields("main", "st1")
    assert FIELDS_QUERY in [c.args[0] for c in svc.jobs.oneshot.call_args_list]
    assert RealSplunk(svc)._fields("main", "st2") == {}  # no fieldsummary rows => no fields
    assert len(fields) == 60 and set(fields) == {f"f{i:02d}" for i in range(60)}
    assert "mid" not in fields and "rare" not in fields
    assert all(len(v) == 3 and all(len(s) == 80 for s in v) for v in fields.values())
    assert RealSplunk(svc)._sample("main", "st1") == "r" * 600
