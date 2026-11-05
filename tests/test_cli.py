import json
import re

import pytest

from detection_engineering_agent import cli, models
from detection_engineering_agent.models import Detection, Draft, Idea
from detection_engineering_agent.pipeline import EXIT_CODES, Pipeline

SYSMON = "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational"


def test_ideas_writes_validated_ideas_once(fixture_dir, fake_llm, tmp_path, capsys):
    fake = fake_llm()
    out = tmp_path / "ideas"
    assert cli.main(["ideas", str(fixture_dir / "article.html"), "-o", str(out)]) == 0
    files = sorted(out.glob("*.yml"))
    assert len(files) == 2
    for f in files:
        idea = Idea.load(f)
        assert idea.source_url == str(fixture_dir / "article.html")
        assert f.stem == idea.stem
    step, argv, kwargs = fake.calls[0]
    assert step == "ideas" and set(json.loads(kwargs["input"])) == {"text"}
    assert "--model" in argv and argv[argv.index("--model") + 1] == "claude-haiku-5-5"

    before = {f: f.stat().st_mtime_ns for f in files}
    capsys.readouterr()
    assert cli.main(["ideas", str(fixture_dir / "article.html"), "-o", str(out)]) == 0
    assert capsys.readouterr().out.count("exists") == 2
    assert {f: f.stat().st_mtime_ns for f in sorted(out.glob("*.yml"))} == before
    assert len(fake.calls) == 2  # exactly one inference call per article


def test_ideas_skips_draft_whose_title_has_no_ascii_stem(fixture_dir, tmp_path, monkeypatch, capsys):
    drafts = json.loads((fixture_dir / "llm" / "ideas.json").read_text())[0]["ideas"]
    cyrillic = drafts[0] | {"title": "Обнаружение"}
    out = models.IdeasOut.model_validate({"ideas": [drafts[0], cyrillic, drafts[1]]})
    monkeypatch.setattr(cli.llm, "ask", lambda *a, **k: (out, 0.0))
    dest = tmp_path / "ideas"
    assert cli.main(["ideas", str(fixture_dir / "article.html"), "-o", str(dest)]) == 0
    assert {f.stem for f in dest.glob("*.yml")} == {"office_app_spawns_encoded_powershell", "scheduled_task_persistence_created_by_powershell"}
    err = capsys.readouterr().err
    assert "warning: skipping 'Обнаружение'" in err and "ASCII letter or digit" in err


def test_ideas_model_override_and_short_text(fixture_dir, fake_llm, tmp_path):
    fake = fake_llm()
    assert cli.main(["ideas", str(fixture_dir / "article.html"), "-o", str(tmp_path), "--model", "claude-sonnet-5-5"]) == 0
    argv = fake.calls[0][1]
    assert argv[argv.index("--model") + 1] == "claude-sonnet-5-5"
    short = tmp_path / "short.txt"
    short.write_text("too short")
    assert cli.main(["ideas", str(short), "-o", str(tmp_path)]) == 1
    assert len(fake.calls) == 1


def test_extract_text_local_files(fixture_dir, tmp_path):
    text, url = cli.extract_text(str(fixture_dir / "article.html"))
    assert len(text) > 2000 and "powershell" in text.lower() and url.endswith("article.html")
    md = tmp_path / "notes.md"
    md.write_text("# raw\n" * 50)
    assert cli.extract_text(str(md))[0] == md.read_text()


def _run_args(fixture_dir, tmp_path, idea="idea.yml"):
    return ["run", str(fixture_dir / idea), "--runs", str(tmp_path / "runs"), "-o", str(tmp_path / "detections"),
            "--inventory", str(tmp_path / "inventory.json"), "--refresh", "--splunk", "mock"]


@pytest.mark.parametrize("terminal,rc", sorted(EXIT_CODES.items()))
def test_run_parses_flags_and_maps_exit_codes(fixture_dir, mock_splunk, monkeypatch, tmp_path, terminal, rc):
    monkeypatch.setenv("DEA_FIXTURES", str(mock_splunk.dir))
    seen = {}

    def drive(self):
        seen["config"], seen["run_dir"] = self.config, self.run_dir
        return terminal

    monkeypatch.setattr(Pipeline, "drive", drive)
    argv = _run_args(fixture_dir, tmp_path) + ["--window=-7d", "--tunes", "2", "--max-cost", "9", "--model", "tune=claude-opus-5-5"]
    assert cli.main(argv) == rc
    cfg = seen["config"]
    assert cfg.window == "-7d" and cfg.max_tunes == 2 and cfg.max_cost_usd == 9.0 and cfg.models == {"tune": "claude-opus-5-5"}
    assert cfg.out_dir == str(tmp_path / "detections")
    assert seen["run_dir"] == tmp_path / "runs" / "3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11"
    assert (tmp_path / "inventory.json").exists()


def test_run_rejects_bad_model_spec(fixture_dir, tmp_path):
    with pytest.raises(SystemExit):
        cli.main(_run_args(fixture_dir, tmp_path) + ["--model", "bogus=claude-opus-5-5"])


@pytest.mark.parametrize("cmd", ["run", "inventory"])
def test_bad_window_rejected_before_any_work(fixture_dir, tmp_path, monkeypatch, cmd):
    monkeypatch.setattr(Pipeline, "drive", lambda self: pytest.fail("pipeline started with invalid --window"))
    monkeypatch.setattr(cli, "load_inventory", lambda *a, **k: pytest.fail("inventory fetched with invalid --window"))
    argv = _run_args(fixture_dir, tmp_path) if cmd == "run" else ["inventory", "--splunk", "mock"]
    with pytest.raises(SystemExit):
        cli.main(argv + ["--window=-7"])


def test_load_inventory_uses_fresh_cache(mock_splunk, tmp_path, monkeypatch):
    path = tmp_path / "nested" / "dir" / "inventory.json"
    inv = cli.load_inventory(path, mock_splunk, "-7d", refresh=False)
    assert inv.sourcetype_names() == mock_splunk.inventory().sourcetype_names()
    monkeypatch.setattr(mock_splunk, "inventory", lambda **kw: (_ for _ in ()).throw(AssertionError("must use cache")))
    assert cli.load_inventory(path, mock_splunk, "-7d", refresh=False) == inv
    with pytest.raises(AssertionError):
        cli.load_inventory(path, mock_splunk, "-7d", refresh=True)


def _detection(idea, tmp_path) -> Detection:
    draft = Draft(n=1, origin="author", spl=f'index=wineventlog sourcetype="{SYSMON}" EventCode=1 | stats count by Computer User',
                  group_fields=["Computer", "User"], fields_used=["Computer", "EventCode", "User"])
    src = models.Source(index="wineventlog", sourcetype=SYSMON, score=14, data_source="Sysmon EventID 1",
                        asset_type="Endpoint", security_domain="endpoint")
    return Detection.from_run(idea, draft, [src], [], "experimental", tmp_path)


def _write(idea, out) -> Detection:  # what do_render writes: <out>/<stem>.yml + <out>/macros/<stem>_filter.yml
    det = _detection(idea, out)
    (out / f"{idea.stem}.yml").write_text(det.to_yaml())
    (out / "macros").mkdir(exist_ok=True)
    (out / "macros" / f"{idea.stem}_filter.yml").write_text(Detection.macro_yaml(idea.stem))
    return det


def test_publish_dry_run_prints_props(idea, tmp_path, capsys):
    det = _write(idea, tmp_path)
    assert cli.main(["publish", str(tmp_path), "--dry-run", "--es"]) == 0
    out = capsys.readouterr().out
    assert f"[{det.name}]" in out and f"search = {det.search}" in out
    assert "is_scheduled = 1" in out and "cron_schedule = */15 * * * *" in out and "action.notable = 1" in out
    assert out.index(f"[{idea.stem}_filter]\ndefinition = search *\n") < out.index(f"[{det.name}]")


def test_publish_mock_and_failure(idea, mock_splunk, tmp_path, monkeypatch, capsys):
    monkeypatch.setenv("DEA_FIXTURES", str(mock_splunk.dir))
    good = tmp_path / f"{idea.stem}.yml"
    _write(idea, tmp_path)
    assert cli.main(["publish", str(good), "--splunk", "mock"]) == 0
    conf = (mock_splunk.dir / "published.conf").read_text()
    assert conf.index(f"[{idea.stem}_filter]\ndefinition = search *\n") < conf.index(f"[{idea.title}]")  # macro first
    bad = tmp_path / "bad.yml"
    bad.write_text("name: nope\n")
    assert cli.main(["publish", str(bad), "--splunk", "mock"]) == 1
    # a search that ends in `<stem>_filter` without its macros/<stem>_filter.yml cannot run on Splunk: fail that file
    (tmp_path / "macros" / f"{idea.stem}_filter.yml").unlink()
    assert cli.main(["publish", str(good), "--splunk", "mock"]) == 1
    assert f"{idea.stem}_filter.yml" in capsys.readouterr().err
    # a missing path (e.g. detections/ before the first `dea run`) is skipped with a note, not an error
    assert cli.main(["publish", str(tmp_path / "nope"), "--splunk", "mock"]) == 0
    assert "nope: not found, skipping" in capsys.readouterr().err


def test_run_verbose_prints_one_transition_line_per_step_to_stderr(fixture_dir, fake_llm, mock_splunk, monkeypatch, tmp_path, capsys):
    monkeypatch.setenv("DEA_FIXTURES", str(mock_splunk.dir))
    fake_llm()
    assert cli.main(_run_args(fixture_dir, tmp_path)) == 0
    out, err = capsys.readouterr()
    assert err == ""  # default off: stdout/stderr unchanged
    assert str(tmp_path / "detections" / "office_app_spawns_encoded_powershell.yml") in out.splitlines()
    fake_llm()
    assert cli.main(_run_args(fixture_dir, tmp_path) + ["-v"]) == 0
    out, err = capsys.readouterr()
    lines = err.splitlines()
    assert [l.split()[:3] for l in lines[:2]] == [["start", "->", "matched"], ["matched", "->", "drafted"]]
    assert lines[-1].split()[:4] == ["approved", "->", "done", "render"]
    assert len(lines) == 12  # one per transition (the history has 12 steps)
    assert re.fullmatch(r"\s+matched -> drafted\s+author\s+\$0\.00\s+\d+:\d\d", lines[1])
    assert str(tmp_path / "detections" / "office_app_spawns_encoded_powershell.yml") in out.splitlines()
