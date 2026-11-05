"""End-to-end offline run: idea -> done -> publish (§11.3), plus the failed_noisy and infeasible scenarios."""

import json
from collections import Counter
from pathlib import Path

import pytest
import yaml

from detection_engineering_agent import cli
from detection_engineering_agent.models import Detection

STEM = "office_app_spawns_encoded_powershell"


@pytest.fixture
def env(mock_splunk, tmp_path, monkeypatch):
    monkeypatch.setenv("DEA_SPLUNK", "mock")
    monkeypatch.setenv("DEA_FIXTURES", str(mock_splunk.dir))
    return tmp_path


def _run(fixture_dir, tmp: Path, idea: Path | None = None) -> int:
    return cli.main(["run", str(idea or fixture_dir / "idea.yml"), "--runs", str(tmp / "runs"), "-o", str(tmp / "detections"),
                     "--inventory", str(tmp / "inventory.json"), "--refresh"])


def _state(tmp: Path) -> dict:
    return json.loads((tmp / "runs" / "3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11" / "state.json").read_text())


def test_idea_to_done_to_publish(fixture_dir, fake_llm, mock_splunk, env):
    fake = fake_llm(fixture_dir / "llm")
    assert _run(fixture_dir, env) == 0
    st = _state(env)
    assert st["state"] == "done" and st["tunes"] == 2 and st["remakes"] == 0 and st["reviews"] == 1
    assert len(st["drafts"]) == 4 and len(st["examples"]) == 1 and st["cost_usd"] == 0.0
    assert [h["step"] for h in st["history"]] == [
        "match", "author", "test", "tune", "test", "tune", "test", "review", "refine", "test", "review", "render"]
    assert Counter(c[0] for c in fake.calls) == {"author": 1, "tune": 2, "review": 2, "refine": 1}
    assert st["gates"]["recall"] == {"ran": True, "counts": [1], "ok": True}

    out = env / "detections"
    det = Detection.model_validate(yaml.safe_load((out / f"{STEM}.yml").read_text()))
    assert det.status == "experimental"
    assert det.search.endswith(f"`{STEM}_filter`")
    assert (out / "macros" / f"{STEM}_filter.yml").exists()
    assert not list(out.rglob("*.conf"))
    assert sorted(st["outputs"]) == sorted(str(p) for p in out.rglob("*.yml"))

    assert cli.main(["publish", str(out), "--splunk", "mock"]) == 0
    conf = (mock_splunk.dir / "published.conf").read_text()
    assert "[Office app spawns encoded PowerShell]" in conf
    assert "is_scheduled = 1" in conf and "cron_schedule = */15 * * * *" in conf
    assert conf.index(f"[{STEM}_filter]\ndefinition = search *\n") < conf.index("[Office app spawns encoded PowerShell]")


def test_noisy_forever_fails_noisy(fixture_dir, fake_llm, mock_splunk, env):
    runs = mock_splunk.dir / "runs.json"
    runs.write_text(json.dumps(json.loads(runs.read_text())[:1]))  # the 412-alert entry repeats forever
    fake = fake_llm(fixture_dir / "llm_noisy")
    assert _run(fixture_dir, env) == 3
    st = _state(env)
    assert st["state"] == "failed_noisy"
    assert Counter(c[0] for c in fake.calls) == {"author": 2, "tune": 6}
    assert len(st["failed_attempts"]) == 4
    assert not (env / "detections").exists()


def test_no_matching_source_is_infeasible(fixture_dir, fake_llm, env):
    fake = fake_llm(fixture_dir / "llm")
    data = yaml.safe_load((fixture_dir / "idea.yml").read_text())
    for ls in data["log_sources"]:
        ls["keywords"] = ["nonexistent"]
    idea = env / "idea.yml"
    idea.write_text(yaml.safe_dump(data))
    assert _run(fixture_dir, env, idea) == 2
    st = _state(env)
    assert st["state"] == "infeasible" and fake.calls == []
    assert (env / "runs" / data["id"] / "coverage.md").exists()
