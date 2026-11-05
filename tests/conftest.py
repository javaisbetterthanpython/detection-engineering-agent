import json
import shutil
import subprocess
from pathlib import Path

import pytest

FIXTURES = Path(__file__).parent / "fixtures"


@pytest.fixture
def fixture_dir() -> Path:
    return FIXTURES


@pytest.fixture
def mock_splunk(tmp_path):
    from detection_engineering_agent.splunk import MockSplunk

    # a `dea run`/`dea publish` on the default mock writes ingested.jsonl/published.conf into the fixtures; never copy them
    return MockSplunk(shutil.copytree(FIXTURES / "splunk", tmp_path / "splunk", ignore=shutil.ignore_patterns("*.jsonl", "*.conf")))


@pytest.fixture
def idea():
    from detection_engineering_agent.models import Idea

    return Idea.load(FIXTURES / "idea.yml")


@pytest.fixture
def inventory():
    from detection_engineering_agent.models import Inventory

    return Inventory.model_validate_json((FIXTURES / "splunk" / "inventory.json").read_text())


@pytest.fixture
def tmp_runs(tmp_path) -> Path:
    runs = tmp_path / "runs"
    runs.mkdir()
    return runs


class FakeLLM:
    """Scripted `subprocess.run` replacement: one `<dir>/<step>.json` list per step, consumed in order."""

    def __init__(self, directory: Path):
        self.envelope = json.loads((FIXTURES / "llm" / "envelope.json").read_text())
        self.queues = {p.stem: json.loads(p.read_text()) for p in Path(directory).glob("*.json")}
        self.calls: list = []

    def __call__(self, argv, **kwargs):
        from detection_engineering_agent import prompts

        step = {v: k for k, v in prompts.SYSTEM.items()}[argv[argv.index("--system-prompt") + 1]]
        self.calls.append((step, argv, kwargs))
        entry = self.queues.get(step, []).pop(0)  # IndexError when exhausted or unscripted -> pipeline `error` terminal
        stdout = json.dumps({**self.envelope, "structured_output": entry, "total_cost_usd": 0.0})
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")


@pytest.fixture
def fake_llm(monkeypatch):
    def factory(dir=FIXTURES / "llm") -> FakeLLM:
        fake = FakeLLM(dir)
        monkeypatch.setattr(subprocess, "run", fake)
        return fake

    return factory
