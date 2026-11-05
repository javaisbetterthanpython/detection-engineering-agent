import json
import subprocess

import pytest

from detection_engineering_agent import llm, prompts
from detection_engineering_agent.models import SplOut, schema


def patch_run(monkeypatch, stdout):
    calls = []

    def fake(argv, **kwargs):
        calls.append((argv, kwargs))
        return subprocess.CompletedProcess(argv, 0, stdout=stdout, stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    return calls


def test_ask_builds_argv_and_returns_output(monkeypatch, fixture_dir):
    envelope = (fixture_dir / "llm" / "envelope.json").read_text()
    calls = patch_run(monkeypatch, envelope)
    payload = {"spl": "index=x | stats count by host", "problems": ["noisy"], "schedule": prompts.SCHEDULE}
    result, cost = llm.ask("tune", payload, SplOut)

    assert isinstance(result, SplOut)
    assert result.spl == json.loads(envelope)["structured_output"]["spl"]
    assert cost == 0.0076
    assert len(calls) == 1
    argv, kwargs = calls[0]
    assert argv[:2] == ["claude", "-p"]
    for flag, value in [("--tools", ""), ("--max-turns", "2"), ("--setting-sources", ""),
                        ("--system-prompt", prompts.SYSTEM["tune"]), ("--json-schema", json.dumps(schema(SplOut))),
                        ("--model", prompts.MODEL["tune"]), ("--effort", prompts.EFFORT["tune"]),
                        ("--output-format", "json")]:
        assert argv[argv.index(flag) + 1] == value
    assert "--no-session-persistence" in argv
    assert argv.count("--tools") == 1 and argv.count("--max-turns") == 1 and argv.count("--setting-sources") == 1
    assert kwargs["input"] == json.dumps(payload, ensure_ascii=False)
    assert not any(payload["spl"] in a for a in argv)
    assert kwargs["capture_output"] and kwargs["text"]


def test_explicit_model_and_effort(monkeypatch, fixture_dir):
    calls = patch_run(monkeypatch, (fixture_dir / "llm" / "envelope.json").read_text())
    llm.ask("tune", {"spl": "x"}, SplOut, model="claude-opus-5-5", effort="high")
    argv = calls[0][0]
    assert argv[argv.index("--model") + 1] == "claude-opus-5-5"
    assert argv[argv.index("--effort") + 1] == "high"


def test_error_max_turns_retries_once_then_raises(monkeypatch, fixture_dir):
    env = json.loads((fixture_dir / "llm" / "envelope.json").read_text())
    env["subtype"] = "error_max_turns"
    calls = patch_run(monkeypatch, json.dumps(env))
    with pytest.raises(llm.LLMError):
        llm.ask("tune", {"spl": "x"}, SplOut)
    assert len(calls) == 2
    assert calls[0][0] == calls[1][0]
    assert calls[0][1]["input"] == calls[1][1]["input"]


def test_is_error_retries_once_then_raises(monkeypatch, fixture_dir):
    env = json.loads((fixture_dir / "llm" / "envelope.json").read_text())
    env["is_error"] = True
    calls = patch_run(monkeypatch, json.dumps(env))
    with pytest.raises(llm.LLMError):
        llm.ask("tune", {"spl": "x"}, SplOut)
    assert len(calls) == 2


def test_nonzero_exit_surfaces_envelope_result(monkeypatch, fixture_dir):
    # Real shape from claude 2.1.198 rejecting claude-opus-5-5: exit 1, empty stderr, reason only in stdout.
    env = json.loads((fixture_dir / "llm" / "envelope.json").read_text())
    env.update(is_error=True, api_error_status=400,
               result="API Error: 400 Claude Code 2.1.198 does not support this model; version 2.1.280 or newer is required.")
    env.pop("structured_output")
    calls = []

    def fake(argv, **kwargs):
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 1, stdout=json.dumps(env), stderr="")

    monkeypatch.setattr(subprocess, "run", fake)
    with pytest.raises(llm.LLMError) as info:
        llm.ask("author", {"summary": "x"}, SplOut)
    assert len(calls) == 2
    msg = str(info.value)
    assert "claude exited 1" in msg and "api_error_status=400" in msg and "does not support this model" in msg


def test_nonzero_exit_prefers_stderr(monkeypatch):
    monkeypatch.setattr(subprocess, "run",
                        lambda argv, **kw: subprocess.CompletedProcess(argv, 2, stdout="", stderr="boom\n"))
    with pytest.raises(llm.LLMError, match=r"claude exited 2: boom"):
        llm.ask("tune", {"spl": "x"}, SplOut)


def test_invalid_structured_output_retries_once_then_raises(monkeypatch, fixture_dir):
    env = json.loads((fixture_dir / "llm" / "envelope.json").read_text())
    env["structured_output"] = {"nope": 1}
    calls = patch_run(monkeypatch, json.dumps(env))
    with pytest.raises(llm.LLMError):
        llm.ask("tune", {"spl": "x"}, SplOut)
    assert len(calls) == 2


def test_disallowed_payload_key_raises_before_subprocess(monkeypatch):
    calls = patch_run(monkeypatch, "")
    with pytest.raises(ValueError):
        llm.ask("tune", {"spl": "x", "bogus": 1}, SplOut)
    assert calls == []


def test_prompts_tables_are_consistent():
    assert set(prompts.SYSTEM) == set(prompts.INPUTS) == set(prompts.MODEL) == set(prompts.EFFORT)
    for step in ("author", "tune", "refine"):
        assert prompts.SYSTEM[step].endswith(prompts.RULES)
    assert prompts.SCHEDULE == {"cron": "*/15 * * * *", "window": "20m"}


@pytest.mark.parametrize("step", ["author", "tune", "review", "refine"])
def test_prompts_name_only_payload_keys(step):
    """Every payload key a system prompt names must be an input of that step (no dangling references such as attack_steps in refine)."""
    import re

    keys = {k for ks in prompts.INPUTS.values() for k in ks} - {"spl", "text"}
    named = {w for w in re.findall(r"[a-z]+(?:_[a-z]+)+", prompts.SYSTEM[step]) if w in keys}
    allowed = set(prompts.INPUTS[step]) | ({"available_fields"} if step == "author" else set())  # author gets sources[].fields
    assert named <= allowed, named - allowed


def test_review_prompt_scopes_severity_and_events_to_attack_steps():
    """Run 4 (tasks/e2e_run4_state.json): the reviewer, told only to "bypass this SPL", raised a new HIGH each round for an
    attack the idea does not describe (Office -> cmd.exe -> powershell; base64 without -enc), each with an evasion_event
    recall would force refine to match; against max_reviews=2 that is failed_review by construction. attack_steps is the
    claim under test: in-scope variants keep full severity, out-of-scope attacks are at most low with no event."""
    text = prompts.SYSTEM["review"]
    assert "attack_steps are the claim under test" in text
    assert "Severity high/critical only if a realistic variant of attack_steps is fully missed" in text
    assert "out of scope: report it at most as low and give it no evasion_event" in text
    assert "alternate parents" not in text  # seeded the interposed-launcher chain that the idea never claimed
    for variant in ("renamed binaries", "quoting", "abbreviated or colon-separated switches", "field absence"):
        assert variant in text  # the teeth: every in-scope variant class is still named


def test_rules_state_spl_backslash_escaping():
    """Real-Splunk run 3 (tasks/real_splunk_run3_state.json): refine/tune emitted match(Image, "(?i)\\powershell\\.exe$"), which an
    SPL double-quoted string hands to PCRE as \\p ("unknown property after \\P or \\p") and "\\\\(" as a literal paren ("unmatched
    closing parenthesis"); the run ended failed_noisy with no detection. Verified on Splunk 10: \\\\\\\\ is one literal backslash,
    [.] and [\\\\\\\\/] need none, and "\\\\WINWORD" is \\W (silently 0 matches)."""
    rule = prompts.RULES.splitlines()[-1]
    assert rule.startswith("9. ") and r"\\ is one backslash" in rule
    assert r'match(Image, "(?i)\\\\powershell\\.exe$")' in rule  # the correct spelling, verbatim
    assert r'"\\powershell" reaches the regex as \p' in rule and r'"\\WINWORD" reaches it as \W' in rule  # both failure modes named
    assert r"[.] for a literal dot, [\\\\/] for a path separator" in rule  # the backslash-free alternatives
    for step in ("author", "tune", "refine"):
        assert rule in prompts.SYSTEM[step]
