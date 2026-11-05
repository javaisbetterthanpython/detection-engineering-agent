"""The single inference helper: one `claude -p` subprocess per call (§6.1)."""

import json
import subprocess

from pydantic import BaseModel

from . import models, prompts


class CostCapExceeded(RuntimeError): ...


class LLMError(RuntimeError): ...


def _detail(proc: subprocess.CompletedProcess) -> str:
    """Diagnostic text for a failed call: stderr, else the stdout envelope's api_error_status/result.

    `claude -p` reports API errors (e.g. an unsupported model id) with exit 1, EMPTY stderr and the
    reason only in the JSON envelope's `result`, so stderr alone yields a blank message."""
    if proc.stderr.strip():
        return proc.stderr.strip()
    try:
        env = json.loads(proc.stdout)
    except ValueError:
        return proc.stdout.strip()[:500]
    status = env.get("api_error_status")
    return " ".join(p for p in (f"api_error_status={status}" if status else "", str(env.get("result") or "")) if p)


def ask[T: BaseModel](step: str, payload: dict, out: type[T], model: str | None = None, effort: str | None = None) -> tuple[T, float]:
    """Run one pure-inference call for `step` and return (validated output, cost_usd)."""
    extra = set(payload) - set(prompts.INPUTS[step])
    if extra:
        raise ValueError(f"payload keys not allowed for {step!r}: {sorted(extra)}")
    argv = ["claude", "-p",
            "--model", model or prompts.MODEL[step], "--effort", effort or prompts.EFFORT[step],
            "--tools", "", "--max-turns", "2",
            "--setting-sources", "", "--no-session-persistence", "--disable-slash-commands",
            "--max-budget-usd", "2.00",
            "--system-prompt", prompts.SYSTEM[step],
            "--output-format", "json",
            "--json-schema", json.dumps(models.schema(out))]
    stdin = json.dumps(payload, ensure_ascii=False)
    err: Exception | None = None
    for _ in range(2):
        try:
            proc = subprocess.run(argv, input=stdin, capture_output=True, text=True, timeout=600)
            if proc.returncode != 0:
                raise LLMError(f"claude exited {proc.returncode}: {_detail(proc)}")
            env = json.loads(proc.stdout)
            if env.get("subtype") != "success" or env.get("is_error") or "structured_output" not in env:
                raise LLMError(f"claude result not usable: subtype={env.get('subtype')!r} is_error={env.get('is_error')!r}"
                               + (f": {_detail(proc)}" if env.get("is_error") else ""))
            return out.model_validate(env["structured_output"]), float(env.get("total_cost_usd") or 0.0)
        except (LLMError, ValueError) as e:
            err = e
    raise LLMError(f"{step}: inference failed twice: {err}") from err
