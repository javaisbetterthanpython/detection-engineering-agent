# Contributing

## Setup

- `uv sync --group dev`; Python 3.13 only (`splunk-sdk==3.0.1` needs it).
- `uv run pytest -q` must pass with no network, no `claude` binary and no Splunk. Inference is a monkeypatched `subprocess.run`; Splunk is the mock adapter in `tests/fixtures/splunk`.

## Ground truth

- [docs/SPEC.md](docs/SPEC.md) decides behaviour. A change to behaviour edits the spec section first, then the code, then the tests, in the same PR; name the section in the PR description.
- Any change to `pipeline.TRANSITIONS` must regenerate the state diagram (`uv run python docs/scripts/state_diagram.py`) and update [docs/pipeline.md](docs/pipeline.md) in the same PR.
- Every payload key a system prompt names must be in `prompts.INPUTS[step]` (`tests/test_llm.py` enforces it); `llm.ask` rejects anything else at runtime.
- Edits to `src/detection_engineering_agent/prompts.py` need a real run attached to the PR: its `runs/<id>/state.json` goes to `docs/development/runs/` with the scratch paths stripped, and a dated line goes in [docs/development/build-log.md](docs/development/build-log.md).

## Fixtures and tests

- Every scripted SPL in a scenario (`tests/fixtures/llm*/`) must be unique after `spl.normalise()`, or the stall guard routes the run to remake and the test takes a different path.
- Every fixture SPL must lint clean against `tests/fixtures/splunk/inventory.json` (known fields, index, sourcetype, a `| stats ... by`), unless the test is about lint.
- The shared `tests/fixtures/splunk/runs.json` never scripts a Splunk error; a test that needs one writes its own.
- Every pipeline change adds or changes a test under `tests/`.

## Docs

- Every number and artifact in the README and `docs/` comes from a file in the repo (run states, fixtures, `EXIT_CODES`, `Config` defaults) and carries its provenance.
- GIFs are recordings of real commands; rebuild with `make -C docs/assets` and commit the `.cast` files.
- Relative links only, no absolute GitHub URLs outside the badges.

## Pull requests

One concern per PR, CI green, no model-chosen routing anywhere. State which exit code or pipeline state the change affects.
