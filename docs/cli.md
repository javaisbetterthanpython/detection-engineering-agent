# CLI reference

`dea` is an argparse program with four subcommands: `ideas`, `inventory`, `run`, `publish` (`src/detection_engineering_agent/cli.py`). Run it as `uv run dea ...` from the repo root. Every flag and default below is read from `cli.py` and `pipeline.Config`.

## `dea ideas <src>`

Article in, idea YAMLs out. One `claude -p` call per article, whatever the number of ideas.

```sh
uv run dea ideas https://example.org/post -o ideas/
uv run dea ideas report.pdf -o ideas/
uv run dea ideas tests/fixtures/article.html -o ideas/ --model claude-sonnet-5-5
```

| flag | default | effect |
|---|---|---|
| `src` | required | a `http://`/`https://` URL, or a local `.html`/`.htm` (trafilatura), `.pdf` (pypdf), `.txt`/`.md` (read as is) |
| `-o`, `--out` | `ideas` | output directory, created if missing |
| `--model` | `claude-haiku-5-5` | the model name itself (not `STEP=MODEL`) |

Behaviour: text under 200 characters is an error (exit 1); text over 100,000 characters is head-truncated with a stderr warning. Each returned idea gets a uuid4 `id` and `source_url`; ideas with no `attack_steps` or no `log_sources` are skipped with a warning; invalid MITRE ids are dropped. The file is `<out>/<stem>.yml`; an existing file is left alone and `<path> exists` is printed. Written paths go to stdout. Known limit: articles rarely quote raw events, so `attack_examples` is usually empty and the resulting run renders with `status: experimental`.

## `dea inventory`

Fetch the Splunk inventory (indexes, sourcetypes, common fields with top values, one raw sample per sourcetype, macro names) or print the cached one.

```sh
uv run dea inventory --splunk real --refresh
uv run dea inventory --splunk mock
```

| flag | default | effect |
|---|---|---|
| `--splunk` | automatic (below) | `mock` or `real` |
| `--window` | `-7d` | Splunk relative time for the sourcetype counts; write it as `--window=-7d` |
| `--refresh` | off | refetch even when the cache is younger than 24 hours |
| `-o`, `--out` | `inventory.json` | cache file |
| `--max-sourcetypes` | `200` | keep the N highest-count sourcetypes |

Prints one `index<TAB>sourcetype<TAB>count` line per sourcetype. Exit 0, or 1 on any exception (message on stderr as `error: ...`).

## `dea run <idea.yml>`

The pipeline ([pipeline.md](pipeline.md)).

```sh
uv run dea run tests/fixtures/idea.yml --splunk mock
uv run dea run ideas/<stem>.yml --splunk real --window=-7d
uv run dea run ideas/<stem>.yml --resume --max-cost 10
uv run dea run ideas/<stem>.yml --model author=claude-opus-4-8 --model review=claude-opus-4-8 --model refine=claude-opus-4-8
```

| flag | default | effect |
|---|---|---|
| `idea` | required | the idea YAML; it must carry a uuid4 `id` |
| `--splunk` | automatic | `mock` or `real` |
| `--inventory` | `inventory.json` | inventory cache to read (fetched when missing or older than 24 hours) |
| `--refresh` | off | refetch the inventory first |
| `--window` | `-7d` | window of the noise run; `--window=-7d` |
| `--resume` | off | continue from `runs/<idea_id>/state.json` when it exists |
| `--tunes` | `3` | max tune rounds per draft line |
| `--remakes` | `1` | max remakes (fresh `author` call with `failed_attempts`) |
| `--reviews` | `2` | max refine rounds |
| `--max-cost` | `5.0` | USD cap on the run's total inference cost |
| `--attack-index` | `dea_attack` | scratch index the recall gate ingests into |
| `--max-scan` | `50000000` | `scan_count` above which a performance warning is added; never blocks |
| `--model` | none | `STEP=MODEL`, repeatable; `STEP` in `ideas`, `author`, `tune`, `review`, `refine` |
| `-o`, `--out` | `detections` | where the detection and macro YAML are written |
| `--runs` | `runs` | where `<idea_id>/state.json` (and `coverage.md`) are written |
| `-v`, `--verbose` | off | one stderr line per state transition: `<from> -> <to>  <step>  $<cost>  <m:ss>` |

Output on stdout: one summary line `<state>  tunes=<n> remakes=<n> reviews=<n> cost_usd=<x.xx>`, then one line per written file on `done`, the `coverage.md` path on `infeasible`, or the final `gates["problems"]` lines otherwise. On `error` the exception text goes to stderr. Nothing is printed to stdout while the pipeline is running; `-v` prints one stderr line per state transition (from, to, the last `history` step and its cost, elapsed time), or follow `cat runs/<idea_id>/state.json` (the `history` list and `state` field).

Run 5's stdout, verbatim:

```
done  tunes=2 remakes=0 reviews=2 cost_usd=1.30
detections/office_app_spawns_encoded_powershell.yml
detections/macros/office_app_spawns_encoded_powershell_filter.yml
```

(paths were absolute in the original log because the run used `-o <absolute dir>`.)

On `--resume` the flags given on the command line win over the persisted config: counters, drafts, examples, cost and history are kept, and an `error` state re-enters `prior_state`.

### Exit codes

`pipeline.EXIT_CODES`:

| code | terminal state | meaning |
|--:|---|---|
| 0 | `done` | detection and macro written; `status` is `production` or `experimental` |
| 1 | `error` | exception or cost cap; resumable with `--resume` |
| 2 | `infeasible` | no inventory sourcetype matched the idea's `log_sources`; see `runs/<id>/coverage.md` |
| 3 | `failed_noisy` | tune and remake budget spent, or tuning stalled on an unchanged SPL |
| 4 | `failed_review` | review budget spent with a high or critical finding left |

A `--model` value that is not `STEP=MODEL` with a known step, or a `--window` that does not match `-<n>[smhdw][@unit]`, is an argparse error (exit 2 from argparse, before the pipeline starts). Any other exception before the pipeline starts (an unreadable idea file, a missing `SPLUNK_TOKEN` for `--splunk real`, a failed inventory fetch) exits 1 with `error: <message>` on stderr; `ideas`, `inventory` and `publish` do the same.

## `dea publish <paths...>`

Detection YAML to scheduled saved search ([detection-format.md](detection-format.md)).

```sh
uv run dea publish detections/office_app_spawns_encoded_powershell.yml --dry-run
uv run dea publish detections/ --splunk real
uv run dea publish detections/ --splunk real --es
```

| flag | default | effect |
|---|---|---|
| `paths` | required, one or more | detection files or directories (every `*.yml` directly inside a directory) |
| `--splunk` | automatic | `mock` or `real`; ignored with `--dry-run`, which never connects |
| `--es` | off | add Enterprise Security notable, correlation-search and risk keys |
| `--dry-run` | off | print the macro stanza and the saved-search properties instead of publishing |

For each file: validate as `Detection`; find the trailing `` `<stem>_filter` `` in `search` and load `macros/<stem>_filter.yml` next to the file; publish or print the macro first, then the saved search (create or update, both idempotent). A path that does not exist is skipped with a stderr note. Exit 0, or 1 when any file failed to validate or publish (the others are still processed).

## Splunk selection and environment

`splunk.get(kind)` resolves the adapter: the `--splunk` flag, else `DEA_SPLUNK`, else `real` when `SPLUNK_TOKEN` is set, else `mock`.

| variable | default | purpose |
|---|---|---|
| `SPLUNK_HOST` | required for `real` | management host |
| `SPLUNK_PORT` | `8089` | management port |
| `SPLUNK_TOKEN` | required for `real` | bearer token, sent as `Authorization: Bearer <token>`; its presence also selects `real` |
| `SPLUNK_APP` | `search` | app context for saved searches and macros |
| `SPLUNK_OWNER` | `nobody` | namespace owner |
| `SPLUNK_VERIFY` | `1` | `0` disables TLS certificate verification |
| `DEA_SPLUNK` | automatic | `mock` or `real`; an explicit `--splunk` wins |
| `DEA_FIXTURES` | `tests/fixtures/splunk` | fixture directory of the mock adapter |

Nothing else is read from the environment; in particular there is no model override variable. CI uses repository secrets `SPLUNK_HOST` and `SPLUNK_TOKEN` and the repository variable `DEA_ES` ([.github/workflows/ci.yml](../.github/workflows/ci.yml)).

The mock adapter reads `inventory.json`, `runs.json` (gate results in call order, last entry repeating) and `recall.json` from the fixture directory, appends ingested events to `ingested.jsonl` and published stanzas to `published.conf` there, and never evaluates SPL. See [splunk.md](splunk.md) for the real adapter.
