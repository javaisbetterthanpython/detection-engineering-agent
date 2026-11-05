# Real Splunk adapter

`splunk.RealSplunk` in `src/detection_engineering_agent/splunk.py`, built on `splunk-sdk==3.0.1`. Selected by `--splunk real`, by `DEA_SPLUNK=real`, or automatically when `SPLUNK_TOKEN` is set. Switching from mock to real is configuration only; no code changes. [SPEC.md §8](SPEC.md) is the law. For a throwaway server to run this against, see [splunk-test-server.md](splunk-test-server.md). Every method in the table below was exercised against Splunk Enterprise 10.6.1.1 on that server: inventory, the gate searches, evasion-event ingest, macro and saved-search creation, and a scheduler run of the published search; the record is in [splunk-test-server.md#record-of-real-runs](splunk-test-server.md#record-of-real-runs).

## Connection

```sh
export SPLUNK_HOST=splunk.example.org
export SPLUNK_TOKEN='...'            # bearer token
export SPLUNK_VERIFY=1               # 0 only against a test server with a self-signed certificate
uv run dea inventory --splunk real --refresh
```

`RealSplunk.from_env()` refuses to start without `SPLUNK_HOST` and `SPLUNK_TOKEN` and connects with `splunklib.client.connect(scheme="https", splunkToken=..., autologin=True, app=SPLUNK_APP, owner=SPLUNK_OWNER)` through a handler with a 900-second request timeout (blocking searches hold the response until they finish). The full variable table is in [cli.md](cli.md).

## What it does on Splunk

| method | used by | SDK calls | REST behind them |
|---|---|---|---|
| `inventory` | `dea inventory`, `dea run` (cache miss or `--refresh`) | lists indexes with `totalEventCount > 0` (non-`_` names); per index `\| tstats count where index=<idx> by sourcetype` over `--window`; per sourcetype `search index=<idx> sourcetype="<st>" \| head 2000 \| dedup 100 EventCode keepempty=true \| fieldsummary maxvals=3 \| fields field count values` and `search ... \| head 1 \| fields _raw`; macro names from `confs["macros"]` (argcount suffix stripped) | `GET data/indexes`, `POST search/jobs` (oneshot), `GET configs/conf-macros` |
| `run` | the noise and recall gates | `jobs.create(spl, exec_mode="blocking", earliest_time, latest_time)`; reads `resultCount`, `scanCount`, up to 200 result rows and any `ERROR` messages; always `job.cancel()`; a job that failed at dispatch (`messages.fatal`/`messages.error` on the job entry, e.g. a bad regex in `match()`; Splunk 10 still answers 201 and only `results()` would 400) or an HTTP 400 from `jobs.create` becomes `Run(count=None, errors=[...])` | `POST search/jobs`, `GET search/jobs/{sid}/results`, `DELETE search/jobs/{sid}` |
| `ingest` | `do_match` (idea `attack_examples`), `do_refine` (evasion events) | `indexes[attack_index]`, created with `indexes.create()` when missing; `index.submit(raw, sourcetype=..., host="dea-<run_id>-<n>")` per event | `POST receivers/simple` |
| `publish_macro` | `dea publish` | `macros[name].update(definition=...)` or `macros.create(name, definition)` | `POST configs/conf-macros[/name]` in `SPLUNK_OWNER`/`SPLUNK_APP` |
| `publish` | `dea publish` | `saved_searches[name].update(search=..., **props).refresh()` or `saved_searches.create(name, search, **props)` | `POST saved/searches[/name]` in `SPLUNK_OWNER`/`SPLUNK_APP` |

Inventory field filtering: keep fields whose `fieldsummary` count is at least 5 percent of the largest count, drop internal fields (`_*`, `date_*`, `tag*`, `punct`, `linecount`, `splunk_server`, `timestamp`, `eventtype`), keep the 60 highest-count fields, and for each keep up to 3 values truncated to 80 characters. The raw sample is one `_raw` truncated to 600 characters. Sourcetypes are capped at `--max-sourcetypes` (200), highest count first. An inventory of N sourcetypes costs roughly `2 + indexes + 2N` requests, so `dea run` reuses `inventory.json` for 24 hours.

## Token and permissions

The token is used for everything the run does, so scope it to what the run needs:

- search over the indexes you want detections for (the inventory reads every non-internal index with events);
- read and, on first use, create `--attack-index` (default `dea_attack`) and submit events to it;
- write macros and saved searches in `SPLUNK_APP` as `SPLUNK_OWNER` (only `dea publish` needs this; `dea run` does not).

`dea run` executes model-written SPL under this token. Lint bans `head`, `delete`, `collect`, `outputlookup`, `sendemail`, `script`, `run`, `map`, `dump`, `rest`, `dbxquery` and `index=*` before anything is sent, and the gate search is always `search ...` or `| tstats ...`, but the token's permissions are the real boundary. Use a scratch attack index: evasion events are attacker-shaped events written by a model.

`inventory.json` holds field values and one raw event per sourcetype from your environment; `runs/<id>/state.json` holds sample rows and the ingested events. Both are git-ignored. Do not commit them from a real environment.

## Mock adapter, for contrast

`MockSplunk` (`--splunk mock`, fixture directory `DEA_FIXTURES`, default `tests/fixtures/splunk`) returns `inventory.json` as is, serves `runs.json` entries in call order for gate runs and `recall.json` entries for recall runs (last entry repeating), appends to `ingested.jsonl` and `published.conf`, and never parses or evaluates SPL. The five `e2e_run*_state.json` runs in [development/runs/](development/runs/) were against the mock, so their hit counts and recall results are scripted; their SPL, findings, evasion events and costs are real. The three `droplet_*_state.json` runs there are `splunk_kind: real` (see [splunk-test-server.md#record-of-real-runs](splunk-test-server.md#record-of-real-runs)).
