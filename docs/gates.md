# Gates

What `do_test` in `pipeline.py` and `lint` in `spl.py` do to every draft. All of it is plain code; the tuner only ever sees the `problems` list this page ends with. [SPEC.md §5.4, §5.5, §7.3, §7.4](SPEC.md) is the law.

## Order of work in `do_test`

1. `spl.lint(draft.spl, inventory, idea.stem, matched sourcetypes)`. Errors stop here: no Splunk call, `run.count = None`.
2. Noise run: `gate_spl = runnable(bucketed(spl, "20m")) + " | sort 0 - count"` over `--window` (default `-7d`).
3. Recall run, once per ingested example: `rewrite_index(runnable(spl), attack_index, host=example.host)` over all time (`earliest="0"`).
4. Rate, top values, high-cardinality check, sample rows, warnings, `problems`, `gates["ok"]`.

## Lint

Rules as `spl.lint` applies them today. Quoted strings are blanked before rules 1, 2 and 5 read the text, so a quoted `latest=` is not a time modifier. Errors block the gate; warnings are feedback only.

| # | error | text the tuner sees |
|--:|---|---|
| 1 | `earliest=`, `latest=`, `_index_earliest`, `_index_latest` anywhere | `time modifiers (earliest/latest/_index_*) are not allowed; the schedule sets the window` |
| 2 | a banned command: `\| head`, `delete`, `collect`, `outputlookup`, `sendemail`, `script`, `run`, `map`, `dump`, `rest`, `dbxquery` | `banned command '\| <cmd>'` |
| 3 | no `index=` or `index IN (...)` term and the search does not start with a macro; or `index=*` | `no index= / index IN term (or a leading macro)`, `index=* is not allowed` |
| 4 | an index or sourcetype value not in the inventory | `unknown index 'x'`, `unknown sourcetype 'x'` |
| 5 | a `` `macro` `` not in `inventory.macros` and not `<stem>_filter` | ``unknown macro '`x`'`` |
| 6 | a referenced field that is neither derived in the search (`eval`, `as`, rex capture, `OUTPUT`) nor in the inventory's fields for the sourcetypes the search names (fallback: all matched sources) | `unknown field 'ParentCommandline' (did you mean 'ParentCommandLine'?)` or `unknown field 'OriginalFileName' (not in available_fields)`; only a search using `\| tstats` or `datamodel=` gets the warning `unverified field 'x'` instead |
| 7 | a bare term starting with `*` in the base search, or `_raw="*` | `bare leading-wildcard term scans every event; anchor it to a field` |
| 8 | no `\| stats ... by`, `\| tstats ... by` or `\| table` segment | `no group fields: end with \| stats count ... by <fields> or \| table <fields>` |

Warnings: `search longer than 4000 chars`; `schedule: <construct> cannot complete inside the 20-minute dispatch window` for `| transaction`, `| streamstats`, `eval` with `earliest()`/`latest()`, or a `span=` over 20 minutes.

Rule 6 reads field names from: the left side of comparisons (`F=`, `F!=`, `F<`, ...), `F IN (...)`, `by` lists, stats function arguments (`values(F)`), the first argument of eval/where functions (`match(F, ...)`, `lower(F)`), `rex field=F`, the columns of `| table` and `| fields`, and the field list of `| fillnull`. Builtins (`index`, `sourcetype`, `source`, `host`, `_time`, `_raw`, `count`, `firstTime`, `lastTime`), SPL keywords and command option words (`field`, `value`, `span`, ...) are skipped.

Why rule 6 is an error and not a warning: the inventory's field list is sampled per `EventCode` (`| head 2000 | dedup 100 EventCode keepempty=true | fieldsummary maxvals=3`, 5 percent floor, top 60), so a field absent from it is absent or not extracted in that environment. Run 1 ([development/e2e-findings.md](development/e2e-findings.md)) let `refine` follow a reviewer's hint onto `OriginalFileName`, a field the environment lacked, and the last review round was spent flagging it. Known limit: a real field below the 5 percent floor or beyond the 60-field cap is rejected too; the remedy is `dea inventory --refresh` or a richer inventory.

## Schedule-shaped noise measurement

The gate counts what the production schedule would alert on, not raw hits. `spl.bucketed(spl, "20m")` inserts `| bin _time span=20m` before the first `| stats` and prepends `_time` to its `by` list (for `| tstats`, `_time span=20m` goes into its `by` clause). One result row is one (20-minute window, entity tuple) pair, which is one alert of the scheduled search (`*/15 * * * *` over `-25m@m` to `-5m@m`).

Run 5's final draft, before and after (`gates["gate_spl"]` in [development/runs/e2e_run5_state.json](development/runs/e2e_run5_state.json)):

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s[-/]e[a-z]*[:\\s]+[\"']?[A-Za-z0-9+/=]{20,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

```spl
search index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s[-/]e[a-z]*[:\\s]+[\"']?[A-Za-z0-9+/=]{20,}") | bin _time span=20m | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by _time Computer, User, ParentImage, Image | sort 0 - count
```

The rule, as the code computes it:

```
window_seconds = spl.window_seconds(config.window)      # ^-(\d+)([smhdw])(@\w+)?$ ; -7d = 604800
threshold      = idea.max_hits_per_day or {"TTP": 5, "Anomaly": 20, "Hunting": 100}[idea.type]
count          = run.count                              # resultCount; None on lint errors or Splunk ERROR messages
rate_per_day   = None if count is None else count * 86400 / window_seconds
noisy          = count is not None and rate_per_day > threshold
ok             = not lint.errors and not run.errors and recall.ok and count is not None and not noisy
```

| idea `type` | default threshold (alerts per day) |
|---|--:|
| `TTP` | 5 |
| `Anomaly` | 20 |
| `Hunting` | 100 |

`max_hits_per_day` on the idea overrides the default. Zero alerts counts as clean only when the recall gate proves the search still matches the attack: on `count == 0` with no recall examples, `do_test` adds the warning `0 hits in <window>; cannot distinguish quiet from broken` and sets `status_cap = "experimental"`. `scan_count > --max-scan` (default 50,000,000) adds a `performance:` warning and never blocks.

Run 5 numbers (mock Splunk: the hit counts come from `tests/fixtures/splunk/runs.json`, consumed in call order; the SPL text is real model output):

| draft | gate count in `-7d` | rate | threshold | result |
|--:|--:|--:|--:|---|
| 1 | 412 | 58.9/day | 5/day | `412 alerts in -7d = 58.9/day > 5/day threshold` → tuning |
| 2 | 60 | 8.6/day | 5/day | noisy → tuning |
| 3 | 2 | 0.29/day | 5/day | clean → review |
| 4 | 1 | 0.14/day | 5/day | clean → review |
| 5 | 1 | 0.14/day | 5/day | clean → review → approved |

## Recall gate

Runs whenever `self.examples` is non-empty. Examples come from two places:

- `do_match`: every `idea.attack_examples[i]` is ingested once into `--attack-index` (default `dea_attack`) under host `dea-<run_id>-<i>`, with the sourcetype of the first matched source whose name contains the example's `keyword` (fallback: the first matched source). An idea with no `attack_examples` sets `status_cap = "experimental"` here.
- `do_refine`: every evasion event of every review round so far is ingested the same way (events already ingested are skipped, so `--resume` does not double-ingest). Evasion events are executed, not trusted: the refined draft must match each one or it is not clean.

In `do_test`, after lint passes, each example is searched for with the un-bucketed search, its `index=` term rewritten to `index=<attack_index> host="<example host>"`, over all time (Splunk parses the event's own timestamp, which is usually old). `recall = {"ran": bool(counts), "counts": [...], "ok": all(c >= 1 for c in counts)}`. The per-run host prefix means stale events from earlier runs never satisfy a current example, so the attack index is never cleaned.

Two guards around it:

- A search with no `index=` term (a leading macro) cannot be scoped to the attack index, so recall is marked failed with `recall: search has no index= term, so the attack index cannot be substituted; start with index=<idx> sourcetype=...` instead of running an all-time production search.
- Field guard (`pipeline.event_fields` / `strip_fields`): for XML events, every `<Data Name='X'>...</Data>` element whose name is in neither the inventory's fields for that sourcetype nor the inventory's raw sample is removed before ingest and in the payload sent to `refine`. A reviewer can write a field the real data lacks into an event (run 1: `OriginalFileName`); without the guard, recall would pass on data production never carries. `review_log` keeps the reviewer's original. Non-XML events are not checked.

The mock adapter never evaluates SPL: `recall.json` is `[1]` and the last entry repeats, so every example "hits". Run 5's `recall.counts == [1, 1, 1, 1, 1, 1]` for its six ingested evasion events says only that the gate ran six times. Only a real Splunk makes recall mean anything.

## `problems`: what the tuner sees

Built in this order, then sent as the `problems` payload key of the `tune` call:

1. `lint: <error>` for each lint error, then `splunk: <error>` for each Splunk error (`run.errors`: a search Splunk rejects at dispatch, such as a bad regex in `match()`, or an ERROR message in the results).
2. `recall: examples 2,3 produced 0 hits (every example must hit)` (or the no-index line above) when recall failed, then on a real Splunk one `recall: example 2 lacks ProcessGuid, so `stats by` drops it; group only by fields it carries` per 0-hit example whose event (`| head 1 | fields host <group fields>`) omits a group field.
3. `<count> alerts in <window> = <rate:.1f>/day > <threshold>/day threshold` when noisy.
4. `high-cardinality group fields: CommandLine (198 distinct / 200 rows)` for group fields with more than 80 percent distinct values, only when at least 10 rows were fetched.
5. `top <field> values: v1 (n1), v2 (n2), ...` per group field with at most 80 percent distinct values, weighted by each row's `count`.
6. `warning: ...` and `performance: ...` lines.

Only lines 1 to 3 can be a draft's `reason` in `failed_attempts`; cardinality, top-value and warning lines never are.

`gates` also carries `sample_rows` (at most 5 rows of the gate search projected to the group fields plus `count`), `top_values`, `rate_per_day`, `threshold`, `window_seconds`, `recall` and `lint`, all of which `review` later reads.
