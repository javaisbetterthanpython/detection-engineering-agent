# Detection format

What `dea run` writes when it reaches `done`, field by field, and where each value comes from. The worked example is run 5's output, [`examples/office_app_spawns_encoded_powershell/detection.yml`](examples/office_app_spawns_encoded_powershell/detection.yml) (run 5 · 2026-11-05 · mock Splunk fixtures · real Claude inference · $1.30). Rendering is `models.Detection.from_run`; [SPEC.md §4.4, §7.5, §7.6](SPEC.md) is the law.

Two files per idea:

```
detections/<stem>.yml                    # models.Detection, legacy-contentctl-shaped YAML
detections/macros/<stem>_filter.yml      # the filter macro the search ends with
```

`stem` = the title lower-cased with every non-alphanumeric run replaced by `_` (`office_app_spawns_encoded_powershell`). `-o/--out` changes `detections/`.

## Fields

Nothing in the YAML is written by a model except the `search` text. Everything else is templated from the idea, derived from the SPL by regex, or looked up in a table.

| field | source |
|---|---|
| `name` | `idea.title` |
| `id` | `idea.id` (the uuid4 `dea ideas` generated) |
| `version` | 1; if `<out>/<stem>.yml` already exists, its `version` + 1 when the `search` differs, unchanged otherwise |
| `date` | the local date at render time |
| `author` | `detection-engineering-agent` |
| `status` | `production` only when no experimental cap was set and the recall gate ran; else `experimental` ([pipeline.md](pipeline.md), terminal semantics) |
| `type` | `idea.type` (`TTP`, `Anomaly`, `Hunting`) |
| `description` | `idea.summary`, a blank line, `Detects: ` + `attack_steps` joined with `; ` |
| `data_source` | `SOURCETYPE_META` label of every matched source whose sourcetype or index appears in the search; fallback: all matched sources. Known limit: run 5's search names only the Sysmon sourcetype but both sources share `index=wineventlog`, so both labels are listed |
| `search` | the final draft's SPL, whitespace-normalised, with `` \| `<stem>_filter` `` appended |
| `how_to_implement` | one `Ingest <product> as sourcetype <st> into index <idx>.` sentence per matched source, then `Fields used: <fields_used>.` and the macro hint |
| `known_false_positives` | `idea.false_positive_notes` or `None identified.`, plus `Review findings: <detail> (<severity>); ...` for `false_positive` findings of the last review round |
| `references` | `[idea.source_url]` when set |
| `drilldown_searches` | omitted for `Hunting`; otherwise contentctl's canonical pair for the first risk field `k`: `View the detection results for $k$` and `View risk events for the last 7 days for $k$` |
| `rba.risk_objects` | one per group field that maps to a type: `user` for `user`, `src_user`, `username`, `user_name`, `account_name`, `useridentity.arn`; `system` for `computer`, `host`, `dest`, `src`, `dvc`, `computername`, `hostname`, `src_ip`, `dest_ip` (case-insensitive); fallback: the first group field as `other`. Score = `{"low": 25, "medium": 50, "high": 70, "critical": 90}[idea.severity]` |
| `rba.threat_objects` | group fields that map in `THREAT_TYPES`: `CommandLine`/`process_command_line` → `command`; `Image`/`process_name`/`new_process_name` → `process_name`; `ParentImage`/`parent_process_name`/`creator_process_name` → `parent_process_name`; `dest_ip`/`DestinationIp` → `ip_address`; `url`; `file_name`/`TargetFilename` → `file_name` |
| `rba.message` | `<title> on $<system field>$ by $<user field>$`, whichever exist |
| `tags.analytic_story` | `[idea.title]` |
| `tags.asset_type`, `tags.security_domain` | from the first matched source's `SOURCETYPE_META` row |
| `tags.mitre_attack_id` | `idea.mitre_attack_id` |
| `tags.product` | `Splunk Enterprise`, `Splunk Enterprise Security`, `Splunk Cloud` |
| `tags.throttling` | `{fields: <risk object fields>, period: 86400s}`; omitted for `Hunting` |
| `tests` | only when `idea.attack_data_url` is set: one `True Positive Test` of `test_type: unit` pointing at it |

Group fields are the `by` list of the last `| stats`/`| tstats`, else the columns of the last `| table`. A non-Hunting draft with no group fields cannot be rendered (lint rule 8 rejects it earlier).

`SOURCETYPE_META` (first regex match on the sourcetype name wins, case-insensitive): `sysmon` → Sysmon EventID 1 / Endpoint / endpoint; `powershell` → Powershell Script Block Logging 4104; `wineventlog:security` or `:4688` → Windows Event Log Security 4688; `wineventlog` → Windows Event Log; `linux|syslog|auditd` → Linux Auditd; `cloudtrail` → AWS CloudTrail / AWS Account / threat; `azure|o365|m365|office365` → Azure Monitor Activity / Azure Tenant / threat; whole-word `gcp` or `google` → Google Cloud Platform / GCP Account / threat; `okta|auth0|duo` → Okta / Okta Tenant / identity; `zeek`, whole-word `bro` or `dns`, `pan:`/`pan_`/`panos:`, `firewall`, `netflow`, `suricata` → Zeek / Network / network; `proxy|squid|zscaler|web|iis|nginx|apache` → Nginx Access / Web Server / network; anything else → the sourcetype name / Endpoint / endpoint.

## The filter macro

```yaml
name: office_app_spawns_encoded_powershell_filter
definition: search *
description: Update this macro to limit the output results to filter out false positives.
```

Every rendered search ends with `` | `<stem>_filter` ``. The macro ships as `search *` (a no-op) so an operator can add environment-specific exclusions in Splunk without editing the detection. `dea publish` creates or updates the macro before the saved search, because a saved search whose macro does not exist fails on every scheduled run.

## contentctl

The YAML is shaped like legacy contentctl detection files (enum-valued `security_domain`, the two canonical drilldowns, no `rba` for Hunting, `tests` only with attack data) and is validated by the strict `Detection` model (`extra="forbid"`). There is no contentctl dependency, build or CI job: copy the two files into a `contentctl init` repository's `detections/` and `macros/` directories by hand if you want `contentctl validate`. Run metadata (drafts, gates, findings) never goes into the YAML because contentctl rejects unknown keys; it stays in `runs/<id>/state.json`.

## Saved-search properties (`dea publish`)

There is no `savedsearches.conf` or `macros.conf` file in the repo. `dea publish` sends `Detection.conf_props(es)` as REST arguments to `saved/searches`; `--dry-run` prints them. Run 5's dry run, verbatim ([`examples/office_app_spawns_encoded_powershell/publish.dry-run.conf`](examples/office_app_spawns_encoded_powershell/publish.dry-run.conf)):

```ini
[office_app_spawns_encoded_powershell_filter]
definition = search *

[Office app spawns encoded PowerShell]
search = index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s[-/]e[a-z]*[:\\s]+[\"']?[A-Za-z0-9+/=]{20,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image | `office_app_spawns_encoded_powershell_filter`
is_scheduled = 1
cron_schedule = */15 * * * *
schedule_window = auto
allow_skew = 100%
dispatch.earliest_time = -25m@m
dispatch.latest_time = -5m@m
description = A malicious Word macro launches powershell.exe with -EncodedCommand to fetch a second stage.

Detects: winword.exe or excel.exe or outlook.exe spawns powershell.exe; powershell.exe command line contains -enc or -EncodedCommand followed by base64
alert_type = number of events
alert_comparator = greater than
alert_threshold = 0
alert.severity = 4
alert.track = 1
alert.digest_mode = 0
alert.suppress = 1
alert.suppress.fields = Computer,User
alert.suppress.period = 86400s
```

- The schedule is fixed: every 15 minutes over `-25m@m` to `-5m@m`, a 20-minute window with 5 minutes of overlap and 5 minutes of indexing-lag tolerance. It is the same 20-minute span the noise gate buckets by.
- `alert.severity` is `{"low": 2, "medium": 3, "high": 4, "critical": 5}` of the detection's severity, which `publish` recovers from the highest `rba.risk_objects[].score` (25 → low, 50 → medium, 70 → high, 90 → critical; `medium` when there is no `rba`).
- `alert.suppress*` come from `tags.throttling` and are omitted for Hunting; `alert.suppress.fields` is the risk-typed subset of the SPL's `by` fields (`USER_FIELDS`/`SYSTEM_FIELDS`), or the first `by` field when none is.
- `--es` adds `action.notable = 1` with `rule_title`, `rule_description`, `security_domain` and `severity` params, `action.correlationsearch.enabled = 1`, `action.correlationsearch.label`, and, when `rba` exists, `action.risk = 1`, `action.risk.param._risk_message`, `action.risk.param._risk_score = 0` and `action.risk.param._risk` as a JSON list of the risk and threat objects.
