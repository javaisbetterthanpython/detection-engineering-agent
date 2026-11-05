# Detection Engineering Agent — Final Implementation Spec

Repo: the repo root (uv project, package `detection_engineering_agent`, console script `dea`).
This document is the single source of truth. Every open question from the design round is decided here; there is no TBD. Implementers build the items in §12 from this document alone.

Conventions used in this spec:
- `X`, `Y`, `Z` = max tune rounds per draft (3), max remakes (1), max adversarial review rounds (2). All overridable by CLI flag.
- "stem" = `re.sub(r"[^a-z0-9]+", "_", idea.title.lower()).strip("_")`.
- "normalised SPL" = output of `spl.normalise()` (§7).
- "the schedule" = `*/15 * * * *` over `dispatch.earliest_time = -25m@m`, `dispatch.latest_time = -5m@m` (a 20-minute window; `prompts.SCHEDULE = {"cron": "*/15 * * * *", "window": "20m"}`).
- Every path below is relative to the repo root unless written absolutely.

---

## 1. Overview

`dea` turns a detection idea (YAML) into a deployable, tuned, adversarially reviewed Splunk detection in detections-as-code form (legacy-contentctl-shaped YAML + filter macro YAML). A second subcommand turns an article (URL / HTML / PDF / text) into one or more idea YAMLs. `dea publish` pushes the YAML to Splunk as a scheduled saved search over REST.

Pipeline for one idea (requirements a–j map to the steps in brackets):

1. Load + validate idea YAML (a).
2. Fetch (or load cached) Splunk inventory: indexes → sourcetypes → common field names with top values, one raw sample per sourcetype, plus the list of macro names (b). Mock adapter now; real adapter is `splunk-sdk` with a bearer token and is selected purely by environment variables.
3. **Deterministically** match the idea's `log_sources` to inventory sourcetypes (keyword substring + field overlap). No match ⇒ terminal `infeasible` with a generated coverage note (c). Attack examples (from the idea, later also from review) are ingested into the scratch index `config.attack_index` for the recall gate.
4. Inference #1 `author` (opus) writes the first SPL from the idea + matched sources (d).
5. Gates, all plain code: regex lint (fields / index / sourcetype / macros / banned commands / schedule-incompatible commands), run a schedule-shaped (time-bucketed) form of the search on Splunk, recall gate (every ingested attack example must hit), noise rate (alerts/day vs threshold), performance warning (scan_count) (e).
6. Noisy or broken ⇒ inference #2 `tune` (sonnet; opus on the last allowed round) with code-generated `problems` (lint errors, rate, top-N offending values, high-cardinality group fields). After X tune rounds, or when the tuner returns an SPL already seen (fixed point) ⇒ remake via `author` with `failed_attempts`. After Y remakes ⇒ terminal `failed_noisy` (f, g).
7. Clean ⇒ inference #3 `review` (opus, adversarial red team) which sees hit rate, sample rows, top values, exclusions and raw samples and returns findings plus concrete evasion *events*. Only-low findings ⇒ render. Otherwise ⇒ inference #4 `refine` (opus); the evasion events are ingested into the attack index and join the recall example set, so the refined SPL goes back through the gates (step 5) and must catch them ⇒ review again. After Z rounds (or identical findings twice) with only low/medium findings ⇒ accept as `experimental`; with a high/critical finding ⇒ terminal `failed_review` (h, i).
8. Render `detections/<stem>.yml` and `detections/macros/<stem>_filter.yml` deterministically; `dea publish` creates/updates the filter macro and then the saved search via REST (CI) (j).

Control flow is one explicit `transitions` state machine driven by a 4-line loop. No model ever chooses the next step: every routing guard is a pure function of code-computed gate results and of the *findings list* (never of a verdict field). Each inference call receives exactly the fields listed in §6 and nothing else — enforced by a key check in `llm.ask`. Happy path = 2 inference calls (author, review); hard maximum = 13 (§5.3).

Decisions carried over from the design panel (winner "minimal", with grafts):
- Source selection is deterministic (no haiku `select_sources` call).
- Metadata (description, known_false_positives, how_to_implement, rba, drilldowns, cron, throttling) is templated from the idea and from the SPL text, never inferred. Authoring calls return only `spl`; group fields and used fields are derived from the SPL by regex.
- Stall guards (fixed-point SPL; identical review findings), `error` terminal with resume, total cost cap, weighted `top_values` feedback, model ladder for tune, recall gate via `index.submit()` that runs whenever attack examples exist, macros in inventory for existence lint, `evasion_events` in review output (executed, not trusted), `scan_count` performance warning, distinct exit codes, schedule-shaped noise measurement.
- Not adopted: metadata inference call, mock SPL evaluator, `x_dea` YAML block, cron-by-severity, Sigma logsource map file, macros/datamodel-aware authoring beyond macro existence lint, a `savedsearches.conf` side file, a contentctl CI job, a `dea status` subcommand, a fixture-replay backend inside `llm.py`.
- Python **3.13** (`splunk-sdk==3.0.1` needs ≥3.13). `.python-version` becomes `3.13`.

---

## 2. Package layout

All paths are relative to the repo root.

```
pyproject.toml                                   # §3; scripts: dea = "detection_engineering_agent.cli:main"
.python-version                                  # "3.13"
.gitignore                                       # runs/, inventory.json, .venv/, __pycache__/, dist/
README.md                                        # short usage (ideas / inventory / run / publish), environment table, CI deploy steps; notes that the YAML is legacy-contentctl-shaped
                                                 # and can be dropped into a `contentctl init` repo by hand; `cat runs/<idea_id>/state.json` for run status
.github/workflows/ci.yml                         # §11.4
src/detection_engineering_agent/
  __init__.py                                    # `__version__ = "0.1.0"` only
  models.py                                      # pydantic contracts (§4) + lookup tables + Detection rendering (from_run / to_yaml / conf_props / macro_yaml)
  prompts.py                                     # SYSTEM[step], INPUTS[step] (allowed payload keys), MODEL[step], EFFORT[step], SCHEDULE; constants only
  llm.py                                         # ask(): `claude -p` subprocess wrapper (the only backend)
  spl.py                                         # normalise, runnable, with_filter, lint, field extraction, group_fields, bucketed, exclusions, window_seconds, top_values, project, rewrite_index
  splunk.py                                      # Run model, Splunk Protocol, MockSplunk, RealSplunk, get()
  pipeline.py                                    # Pipeline (transitions machine), Config, PipelineState, step callbacks, guards, drive(), save/load
  cli.py                                         # argparse: ideas | inventory | run | publish  (article→idea tool lives here)
tests/
  conftest.py                                    # fixtures: fixture_dir, mock_splunk, fake_llm (subprocess.run monkeypatch), tmp run dir, sample idea
  test_models.py                                 # Idea/Inventory/Detection validation, rendering, lookup tables, conf_props keys, schema()
  test_spl.py                                    # lint rules, normalise, field extraction, group_fields, bucketed, exclusions, window_seconds, top_values, rewrite_index
  test_llm.py                                    # argv built exactly, stdin payload, envelope parsing, retry, allowed-keys check
  test_splunk.py                                 # MockSplunk behaviour (runs.json / recall.json); RealSplunk against MagicMock service
  test_pipeline.py                               # machine paths with stubbed do_* callbacks; resume; cost cap; stall; tune ladder; bucketed gate search
  test_cli.py                                    # ideas tool on local HTML (fake llm), --window=-7d parsing, exit codes, publish --dry-run
  test_e2e.py                                    # full offline run idea -> done -> publish (§11.3)
  fixtures/
    idea.yml                                     # office_app_spawns_encoded_powershell (§4.1 example)
    article.html                                 # local article for `dea ideas`
    splunk/inventory.json                        # §4.2 example (2 indexes, 3 sourcetypes, fields+sample, macros)
    splunk/runs.json                             # scripted gate Run results consumed in order (§8.1)
    splunk/recall.json                           # scripted recall counts consumed in order (§8.1)
    llm/ideas.json                               # list of scripted structured outputs per step (consumed in order by conftest.fake_llm)
    llm/author.json
    llm/tune.json
    llm/review.json
    llm/refine.json
    llm/envelope.json                            # a real `claude --output-format json` result envelope (from recon) for test_llm
    llm_noisy/author.json                        # e2e scenario 2: 2 distinct SPLs
    llm_noisy/tune.json                          # e2e scenario 2: 6 SPLs, pairwise distinct and distinct from both author SPLs
detections/                                      # DaC output (committed by users); created by `dea run` when missing
detections/macros/                               # filter macros
runs/<idea_id>/state.json                        # pipeline state (git-ignored); `run_dir` = <runs>/<idea.id> everywhere in this spec
inventory.json                                   # cached inventory (git-ignored)
```

8 source files (one is constants only). No other modules.

---

## 3. Dependencies

`pyproject.toml` (replace the scaffold entirely):

```toml
[project]
name = "detection-engineering-agent"
version = "0.1.0"
description = "Detection engineering agent: detection idea YAML -> tuned, reviewed Splunk detection as code"
readme = "README.md"
requires-python = ">=3.13,<3.14"
dependencies = [
    "pydantic>=2.7,<3",
    "pyyaml>=6,<7",
    "transitions==0.9.3",
    "splunk-sdk==3.0.1",
    "trafilatura==2.3.1",
    "pypdf>=5,<6",
]

[project.scripts]
dea = "detection_engineering_agent.cli:main"

[dependency-groups]
dev = ["pytest>=8,<9"]

[build-system]
requires = ["uv_build>=0.13.4,<0.14.0"]
build-backend = "uv_build"
```

Why each: `pydantic` = every contract, YAML validation, state (de)serialisation, and the JSON schemas passed to `claude --json-schema` (generated, never hand-written); `pyyaml` = idea in / detection out; `transitions` = state machine as one list of dicts, `model.state` is a plain string we persist; `splunk-sdk` = real adapter (bearer token, indexes, jobs, saved searches, index submit, conf-macros); `trafilatura` + `pypdf` = article text. Stdlib covers everything else: `argparse`, `subprocess`, `re`, `json`, `uuid`, `datetime`, `difflib`, `pathlib`, `fnmatch`.

Explicitly NOT used: click/typer, jinja2, requests/httpx, python-statemachine, contentctl (not even as an optional extra), any SPL parser library, newspaper3k, readability-lxml.

Setup: `uv python pin 3.13 && uv sync --group dev`.

---

## 4. Data contracts

All models live in `src/detection_engineering_agent/models.py` (pipeline-only models `Config`, `PipelineState` live in `pipeline.py`), `pydantic.BaseModel` with `model_config = ConfigDict(extra="forbid")` unless noted.

### 4.1 Detection idea YAML — `models.Idea`

```yaml
# ideas/office_app_spawns_encoded_powershell.yml
id: 3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11      # uuid4 string; generated by `dea ideas`, required for `dea run`
title: Office app spawns encoded PowerShell       # str, 1..99 chars (contentctl name limit)
source_url: https://thedfirreport.com/2026/10/30/example/   # str | null
summary: >-                                       # str, 1..600 chars; the only narrative given to inference
  A malicious Word macro launches powershell.exe with -EncodedCommand to fetch a second stage.
attack_steps:                                     # list[str], min 1; concrete log-observable behaviours
  - "winword.exe or excel.exe or outlook.exe spawns powershell.exe"
  - "powershell.exe command line contains -enc or -EncodedCommand followed by base64"
indicators: ["-EncodedCommand", "-enc ", "powershell.exe"]   # list[str], may be empty; literal strings only
mitre_attack_id: [T1059.001, T1566.001]           # list[str], each ^T\d{4}(\.\d{3})?$
type: TTP                                         # TTP | Anomaly | Hunting
severity: high                                    # low | medium | high | critical ; default medium
log_sources:                                      # list[LogSource], min 1; drives deterministic matching (§7.2)
  - product: Windows Sysmon                       # free text, used in how_to_implement
    keywords: [sysmon]                            # list[str] min 1; case-insensitive substrings of sourcetype names
    fields: [EventCode, Image, ParentImage, CommandLine]   # list[str]; expected field names (overlap tiebreak)
  - product: Windows Security
    keywords: [wineventlog, security, "4688"]
    fields: [EventCode, New_Process_Name, Creator_Process_Name, Process_Command_Line]
sourcetypes: []                                   # list[str]; OPTIONAL explicit override: exact inventory sourcetype names
max_hits_per_day: null                            # int | null; overrides type default (§5.4)
false_positive_notes: Admin scripts launched from Office automation in finance.   # str | null
attack_examples: []                               # list[AttackExample]; raw events of the attack; drive the recall gate (§5.5)
#  - keyword: sysmon                              #   picks the matched source whose sourcetype contains this keyword
#    raw: "<Event>...<Data Name='CommandLine'>powershell -enc AAAA</Data>...</Event>"
attack_data_url: null                             # str | null; URL to a replayable log for contentctl `tests:`
```

`Idea.stem` (property) per the convention above. `Idea.load(path) -> Idea` = `yaml.safe_load` + `model_validate`. `Idea.threshold` (property) = `max_hits_per_day or {"TTP": 5, "Anomaly": 20, "Hunting": 100}[type]` — the one resolved noise threshold used by the gate and sent to every authoring call.

### 4.2 Splunk inventory JSON — `models.Inventory`

```json
{
  "fetched_at": "2026-11-04T10:00:00Z",
  "window": "-7d",
  "macros": ["sysmon", "security_content_ctime", "drop_dm_object_name"],
  "indexes": [
    {
      "name": "wineventlog",
      "events": 1834400,
      "sourcetypes": [
        {
          "name": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
          "count": 912000,
          "fields": {
            "EventCode":   ["1", "3", "11"],
            "Image":       ["C:\\Windows\\System32\\svchost.exe", "C:\\Windows\\explorer.exe", "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE"],
            "ParentImage": ["C:\\Windows\\System32\\services.exe", "C:\\Windows\\explorer.exe"],
            "CommandLine": ["C:\\Windows\\system32\\svchost.exe -k netsvcs", "\"C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE\" /n"],
            "User":        ["NT AUTHORITY\\SYSTEM", "CORP\\jdoe"],
            "Computer":    ["WS01.corp.local", "WS02.corp.local"]
          },
          "sample": "<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'>...</Event>"
        }
      ]
    }
  ]
}
```

Rules: `fields` = `{field_name: up to 3 distinct top values, each truncated to 80 chars}` from the field query in §8.2 (`| head 2000 | dedup 100 EventCode keepempty=true | fieldsummary maxvals=3`, so rare EventCodes are represented); keep only fields whose fieldsummary `count >= 0.05 * max_count` (`max_count` = the largest `count` in the result, taken before dropping internal fields), then drop internal fields (`^_`, `date_*`, `punct`, `linecount`, `splunk_server`, `timestamp`, `eventtype`, `tag*`), then cap at the 60 highest-count fields; `sample` = one `_raw` string truncated to 600 chars (`null` when none); sourcetypes with `count == 0` dropped; at most `max_sourcetypes` (200) per inventory, highest count first. Helper methods: `Inventory.sourcetype_names() -> set[str]`, `Inventory.index_names() -> set[str]`, `Inventory.fields_for(sourcetype) -> dict[str, list[str]]`, `Inventory.sample_for(sourcetype) -> str | None`, `Inventory.find(index, sourcetype) -> Sourcetype`.

### 4.3 Pipeline state JSON — `runs/<idea_id>/state.json`

Everything the pipeline persists is one pydantic model, `pipeline.PipelineState`, and `STATE_FIELDS = tuple(PipelineState.model_fields)` (an explicit model, never `vars()`, because `transitions` injects trigger methods). `Source`, `Example`, `Draft`, `ReviewRound` live in `models.py`; `Config` and `PipelineState` in `pipeline.py`:

```python
class Source(BaseModel):      index: str; sourcetype: str; score: int; data_source: str; asset_type: str; security_domain: str
class Example(BaseModel):     sourcetype: str; raw: str; host: str                      # one ingested attack/evasion event
class Draft(BaseModel):       n: int; origin: Literal["author","tune","refine"]; spl: str
                              group_fields: list[str]; fields_used: list[str]            # both derived from spl by spl.group_fields / spl.referenced_fields
class ReviewRound(BaseModel): round: int; draft: int; findings: list[Finding]; evasion_events: list[EvasionEvent]
class Config(BaseModel):      max_tunes: int = 3; max_remakes: int = 1; max_reviews: int = 2; max_cost_usd: float = 5.0
                              window: str = "-7d"; attack_index: str = "dea_attack"; out_dir: str = "detections"
                              max_scan_count: int = 50_000_000; models: dict[str, str] = {}; verbose: bool = False
class PipelineState(BaseModel):
    state: str; prior_state: str | None = None; error: str | None = None
    idea_path: str; splunk_kind: str; run_id: str; config: Config
    tunes: int = 0; remakes: int = 0; reviews: int = 0; cost_usd: float = 0.0; status_cap: str | None = None
    sources: list[Source] = []; examples: list[Example] = []; drafts: list[Draft] = []
    gates: dict = {}; review_log: list[ReviewRound] = []; failed_attempts: list[dict] = []
    history: list[dict] = []; outputs: list[str] = []
```

`Pipeline.save()` = `PipelineState(**{k: getattr(self, k) for k in STATE_FIELDS}).model_dump_json(indent=2)` (validates on every save). `Pipeline.load()` = `PipelineState.model_validate_json(...)` then `setattr` for every field except `config` (§5.7), so list elements come back as `Draft`/`Source`/`Example`/`ReviewRound` objects, never dicts.

```json
{
  "state": "tuning",
  "prior_state": null,
  "error": null,
  "idea_path": "ideas/office_app_spawns_encoded_powershell.yml",
  "splunk_kind": "mock",
  "run_id": "9f1c2a7b",
  "config": {"max_tunes": 3, "max_remakes": 1, "max_reviews": 2, "max_cost_usd": 5.0, "window": "-7d",
             "attack_index": "dea_attack", "out_dir": "detections", "max_scan_count": 50000000, "models": {}, "verbose": false},
  "tunes": 1, "remakes": 0, "reviews": 0, "cost_usd": 0.47,
  "status_cap": null,
  "sources": [
    {"index": "wineventlog", "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "score": 14,
     "data_source": "Sysmon EventID 1", "asset_type": "Endpoint", "security_domain": "endpoint"}
  ],
  "examples": [
    {"sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational", "raw": "<Event>...</Event>", "host": "dea-9f1c2a7b-0"}
  ],
  "drafts": [
    {"n": 1, "origin": "author", "spl": "index=wineventlog sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 Image=\"*\\\\powershell.exe\" | stats count by Computer User ParentImage Image CommandLine",
     "group_fields": ["Computer", "User", "ParentImage", "Image", "CommandLine"],
     "fields_used": ["CommandLine", "Computer", "EventCode", "Image", "ParentImage", "User"]}
  ],
  "gates": {
    "draft": 1,
    "lint": {"errors": [], "warnings": []},
    "gate_spl": "search index=wineventlog ... EventCode=1 Image=\"*\\\\powershell.exe\" | bin _time span=20m | stats count by _time Computer User ParentImage Image CommandLine | sort 0 - count",
    "run": {"count": 412, "scan_count": 912000, "errors": []},
    "recall": {"ran": true, "counts": [1], "ok": true},
    "rate_per_day": 58.86, "threshold": 5, "window_seconds": 604800,
    "top_values": {"ParentImage": [["C:\\Windows\\explorer.exe", 380], ["C:\\Windows\\System32\\services.exe", 30]]},
    "sample_rows": [{"Computer": "WS01", "User": "CORP\\jdoe", "ParentImage": "C:\\Windows\\explorer.exe", "Image": "C:\\Windows\\...\\powershell.exe", "CommandLine": "powershell.exe -File login.ps1", "count": "3"}],
    "problems": ["412 alerts in 7d = 58.9/day > 5/day threshold", "high-cardinality group fields: CommandLine (198 distinct / 200 rows)", "top ParentImage values: C:\\Windows\\explorer.exe (380), C:\\Windows\\System32\\services.exe (30)"],
    "ok": false
  },
  "review_log": [],
  "failed_attempts": [],
  "history": [
    {"ts": "2026-11-04T10:01:02Z", "step": "match", "model": null, "cost_usd": 0.0},
    {"ts": "2026-11-04T10:01:40Z", "step": "author", "model": "claude-opus-5-5", "cost_usd": 0.31},
    {"ts": "2026-11-04T10:01:41Z", "step": "test", "model": null, "cost_usd": 0.0}
  ],
  "outputs": []
}
```

`gates` always describes the latest draft (`drafts[-1]`). `review_log` entries are `ReviewRound`s: `{"round": 1, "draft": 3, "findings": [...], "evasion_events": [...]}`. `failed_attempts`: `[{"spl": "...", "reason": "412 alerts in 7d = 58.9/day > 5/day threshold"}, ...]` (one entry per draft of the abandoned line, §5.3). `outputs`: paths written by render. `run_id` = `uuid.uuid4().hex[:8]`, generated once per fresh run and used as the host prefix for ingested examples.

### 4.4 Final detection YAML — `models.Detection` (strict superset of legacy contentctl 5.6.3 fields; `extra="forbid"`)

```yaml
# detections/office_app_spawns_encoded_powershell.yml
name: Office app spawns encoded PowerShell
id: 3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11        # == idea.id
version: 1                                       # existing file with same name: existing.version + 1 if search differs, else unchanged
date: '2026-11-04'
author: detection-engineering-agent
status: experimental                             # production | experimental  (§5.6)
type: TTP
description: >-
  A malicious Word macro launches powershell.exe with -EncodedCommand to fetch a second stage.

  Detects: winword.exe or excel.exe or outlook.exe spawns powershell.exe; powershell.exe command line contains -enc or -EncodedCommand followed by base64
data_source: [Sysmon EventID 1]                  # from SOURCETYPE_META for each matched source actually referenced by the search
search: 'index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*\\WINWORD.EXE" OR ParentImage="*\\EXCEL.EXE" OR ParentImage="*\\OUTLOOK.EXE") Image="*\\powershell.exe" (CommandLine="* -enc*" OR CommandLine="*-EncodedCommand*") | stats count min(_time) as firstTime max(_time) as lastTime by Computer User ParentImage Image CommandLine | `office_app_spawns_encoded_powershell_filter`'
how_to_implement: >-
  Ingest Windows Sysmon as sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational into index wineventlog.
  Fields used: CommandLine, Computer, EventCode, Image, ParentImage, User. Adjust the index/sourcetype or the
  office_app_spawns_encoded_powershell_filter macro for your environment.
known_false_positives: >-
  Admin scripts launched from Office automation in finance. Review findings: Signed vendor add-ins that invoke
  PowerShell with encoded commands (medium).
references: ["https://thedfirreport.com/2026/10/30/example/"]
drilldown_searches:                              # omitted for type Hunting
  - name: View the detection results for $Computer$
    search: '%original_detection_search% | search Computer="$Computer$"'
    earliest_offset: $info_min_time$
    latest_offset: $info_max_time$
  - name: View risk events for the last 7 days for $Computer$
    search: '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$Computer$") starthoursago=168 | stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" by normalized_risk_object'
    earliest_offset: $info_min_time$
    latest_offset: $info_max_time$
rba:                                             # omitted for type Hunting
  message: Office app spawns encoded PowerShell on $Computer$ by $User$
  risk_objects:                                  # in group_fields order
    - {field: Computer, type: system, score: 70}
    - {field: User, type: user, score: 70}
  threat_objects:
    - {field: CommandLine, type: command}
    - {field: Image, type: process_name}
    - {field: ParentImage, type: parent_process_name}
tags:
  analytic_story: [Office app spawns encoded PowerShell]
  asset_type: Endpoint
  mitre_attack_id: [T1059.001, T1566.001]
  product: [Splunk Enterprise, Splunk Enterprise Security, Splunk Cloud]
  security_domain: endpoint                      # Literal endpoint|network|threat|identity|access|audit (contentctl enum)
  throttling: {fields: [Computer, User], period: 86400s}   # omitted for type Hunting
tests:                                           # present only when attack_data_url is set; else omitted
  - name: True Positive Test
    attack_data:
      - data: https://example.org/attack_data/office_encoded_ps.log
        source: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
        sourcetype: XmlWinEventLog:Microsoft-Windows-Sysmon/Operational
    test_type: unit
```

Sub-model typing: `ThreatObject.type: Literal["command","process_name","parent_process_name","ip_address","url","file_name"]`, `RiskObject.type: Literal["user","system","other"]`, `Tags.security_domain: Literal["endpoint","network","threat","identity","access","audit"]`.

Side file, rendered deterministically alongside — `detections/macros/office_app_spawns_encoded_powershell_filter.yml`:
```yaml
name: office_app_spawns_encoded_powershell_filter
definition: search *
description: Update this macro to limit the output results to filter out false positives.
```

There is no `.conf` side file. The saved-search properties exist only as REST arguments, `Detection.conf_props(es)` (§7.5), used by `dea publish`; `dea publish --dry-run` prints them as `[name]`, `search = ...`, then `key = value` per prop. Run metadata never goes into the YAML (contentctl models reject unknown keys); it stays in `state.json`.

### 4.5 Inference output models (in `models.py`)

```python
class IdeaDraft(BaseModel):            # one element of IdeasOut.ideas; Idea minus id/source_url/sourcetypes/max_hits_per_day/attack_data_url
    title: str = Field(max_length=99); summary: str = Field(max_length=600)
    attack_steps: list[str]; indicators: list[str]; mitre_attack_id: list[str]
    type: Literal["TTP","Anomaly","Hunting"]; severity: Literal["low","medium","high","critical"]
    log_sources: list[LogSource]; false_positive_notes: str | None = None; attack_examples: list[AttackExample] = []
class IdeasOut(BaseModel):    ideas: list[IdeaDraft]
class SplOut(BaseModel):      spl: str                                   # output of author, tune and refine
class Finding(BaseModel):     category: Literal["evasion","false_positive","logic","performance","brittleness"]
                              severity: Literal["low","medium","high","critical"]; detail: str; fix_hint: str
class EvasionEvent(BaseModel): sourcetype: str; raw: str; note: str     # a real sample edited into the evasion; ingested and must hit
class ReviewOut(BaseModel):   findings: list[Finding]; evasion_events: list[EvasionEvent]
```
`models.schema(Model) = Model.model_json_schema()` — nothing else. Recon (2026-11-04, `claude` 2.1.198, haiku, `--json-schema` with `$defs` + `$ref`, 3/3 runs): the CLI accepts nested `$ref` schemas and returns `structured_output`; no inliner is needed. There is no `verdict` field anywhere: routing after review is computed from `findings` severities (§5.3). `max_length` on `IdeaDraft` is emitted as `maxLength` in the schema, so the model is bound to the same limits as `Idea`.

---

## 5. State machine

Library: `transitions==0.9.3`, `Machine(model=self, states=STATES, transitions=TRANSITIONS, initial=self.state, auto_transitions=False, ignore_invalid_triggers=False)` built inside `Pipeline.__init__`. The state string is `self.state`. `pipeline.py` owns everything in this section.

### 5.1 States

| state | meaning | step run from it (trigger) |
|---|---|---|
| `start` | idea loaded, inventory loaded | `match` |
| `matched` | candidate sources chosen | `author` |
| `drafted` | a draft SPL exists (from author, tune or refine) | `test` |
| `tuning` | gates failed, budget left | `tune` |
| `clean` | gates passed | `review` |
| `revising` | review found fixable issues | `refine` |
| `approved` | review passed or residual acceptable | `render` |
| `done` | **terminal**: files written | — |
| `infeasible` | **terminal**: no matching sourcetype | — |
| `failed_noisy` | **terminal**: tune/remake budget exhausted | — |
| `failed_review` | **terminal**: review budget exhausted with high/critical finding | — |
| `error` | **terminal (resumable)**: exception or cost cap; `prior_state` holds where to resume | — |

`TERMINAL = {"done","infeasible","failed_noisy","failed_review","error"}`.

### 5.2 Transitions

`prepare` is attached **only to the first listed transition of each trigger** (transitions evaluates them in order and runs `prepare` before `conditions`; later transitions of the same trigger carry no `prepare`, so each step's work runs exactly once per trigger). If `prepare` raises, the state is unchanged and the driver routes to `error`.

```python
TRANSITIONS = [
 {"trigger":"match",  "source":"start",   "dest":"matched",       "prepare":"do_match",  "conditions":"has_sources"},
 {"trigger":"match",  "source":"start",   "dest":"infeasible",    "after":"write_coverage_note"},

 {"trigger":"author", "source":"matched", "dest":"drafted",       "prepare":"do_author"},

 {"trigger":"test",   "source":"drafted", "dest":"clean",         "prepare":"do_test",   "conditions":"is_clean"},
 {"trigger":"test",   "source":"drafted", "dest":"tuning",        "conditions":"can_tune",   "after":"bump_tune"},
 {"trigger":"test",   "source":"drafted", "dest":"matched",       "conditions":"can_remake", "after":"bump_remake"},
 {"trigger":"test",   "source":"drafted", "dest":"failed_noisy"},

 {"trigger":"tune",   "source":"tuning",  "dest":"drafted",       "prepare":"do_tune"},

 {"trigger":"review", "source":"clean",   "dest":"approved",      "prepare":"do_review", "conditions":"review_pass"},
 {"trigger":"review", "source":"clean",   "dest":"revising",      "conditions":"can_refine", "after":"bump_review"},
 {"trigger":"review", "source":"clean",   "dest":"approved",      "conditions":"residual_acceptable", "after":"cap_experimental"},
 {"trigger":"review", "source":"clean",   "dest":"failed_review"},

 {"trigger":"refine", "source":"revising","dest":"drafted",       "prepare":"do_refine"},

 {"trigger":"render", "source":"approved","dest":"done",          "prepare":"do_render"},

 {"trigger":"fail",   "source":"*",       "dest":"error",         "before":"remember_prior"},
]
NEXT = {"start":"match","matched":"author","drafted":"test","tuning":"tune","clean":"review","revising":"refine","approved":"render"}
```

Driver (the only loop; nothing else decides flow):

```python
def drive(self) -> str:
    while self.state in NEXT:
        try:
            getattr(self, NEXT[self.state])()
        except Exception as e:            # includes CostCapExceeded, subprocess errors, Splunk errors
            self.error = repr(e); self.fail()
        self.save()
    return self.state
```

### 5.3 Guards, counters, callbacks

| name | definition |
|---|---|
| `has_sources` | `len(self.sources) > 0` |
| `is_clean` | `self.gates["ok"]` = lint errors empty **and** run errors empty **and** recall ok **and** `rate_per_day <= threshold` (§5.4) |
| `can_tune` | `self.tunes < config.max_tunes` **and not** `stalled` where `stalled = normalise(drafts[-1].spl) in {normalise(d.spl) for d in drafts[:-1]}` |
| `can_remake` | `self.remakes < config.max_remakes` |
| `review_pass` | `not any(f.severity != "low" for f in last.findings)` (`last = review_log[-1]`); computed in code from the findings list only |
| `can_refine` | `self.reviews < config.max_reviews` **and** `finding_key(last) != finding_key(review_log[-2])` when a previous round exists; `finding_key = sorted((f.category, f.severity) for f in findings)` (free-text `detail` is excluded on purpose: it never matches across rephrasings) |
| `residual_acceptable` | `not any(f.severity in ("high","critical") for f in last.findings)` |
| `bump_tune` | `self.tunes += 1` |
| `bump_remake` | `self.remakes += 1; self.tunes = 0;` append to `failed_attempts` one `{"spl", "reason"}` per draft of the abandoned line (the drafts since the last author call, oldest first, capped at the last 4), `reason` = that draft's noise line (or its first lint/splunk/recall problem when there was no noise line). The gate results per draft are kept in a private `self._line: list[tuple[spl, reason]]` that `do_author` resets and `do_test` appends to (not persisted; on resume the line restarts at the current draft) |
| `bump_review` | `self.reviews += 1` |
| `cap_experimental` | `self.status_cap = "experimental"` |
| `remember_prior` | `self.prior_state = self.state` |
| `write_coverage_note` | writes `run_dir/coverage.md` listing each `log_sources` entry (product, keywords, fields) and the inventory sourcetype names, so a human sees what logs are missing |

There is no `reset_tunes`: a refined draft that comes back noisy spends whatever tune budget is left on its line, then goes to remake / `failed_noisy` like any other draft. This keeps the bound below exact. A refined (or tuned) draft that fails lint — e.g. a field outside `available_fields` (§7.3 rule 6) — takes the same ordinary `drafted → tuning` path: no Splunk run, one `tune` call with the lint line first in `problems` and every review round's evasion notes in `must_keep`, review budget untouched. This is the deterministic lint-of-refine retry: no extra state, no extra call type, and the call bound is unchanged. When the tune budget is already spent the draft goes to remake with the lint line as its `failed_attempts.reason` (review context survives only there; accepted to keep the bound exact).

Defaults: **X = `max_tunes` = 3**, **Y = `max_remakes` = 1**, **Z = `max_reviews` = 2**, `max_cost_usd = 5.0`, `window = "-7d"`, `attack_index = "dea_attack"`, `max_scan_count = 50_000_000`.

Inference-call bound per run: authors `1+Y` = 2, tunes `X·(Y+1)` = 6 (`tunes` is reset only by `bump_remake`), reviews `Z+1` = 3, refines `Z` = 2 → **13 max (+1 per retried call, at most one retry per step)**; happy path **2** (author, review-pass). Every cycle increments a bounded counter or is cut by a stall rule, so the machine terminates.

Tune model ladder: `bump_tune` runs on the `drafted → tuning` transition, so inside `do_tune` `self.tunes` is 1, 2, 3 on rounds 1–3 and the last allowed round is `self.tunes == config.max_tunes`; on exactly that round `do_tune` passes `model=(config.models.get("author") or prompts.MODEL["author"]), effort="high"` to `_ask` (the run's author model, so `--model author=...` follows into the last tune).

### 5.4 Noise threshold rule (deterministic, in `do_test`)

The gate measures what the production schedule would alert on, not raw hits. `spl.bucketed(spl, span="20m")` (§7.3) rewrites the search into its schedule-shaped form: `| bin _time span=20m` before the first `| stats` with `_time` prepended to its `by` list (for `| tstats`, `_time span=20m` is inserted into its `by` clause). One row of that search = one (20-minute window, entity tuple) pair = one alert the scheduled search would have raised.

```
gate_spl       = runnable(bucketed(spl, "20m")) + " | sort 0 - count"      # sort does not change resultCount; the ≤200 fetched rows are the heaviest
window_seconds = spl.window_seconds(config.window)        # regex ^-(\d+)([smhdw])(@\w+)?$ ; s=1 m=60 h=3600 d=86400 w=604800; ValueError otherwise
threshold      = idea.threshold                           # max_hits_per_day or {"TTP": 5, "Anomaly": 20, "Hunting": 100}[type]
count          = run.count                                # resultCount of gate_spl; None when lint errors or Splunk ERROR messages
rate_per_day   = None if count is None else count * 86400 / window_seconds
noisy          = count is not None and rate_per_day > threshold
ok             = not lint.errors and not run.errors and recall.ok and count is not None and not noisy
```
For a search without a `| stats`/`| tstats` segment `bucketed` returns it unchanged and `count` is the raw event count (lint already flags the missing segment as an error, §7.3 rule 8, so this only matters for the lint-error path). Zero alerts is clean *only* when the recall gate proves the search still matches the attack: when `count == 0` and `recall.ran` is false, `do_test` appends `"warning: 0 hits in <window>; cannot distinguish quiet from broken"` to `lint.warnings` (so review sees it) and sets `status_cap = "experimental"`. `scan_count > max_scan_count` adds the warning `"performance: scanned N events in <window>; narrow with index/sourcetype/EventCode or use tstats"` to `lint.warnings` and `problems` — it never blocks.

`problems` (list[str], code-generated, the only feedback the tuner sees) is built in this order: lint errors (`"lint: <msg>"`), Splunk run errors (`"splunk: <msg>"`), recall failure (`"recall: examples 2,3 produced 0 hits (every example must hit)"`, then on real Splunk one `"recall: example 2 lacks ProcessGuid, so `stats by` drops it; group only by fields it carries"` per 0-hit example whose event, probed with `search index=<attack_index> host="<host>" | head 1 | fields host <group fields>`, omits a group field — the real idea run burned 7 tunes rewriting regexes while every draft grouped by a field the article example lacks; the mock never probes), noise line (`"<count> alerts in <window> = <rate:.1f>/day > <threshold>/day threshold"`), high-cardinality line (`"high-cardinality group fields: CommandLine (198 distinct / 200 rows)"` for group fields with > 80 % distinct values over the fetched rows, only when at least 10 rows were fetched — the tuner should stop grouping by them; run 2 showed `Computer (1 distinct / 1 rows)` telling the tuner to drop its only group field), one line per `top_values` field (`"top <field> values: v1 (n1), v2 (n2), ..."`, weighted by each row's `count`), warnings (`"warning: ..."`).

### 5.5 Recall gate (deterministic)

Runs whenever `self.examples` is non-empty. Sources of examples:
- `do_match`: each `idea.attack_examples[i]` becomes `Example(sourcetype, raw, host=f"dea-{run_id}-{i}")` where `sourcetype` = the first matched source whose sourcetype name contains `example.keyword` (case-insensitive; fallback: first matched source) and is ingested once via `splunk.ingest(config.attack_index, sourcetype, [raw], host)`. When `idea.attack_examples` is empty, `status_cap = "experimental"` is set here.
- `do_refine` (before calling the model): each `review_log[-1].evasion_events[j]` becomes `Example(sourcetype, raw, host=f"dea-{run_id}-{len(examples)}")` (sourcetype must be one of `self.sources`; otherwise the first source) and is ingested the same way. Evasion events are therefore executed, not trusted: the refined draft must catch them or it is not clean. The `evasion_events` payload sent to `refine` carries **every round's** events (`review_log[0..-1]`, oldest first, each field-guarded as below; earlier rounds' events are already ingested and are not re-ingested) — exactly the set the recall gate executes. Run 2 (`development/runs/e2e_run2_state.json`): shown only round 2's events, refine followed a round-2 `fix_hint` that silently dropped the `-ec` case round 1 had made an example of; the mock recall gate cannot catch that (§8.1) and the last review round was spent re-reporting it as HIGH → `failed_review`. `findings` stay last-round only: the reviewer receives `prior_findings` and re-reports what is unresolved. **Field guard (code, `pipeline.event_fields`/`strip_fields`):** an evasion event may carry only fields the environment has. For XML events, `event_fields(raw) = {X for <Data Name='X'>}`; every element whose name is in `event_fields(ev.raw) − (set(inventory.fields_for(st)) ∪ event_fields(inventory.sample_for(st)))` is removed (`re.sub` of the `<Data Name='X'>…</Data>` element, DOTALL so a value spanning lines is still removed) before ingest **and** in the `evasion_events` payload sent to `refine`; `review_log` keeps the reviewer's original. Rationale: evasion events are model-authored, so a reviewer can write a field the real data lacks (run 1: `OriginalFileName`) into the event; the TA would extract it from the ingested event and recall would pass on fabricated data while production events never carry it. Non-XML samples have no `Data Name` elements and are not checked. The `note`/`fix_hint` text is untouched (rule 3 of §6.2 tells refine to ignore unlisted fields named there, and lint rule 6 rejects them).

In `do_test`, after lint passes, once per example: `splunk.run(rewrite_index(runnable(spl), config.attack_index, host=ex.host), earliest="0", latest="now").count` (all time, because `index.submit` lets Splunk parse the event's embedded timestamp, which is usually days or months old; the scratch index is tiny so all-time is cheap). `recall = {"ran": true, "counts": [...], "ok": all(c >= 1 for c in counts)}`; failure lists the zero-count example indexes in `problems`. When there are no examples: `recall = {"ran": false, "counts": [], "ok": true}`. The per-run host prefix means stale events from earlier runs never satisfy a current example; no index cleanup is needed.

### 5.6 Terminal semantics and exit codes

| terminal | meaning | `dea run` exit code | final `status` |
|---|---|---|---|
| `done` | all gates passed on the final SPL, review passed or residual ≤ medium, files written | 0 | `production` iff `status_cap is None` **and** `gates["recall"]["ran"]` (i.e. the last review had only low findings, attack examples existed and all hit, and the search never had 0 hits without recall); otherwise `experimental` |
| `infeasible` | no sourcetype matched | 2 | — |
| `failed_noisy` | X tune rounds × (Y+1) drafts exhausted (or stalled) with gates failing | 3 | — |
| `failed_review` | Z refine rounds (or identical findings) with a high/critical finding remaining | 4 | — |
| `error` | exception / cost cap; `--resume` re-enters `prior_state` | 1 | — |

`done` is reached only through `approved`, and `approved` only through `clean` → the final SPL is always the last draft that passed lint + run + recall + noise, and the review that approved it reviewed exactly that draft (refine always routes `drafted → test → clean → review`). `approved` without `status_cap` is only reachable through `review_pass`, so the `status` rule above needs no separate verdict check.

### 5.7 Persistence and resume

`Pipeline.save()` writes `run_dir/state.json` (§4.3) after every trigger in `drive()`; `run_dir = <runs>/<idea.id>` (CLI `--runs`, default `runs/`). `Pipeline.load(run_dir, idea, inventory, splunk, config) -> Pipeline` reads it through `PipelineState.model_validate_json`, sets every field **except `config`** (the `config` passed in from the CLI wins, so `--resume --max-cost 10` raises the cap and `--tunes` etc. apply to the resumed run; the persisted `config` is informational), and if `state == "error"` sets `state = prior_state; error = None; prior_state = None` before building the `Machine(initial=state)`. `dea run --resume` uses `load` when the file exists, else starts fresh. Counters, drafts, examples, cost and history survive resume.

---

## 6. Inference calls

### 6.1 The single helper — `src/detection_engineering_agent/llm.py`

```python
class CostCapExceeded(RuntimeError): ...
class LLMError(RuntimeError): ...

def ask(step: str, payload: dict, out: type[T], model: str | None = None, effort: str | None = None) -> tuple[T, float]:
    """Run one pure-inference call for `step` and return (validated output, cost_usd).
    step   -> key into prompts.SYSTEM / INPUTS / MODEL / EFFORT
    payload-> JSON-serialisable dict; a key outside prompts.INPUTS[step] raises ValueError before any subprocess call
    model/effort default to prompts.MODEL[step] / prompts.EFFORT[step]
    Backend: subprocess `claude` as below. Non-zero exit, subtype != "success", is_error true, missing structured_output
             or pydantic validation error -> retry once with the same argv and input; second failure -> LLMError.
    """
```

Exact subprocess invocation (recon-verified flags; `--bare` is NOT used because the login is OAuth; the payload goes to **stdin**, never argv — Linux caps one argv string at 128 KiB and `ideas` payloads reach 100 k chars):

```python
argv = ["claude", "-p",
        "--model", model, "--effort", effort,
        "--tools", "", "--max-turns", "2",
        "--setting-sources", "", "--no-session-persistence", "--disable-slash-commands",
        "--max-budget-usd", "2.00",
        "--system-prompt", prompts.SYSTEM[step],
        "--output-format", "json",
        "--json-schema", json.dumps(models.schema(out))]
proc = subprocess.run(argv, input=json.dumps(payload, ensure_ascii=False), capture_output=True, text=True, timeout=600)
env  = json.loads(proc.stdout)
obj  = out.model_validate(env["structured_output"]); cost = float(env.get("total_cost_usd", 0.0))
```
`--max-turns 2`, not 1: with `--json-schema` the CLI delivers the structured output through a tool call that counts as a turn; recon showed `--max-turns 1` returning `subtype: "error_max_turns"` with no `structured_output` on some runs and `--max-turns 2` succeeding 3/3. No CLAUDE.md, no tools, no session, no history: the payload JSON on stdin is the entire user turn.

`prompts.py` holds four dicts keyed by step (`ideas, author, tune, review, refine`): `SYSTEM` (text), `INPUTS` (tuple of allowed payload keys), `MODEL`, `EFFORT`, plus the constant `SCHEDULE`. Model precedence, applied in `Pipeline._ask`: explicit argument (the tune ladder) > `config.models[step]` (CLI `--model STEP=MODEL`) > `prompts.MODEL[step]`. There is no environment-variable override. `MODEL = {"ideas": "claude-haiku-5-5", "author": "claude-opus-5-5", "tune": "claude-sonnet-5-5", "review": "claude-opus-5-5", "refine": "claude-opus-5-5"}`, `EFFORT = {"ideas": "medium", "author": "high", "tune": "medium", "review": "high", "refine": "high"}`.

### 6.2 Calls (exhaustive)

Common payload values: `max_hits_per_day` = `idea.threshold` (the resolved number, never null); `schedule` = `prompts.SCHEDULE`; `false_positive_notes` = `idea.false_positive_notes` (null when absent); `available_fields` = `{name: [values]}` merged over `spl.sourcetypes_in(spl)` (fallback: all of `self.sources` when the search names none, e.g. starts with a macro); `samples` = `{sourcetype: inventory.sample_for(sourcetype)}` over the same sourcetypes.

| # | id | purpose | model / effort | exact payload keys (nothing else) | output model | adversarial |
|---|---|---|---|---|---|---|
| 0 | `ideas` | article text → detection ideas (tool `dea ideas`, not in the pipeline) | `claude-haiku-5-5` / medium | `text` (≤ 100 000 chars, head-truncated by code) | `IdeasOut` | no |
| 1 | `author` | first SPL, and remake after tuning fails | `claude-opus-5-5` / high | `summary`, `attack_steps`, `indicators`, `max_hits_per_day`, `false_positive_notes`, `schedule`, `sources` = `[{index, sourcetype, fields: {name: [values]}, sample}]` (when `examples` is non-empty, only sources whose sourcetype an ingested example carries: recall runs every example, so a remake on another sourcetype can never pass it), `failed_attempts` = `[{spl, reason}]` (empty list on first draft) | `SplOut` | no |
| 2 | `tune` | reduce noise / fix lint, Splunk or recall errors | `claude-sonnet-5-5` / medium; **the author model (`--model author=` or `claude-opus-5-5`) / high on the last allowed tune round** | `spl`, `problems` (list[str], §5.4), `attack_steps`, `available_fields`, `sample_rows` (≤5 rows of the gate search projected to `group_fields + ["count"]`), `max_hits_per_day`, `false_positive_notes`, `schedule`, `must_keep` = `[e.note for rnd in review_log for e in rnd.evasion_events]` (every round's, oldest first — exactly what recall executes; empty before any review; **never** finding details: they describe the previous draft's weaknesses and a `false_positive` one reads as "remove this" — run 3, `development/runs/e2e_run3_state.json`: the last tune, shown round 2's low FP detail about the `e`/`en`/`ec` tokens and not round 1's events, dropped `-e`/`-ec` and re-pinned `Image`, and the final review rated both regressions HIGH → `failed_review`) | `SplOut` | no |
| 3 | `review` | adversarial red-team review of a clean SPL | `claude-opus-5-5` / high | `spl`, `attack_steps`, `indicators`, `available_fields`, `samples`, `warnings` (lint warnings incl. performance / zero-hit), `hits_per_day` (`gates["rate_per_day"]`), `sample_rows`, `top_values`, `exclusions` (`spl.exclusions(spl)`), `schedule`, `prior_findings` (`[{category, severity, detail}]` of the previous round, else `[]`) | `ReviewOut` | **yes** |
| 4 | `refine` | apply review findings | `claude-opus-5-5` / high | `spl`, `findings` (all, high/critical first), `evasion_events` (every round's, §5.5), `available_fields`, `max_hits_per_day`, `false_positive_notes`, `schedule` | `SplOut` | no |

The authoring rules are constant text and live in the system prompts (`prompts.RULES`, appended verbatim to `SYSTEM["author"]`, `SYSTEM["tune"]`, `SYSTEM["refine"]`), never in a payload:
```
Rules:
1. Output a single SPL search, no comments, no explanations inside the SPL.
2. Start with a filter on index= and sourcetype=; never index=*.
3. Reference only fields listed in available_fields/sources, or fields you create with eval/rex/rename. That list is exhaustive for this environment: any other field, including one named in a finding, fix_hint or evasion_event, fails lint and the draft is rejected; cover such cases with listed fields.
4. No earliest=/latest= in the search; no head, delete, collect, outputlookup, sendemail, script, run, map, dump.
5. End with | stats count ... by <fields> (or | table) so each row is one alertable entity.
6. Prefer exact field matches and case-insensitive match() over bare leading-wildcard terms.
7. The search runs every 15 minutes over the last 20 minutes (schedule); all events that make up one alert must occur within that window — no transaction, streamstats, first-seen or multi-hour logic.
8. Exclude the benign activity described in false_positive_notes only with a predicate the attacker cannot satisfy while performing the attack (a specific benign program, path or command line); never exclude by user, host, integrity level, a missing keyword or a bare wildcard, and never pin the attack side (image path, parent path, switch spelling) tighter than the attack requires.
9. Inside a double-quoted SPL string, \\ is one backslash and \" is one quote; every other escape reaches the regex unchanged. A literal backslash in a match()/regex/rex pattern is therefore \\\\ (a path ending in \powershell.exe is match(Image, "(?i)\\\\powershell\\.exe$")): "\\powershell" reaches the regex as \p and Splunk rejects the search; "\\WINWORD" reaches it as \W and silently matches nothing. Prefer patterns without backslashes: [.] for a literal dot, [\\\\/] for a path separator, or a search-term wildcard such as Image="*\\powershell.exe".
```

System prompts (`prompts.SYSTEM`, final text; `author`/`tune`/`refine` end with the Rules block above):

- `ideas`: "You extract detection ideas from a security article. Return one idea per distinct, log-observable attacker behaviour. attack_steps must be concrete (process names, command-line fragments, registry keys, ports, API calls). indicators are literal strings that appear in the article. log_sources name the product and the field names a detection would use; keywords are short lowercase substrings likely to appear in a Splunk sourcetype name (e.g. sysmon, wineventlog, 4688, okta, cloudtrail, pan, zeek). attack_examples are raw log lines or events quoted verbatim in the article, one per example, each with the keyword of the log source it belongs to; leave the list empty if the article quotes none. Do not invent indicators, examples or techniques absent from the text. Output only JSON matching the schema."
- `author`: "You are a senior Splunk detection engineer. Write one high-fidelity SPL search that catches the described attack steps using only the listed sources and fields. Target at most max_hits_per_day benign alerts per day. If failed_attempts is non-empty, write a materially different approach (different fields, logic or source), not a tweak. Output only JSON matching the schema." + Rules.
- `tune`: "You are a Splunk detection engineer tuning a search. Fix every item in problems while keeping the search able to catch the attack_steps. Narrow using the top offending values and available_fields; prefer precise field predicates over removing logic. Never remove or weaken logic that covers an item in must_keep; narrow elsewhere. Output only JSON matching the schema." + Rules.
- `review`: "You are the red team and a sceptical SOC lead. Your goal is to bypass this SPL or flood it with benign noise. attack_steps are the claim under test: the search must catch an attacker performing those steps however they are spelled or launched. You are given the search, what it matched in the last 7 days (hits_per_day, sample_rows, top_values), its exclusions, raw samples of the sourcetypes and prior_findings. Report only concrete, field-level findings: evasions of attack_steps (renamed binaries, alternate paths, encoding, case, spacing, quoting, abbreviated or colon-separated switches, field absence), false-positive sources you can see in the rows or samples, logic errors, performance and brittleness. Judge each exclusion against attack_steps: an exclusion that an attacker can satisfy is an evasion finding. For every evasion, give an evasion_event: take a real sample for the sourcetype and edit it into the attacker variant the search currently misses (renamed binary, alternate path, encoded case); it will be ingested and the search must match it. Severity high/critical only if a realistic variant of attack_steps is fully missed or a common benign source will fire daily. A different attack that attack_steps do not describe (another process chain, another payload mechanism) is out of scope: report it at most as low and give it no evasion_event, because the search must not be widened past the idea. If a prior finding is resolved, do not repeat it. Do not rewrite the search. Report nothing above low if the search is sound. Output only JSON matching the schema."
- `refine`: "You are a senior Splunk detection engineer hardening a search against a red-team review. Address every finding and make the search match every evasion_event while keeping benign alerts at or below max_hits_per_day; keep the search deterministic and readable. Output only JSON matching the schema." + Rules.

Routing guard inputs derived from these outputs are computed in code (§5.3); no output field ever selects a state directly.

Shared standard (from run 1, 2026-11-04, `development/e2e-findings.md`): the generator rules state the two tests the reviewer already applies — `available_fields` is complete (rule 3; enforced by lint rule 6) and exclusions must be attacker-unsatisfiable (rule 8; the reviewer's "an exclusion that an attacker can satisfy is an evasion finding") — so a reviewer `fix_hint` can never send `refine` outside the inventory that the next review would flag as brittleness, and the tuner no longer allow-lists users/hosts/integrity levels that cost a review round. Convergence comes from deterministic guards (lint rule 6, the §5.5 field guard, `exclusions` handing the reviewer every `where NOT` predicate), never from a softer reviewer. The one review-prompt change is a *scope* bound, not a severity discount (run 4, `development/runs/e2e_run4_state.json`): the prompt said "bypass this SPL" with no claim to bypass, listed "alternate parents" as an evasion class and set high/critical by "a realistic attacker variant" of anything, so each round raised a new HIGH for a different attack than the idea describes (round 3: Office → cmd.exe → powershell; base64 without `-enc`), each with an evasion_event that recall would have forced `refine` to match by widening the search past the idea. An unbounded finding space against Z=2 is `failed_review` by construction. Now `attack_steps` (already in the payload) is the claim under test: every variant of it (renamed binary, path, encoding, case, spacing, quoting, abbreviated or colon-separated switch, missing field) keeps full severity and an event; an attack the steps do not describe is at most low with no event, and belongs to another idea (`ideas` emits one idea per distinct behaviour). Every payload key a system prompt names must be in `INPUTS[step]` (`test_llm.py`), which is why rule 8 says "the attack" and not `attack_steps` (`refine` does not receive it).

---

## 7. Deterministic steps

All plain code; the library/function used is named for each.

### 7.1 Ideas tool (`cli.py`)
| step | implementation |
|---|---|
| fetch/clean article | `trafilatura.fetch_url(url)` then `trafilatura.extract(html, output_format="markdown", include_comments=False, favor_recall=True)`; local `.html/.htm/.txt/.md` → `extract(open().read())` (for `.txt/.md` use the text directly); `.pdf` → `"\n".join(p.extract_text() or "" for p in pypdf.PdfReader(path).pages)` |
| truncation | `text[:100_000]` with a stderr warning when truncated |
| id / stem / dedupe | `str(uuid.uuid4())`; stem convention; `ideas/<stem>.yml`, skip if exists (print "exists") |
| validation | `IdeaDraft` → `Idea(id=..., source_url=..., **draft)` after `title = title[:99]`, `summary = summary[:600]` (defensive; the schema already carries the limits); invalid MITRE ids filtered by regex before validation |
| write | `yaml.safe_dump(idea.model_dump(exclude_none=True), sort_keys=False, allow_unicode=True)` |

### 7.2 Source matching (`pipeline.do_match`)
```
for each (index, sourcetype st) in inventory where index != config.attack_index:   # the attack index mirrors production sourcetypes; a draft that searched it would count planted events as alerts
    kw_hits    = sum(kw.lower() in st.name.lower() for ls in idea.log_sources for kw in ls.keywords)
    field_hits = len({f for ls in idea.log_sources for f in ls.fields} & set(st.fields))
    score      = kw_hits * 10 + field_hits
keep score > 0 (kw_hits must be >= 1 unless idea.sourcetypes override is set), sort by (score, st.count) desc, keep top 4.
If idea.sourcetypes is non-empty: sources = exactly those names present in the inventory (any index), in order; score = 100.
```
Each source gets `data_source`, `asset_type`, `security_domain` from `models.SOURCETYPE_META` (first row whose regex matches with `re.search(rx, name, re.I)`; fallback `(sourcetype name, "Endpoint", "endpoint")`). Rows are ordered most-specific first and `security_domain` values are restricted to the contentctl enum:

```python
SOURCETYPE_META = [   # (regex, data_source, asset_type, security_domain); matched with re.I, first match wins
 (r"sysmon",                                "Sysmon EventID 1",                     "Endpoint",     "endpoint"),
 (r"powershell",                            "Powershell Script Block Logging 4104",  "Endpoint",     "endpoint"),
 (r"wineventlog:security|:4688",            "Windows Event Log Security 4688",      "Endpoint",     "endpoint"),
 (r"wineventlog",                           "Windows Event Log",                    "Endpoint",     "endpoint"),
 (r"linux|syslog|auditd",                   "Linux Auditd",                         "Endpoint",     "endpoint"),
 (r"cloudtrail",                            "AWS CloudTrail",                       "AWS Account",  "threat"),
 (r"azure|o365|m365|office365",             "Azure Monitor Activity",               "Azure Tenant", "threat"),
 (r"\bgcp\b|google",                        "Google Cloud Platform",                "GCP Account",  "threat"),
 (r"okta|auth0|\bduo\b",                    "Okta",                                 "Okta Tenant",  "identity"),
 (r"zeek|\bbro\b|pan(os)?[:_]|firewall|netflow|suricata|\bdns\b", "Zeek",          "Network",      "network"),
 (r"proxy|squid|zscaler|\bweb\b|\biis\b|nginx|apache", "Nginx Access",             "Web Server",   "network"),
]
```

### 7.3 SPL helpers (`spl.py`)
| function | behaviour |
|---|---|
| `normalise(s) -> str` | strip; collapse runs of whitespace to one space; strip a leading `search ` (case-insensitive); strip a trailing `` \| `<anything>_filter` `` macro |
| `runnable(s) -> str` | `normalise(s)` then prefix `search ` unless it starts with `\|` (splunk-sdk requires this) |
| `with_filter(s, stem) -> str` | `normalise(s) + f" \| `{stem}_filter`"` |
| `window_seconds(w) -> int` | §5.4 regex |
| `referenced_fields(s) -> set[str]` | LHS of `(\w[\w.]*)\s*(=\|!=\|<=\|>=\|<\|>)` and `(\w[\w.]*)\s+IN\s*\(`; names in `by` lists (`\bby\s+([\w.,\s]+?)(?=\|\|$)`); args of stats functions `\b(count\|dc\|values\|min\|max\|sum\|avg\|earliest\|latest\|first\|last\|list)\(([\w.]+)\)`; the first argument of common eval/where functions `_FUNC` = `\b(?:lower\|upper\|len\|trim\|ltrim\|rtrim\|match\|like\|isnull\|isnotnull\|coalesce\|replace\|substr\|split\|mvcount\|tonumber\|tostring\|cidrmatch\|urldecode)\(\s*([A-Za-z_][\w.]*)\b(?!\s*\()` (so `\| where match(F, …)` / `\| eval x=lower(F)` cannot bypass rule 6; the trailing `(?!\s*\()` skips a nested call so `match(lower(F), …)` yields `F`, not the bogus field `lower`, and `tostring(now())` yields nothing; derived names such as `match(ParentLower, …)` are subtracted by `derived_fields`); the value of `rex field=X`; the columns of `\| table` / `\| fields [-+]` segments (wildcards dropped) and the field list of `\| fillnull [value=v]` (so moving an unverified field into a rex/table/fillnull cannot bypass rule 6 either); bare identifiers after `where`/`eval` are still **not** extracted (too noisy). Quoted strings are blanked first. Excludes `BUILTINS = {index, sourcetype, source, host, earliest, latest, _time, _raw, count, firstTime, lastTime}`, the SPL keywords `AND OR NOT IN as by`, and `OPTION_WORDS = {field, value, input, output, outputnew, max_match, offset_field, mode, limit, span, delim, usenull, allnum, otherfield, local, keepempty, consecutive, path, prefix, timeformat, maxspan, maxpause, window}` (command options such as `rex field=`, `fillnull value=`, `spath input=`/`path=`, `convert timeformat=`, `transaction maxspan=` are not fields; now that rule 6 is a gate error a false field reference would waste a tune round) |
| `derived_fields(s) -> set[str]` | `eval\s+([\w.]+)\s*=`, `\bas\s+([\w.]+)`, `\(\?<(\w+)>` (rex), `output(?:new)?=([\w.]+)` (spath/lookup), `\bOUTPUT(?:NEW)?\s+([\w.\s,]+?)(?=\|\|$)` (lookup) |
| `group_fields(s) -> list[str]` | the `by` list of the **last** `\| stats`/`\| tstats` segment (same `by` regex, split on commas/whitespace, `_time` and `span=…` dropped), else the column list of the last `\| table`; `[]` when neither exists |
| `indexes_in(s) -> set[str]`, `sourcetypes_in(s) -> set[str]` | values of `index\s*=\s*("[^"]*"\|\S+)` / `index\s+IN\s*\(([^)]*)\)` and likewise for `sourcetype`, quotes stripped |
| `exclusions(s) -> list[str]` | every `NOT\s+[\w.]+\s*=\s*("[^"]*"\|\S+)` and `[\w.]+\s*!=\s*("[^"]*"\|\S+)` term, verbatim, then every parenthesised group `NOT\s*\((?:[^()]\|\([^()]*\))*\)` (one level of nesting) in a segment that is not a `where … NOT` segment, e.g. `NOT (IntegrityLevel="High" OR IntegrityLevel="System")` in the base search, followed by every `_split` segment matching `where\b.*\bNOT\b` (case-insensitive) verbatim, e.g. `where NOT (IntegrityLevel="High" OR IntegrityLevel="System")`, so the reviewer's `exclusions` input carries attacker-satisfiable `where` predicates instead of relying on it to find them |
| `bucketed(s, span="20m") -> str` | if `s` starts with `\| tstats`: insert `_time span=<span> ` right after the first `\bby\s+` in that segment, or append ` by _time span=<span>` to the segment when it has no `by`; else if a `\| stats` segment exists: replace the first `\|\s*stats\b` with `\| bin _time span=<span> \| stats` and insert `_time ` after that segment's `\bby\s+` (or append ` by _time` when it has none); else return `s` unchanged |
| `lint(spl, inventory, stem, sources: list[str]) -> Lint(errors, warnings)` | rules below; `sources` = the sourcetype names of `self.sources` |
| `top_values(rows, fields, n=5) -> dict[str, list[tuple[str,int]]]` | per field over ≤200 rows, weighted by `int(row.get("count", 1))`; only for fields with ≤ 80 % distinct values over the rows; `most_common(n)` |
| `high_cardinality(rows, fields, min_rows=10) -> list[tuple[str,int,int]]` | `(field, distinct, rows)` for fields with > 80 % distinct values; `[]` when fewer than `min_rows` rows (a handful of rows is always "distinct") |
| `project(rows, fields, n=5) -> list[dict]` | first n rows, keys restricted to `fields` |
| `rewrite_index(s, index, host=None) -> str` | replace every `index\s*=\s*("[^"]*"\|\S+)` and `index\s+IN\s*\([^)]*\)` with `index=<index>`; when `host` is given, the first replacement becomes `index=<index> host="<host>"` (valid after `search` and inside `\| tstats … where`) |

Lint rules (`errors` block the gate, `warnings` are feedback only). Unbalanced syntax is not linted: Splunk's parser reports it as an ERROR message, which reaches the tuner through `run.errors` (§7.4).
1. error: `earliest=`, `latest=`, `_index_earliest`, `_index_latest` anywhere.
2. error: banned command regex `\|\s*(head|delete|collect|outputlookup|sendemail|script|run|map|dump|rest|dbxquery)\b`.
3. error: no `index=` / `index IN` and no macro at the start (unless search starts with `| tstats` and contains `where index=`); `index=*` or `index="*"`.
4. error: each value of `indexes_in` ∉ `inventory.index_names()`; each value of `sourcetypes_in` ∉ `inventory.sourcetype_names()`.
5. error: each `` `macro` `` (regex `` `([\w]+)(?:\([^)]*\))?` ``) ∉ `inventory.macros ∪ {stem_filter}`.
6. unknown field: for each `f` in `referenced_fields − derived_fields` not in `known` = union of `inventory.fields_for(st)` for `st` in `sourcetypes_in(spl) or sources`: **error** `unknown field 'ParentCommandline' (did you mean 'ParentCommandLine'?)` when `difflib.get_close_matches(f, known, n=1, cutoff=0.8)` finds a near match, else **error** `unknown field 'OriginalFileName' (not in available_fields)`. Only when the search uses `| tstats` or `datamodel=` is it a **warning** `unverified field 'f'` (data-model fields are not in the inventory by design, §13). Rationale: the inventory's field sample is balanced per EventCode (§4.2: `dedup 100 EventCode` then `fieldsummary`, 5 % floor), so a field absent from it is absent, or not extracted, in this environment, which is exactly the brittleness a reviewer flags; the recall gate cannot verify a field because evasion events are model-authored (§5.5). Run 1 (`development/e2e-findings.md`) showed that an advisory warning lets `refine` follow a `fix_hint` onto such a field, the reviewer then spends the last round on it and the run ends `failed_review`; as an error the draft is repaired by `tune` (§5.3) before a review round is spent. Residual risk: a real field below the 5 % floor or beyond the 60-field cap is rejected; the operator remedy is `dea inventory --refresh` or a richer inventory, which is also the honest answer (a detection on a field the inventory cannot see is not verifiable).
7. error: a bare (non `field=`) search term beginning with `*` (regex `(?:^|\s)\*\S` in the text before the first `|`) or `_raw="*`. Leading wildcards in `field="*..."` are allowed (needed for path matching).
8. error: no `| stats`/`| tstats`/`| table` segment (group fields are required for rba, throttling and the schedule-shaped gate). warning: search longer than 4000 chars.
9. warning (schedule): the search contains `| transaction`, `| streamstats`, `earliest(`/`latest(` used in an `eval` delta, or a `span=` larger than 20 minutes: `"schedule: <construct> cannot complete inside the 20-minute dispatch window"`.

### 7.4 Gate orchestration (`pipeline.do_test`)
lint → if errors: `run = Run(count=None, scan_count=0, rows=[], errors=[])`, skip Splunk; else `gate_spl` (§5.4), `run = splunk.run(gate_spl, earliest=config.window)`; Splunk ERROR messages → `run.errors`, `count=None`; recall (§5.5, un-bucketed `runnable(spl)` per example); `rate`, `threshold`, rows with `_time` dropped, `top_values(rows, group_fields)`, `high_cardinality`, `project(rows, group_fields + ["count"])`, zero-hit rule, `problems`, `ok` (§5.4). All stored in `self.gates` (incl. `gate_spl`), draft number recorded, `(spl, reason)` appended to `self._line`, history appended. A lint error on a refined draft is not special: `problems[0]` is the lint line and the machine routes `drafted → tuning` (§5.3).

### 7.5 Rendering (`models.Detection.from_run(idea, draft, sources, findings, status, out_dir) -> Detection`)
`findings` = `review_log[-1].findings` (empty when no review ran). `k` = the first of `draft.group_fields` that maps to a risk object, else `draft.group_fields[0]`.

| field | rule |
|---|---|
| `name` | `idea.title` |
| `id` | `idea.id` |
| `version` | 1, or existing file's `version + 1` if `<out_dir>/<stem>.yml` exists and its `search` differs (same search → keep version) |
| `date` | `date.today().isoformat()` |
| `author` | `"detection-engineering-agent"` |
| `status` | §5.6 |
| `type` | `idea.type` |
| `description` | `f"{idea.summary}\n\nDetects: {'; '.join(idea.attack_steps)}"` |
| `data_source` | unique `source.data_source` for sources whose sourcetype (or index) appears in the search; fallback all matched sources |
| `search` | `with_filter(draft.spl, stem)` |
| `how_to_implement` | `f"Ingest {product} as sourcetype {st} into index {idx}. " * matched` + `f"Fields used: {', '.join(draft.fields_used)}. Adjust the index/sourcetype or the {stem}_filter macro for your environment."` |
| `known_false_positives` | `idea.false_positive_notes or "None identified."` + `" Review findings: " + "; ".join(f"{f.detail} ({f.severity})" for f in findings if f.category == "false_positive")` when any |
| `references` | `[idea.source_url]` if set else `[]` |
| `drilldown_searches` | omitted if `type == "Hunting"`; else exactly the two entries of §4.4 (contentctl's canonical pair): `View the detection results for $k$` with `search = '%original_detection_search% \| search {k}="${k}$"'` and `View risk events for the last 7 days for $k$` with the `\| from datamodel Risk.All_Risk ...` search, both with `earliest_offset: $info_min_time$`, `latest_offset: $info_max_time$` |
| `rba` | omitted if `type == "Hunting"`. `risk_objects`: for `g in draft.group_fields`: `user` if `g.lower() in {"user","src_user","username","user_name","account_name","useridentity.arn"}`; `system` if `g.lower() in {"computer","host","dest","src","dvc","computername","hostname","src_ip","dest_ip"}`; score = `SEVERITY_SCORE = {"low":25,"medium":50,"high":70,"critical":90}[idea.severity]`; at least one object required → fallback `{field: group_fields[0], type: "other"}` |
| `rba.threat_objects` | `CommandLine/process_command_line/Process_Command_Line → command`; `Image/process_name/New_Process_Name → process_name`; `ParentImage/parent_process_name/Creator_Process_Name → parent_process_name`; `dest_ip/DestinationIp → ip_address`; `url → url`; `file_name/TargetFilename → file_name`; may be empty |
| `rba.message` | `f"{name} on $<system field>$ by $<user field>$"` using whichever exist |
| `tags` | `analytic_story: [idea.title]`; `asset_type`, `security_domain` from first source; `mitre_attack_id: idea.mitre_attack_id`; `product` constant three; `throttling: {fields: risk-object fields, period: "86400s"}` (omitted for Hunting) |
| `tests` | present iff `idea.attack_data_url`; `data = attack_data_url`; `source = sourcetype = first source sourcetype`; `test_type: unit` |

`Detection.severity` (property) = inverse of `SEVERITY_SCORE` on `max(o.score for o in rba.risk_objects)` (25→low, 50→medium, 70→high, 90→critical; nearest-lower for other values); `"medium"` when `rba` is absent (Hunting). This is how `publish`, which only has the YAML, recovers the severity.

`Detection.to_yaml() -> str` = `yaml.safe_dump(model_dump(exclude_none=True), sort_keys=False, width=10_000, allow_unicode=True)`. `macro_yaml(stem) -> str`.

`Detection.conf_props(es: bool = False) -> dict[str, str|int]` = the REST arguments for `saved/searches` (REST names, not `savedsearches.conf` keys — there is no `enableSched`/`counttype`):
```
is_scheduled = 1                      cron_schedule = */15 * * * *        schedule_window = auto        allow_skew = 100%
dispatch.earliest_time = -25m@m       dispatch.latest_time = -5m@m        description = <description>
alert_type = number of events         alert_comparator = greater than     alert_threshold = 0
alert.severity = SEVERITY_ALERT[severity]  ({"low":2,"medium":3,"high":4,"critical":5})     alert.track = 1
alert.digest_mode = 0  alert.suppress = 1  alert.suppress.fields = <",".join(tags.throttling.fields)>  alert.suppress.period = 86400s
```
(the `alert.suppress*` keys are omitted when `tags.throttling` is absent, i.e. Hunting). The dispatch window is 20 minutes with a 5-minute overlap and 5 minutes of indexing-lag tolerance, matching the bucket span of the noise gate. With `es=True` add: `action.notable = 1`, `action.notable.param.rule_title = <name>`, `action.notable.param.rule_description = <description>`, `action.notable.param.security_domain = <tags.security_domain>`, `action.notable.param.severity = <severity>`, `action.correlationsearch.enabled = 1`, `action.correlationsearch.label = <name>`, and when `rba` exists `action.risk = 1`, `action.risk.param._risk_message = <rba.message>`, `action.risk.param._risk_score = 0`, `action.risk.param._risk = json.dumps([{risk_object_field, risk_object_type, risk_score} …] + [{threat_object_field, threat_object_type} …])`.

Pipeline `do_render` writes `<out>/<stem>.yml` and `<out>/macros/<stem>_filter.yml`, records paths in `self.outputs`.

### 7.6 Publish (`cli publish`)
Load `Detection` from YAML. When `det.search` ends with `` `<m>_filter` `` (always, for rendered detections), load the sibling `<dir>/macros/<m>_filter.yml` and `splunk.publish_macro(m, definition)` **first** (a saved search whose macro does not exist fails on every scheduled run); a missing macro file is an error for that detection (stderr, exit 1). Then `splunk.publish(det.name, det.search, det.conf_props(es))`. Both idempotent: create or update. `--dry-run` prints `[<m>_filter]`, `definition = <definition>`, a blank line, then `[name]`, `search = <search>` and one `key = value` line per prop instead. A path argument that does not exist (e.g. `detections/` before the first run) is skipped with a stderr note, not an error.

---

## 8. Splunk adapter — `src/detection_engineering_agent/splunk.py`

```python
class Run(BaseModel):
    count: int | None          # resultCount; None when the search errored
    scan_count: int = 0
    rows: list[dict] = []      # ≤ `rows` result rows (dicts)
    errors: list[str] = []     # the job's fatal/error messages (failed at dispatch) or ERROR messages in the results

class Splunk(Protocol):
    kind: str                                                                   # "mock" | "real"
    def inventory(self, window: str = "-7d", max_sourcetypes: int = 200) -> Inventory: ...
    def run(self, spl: str, earliest: str = "-7d", latest: str = "now", rows: int = 200) -> Run: ...
    def ingest(self, index: str, sourcetype: str, raws: list[str], host: str) -> int: ...  # events written
    def publish(self, name: str, search: str, props: dict[str, str | int]) -> str: ...   # returns saved-search name
    def publish_macro(self, name: str, definition: str) -> str: ...                     # returns macro name

def get(kind: str | None = None) -> Splunk:
    """kind or env DEA_SPLUNK ('mock'|'real'); default 'real' if SPLUNK_TOKEN is set else 'mock'."""
```

### 8.1 MockSplunk(fixture_dir: Path)

Fixture directory (default `tests/fixtures/splunk`, override env `DEA_FIXTURES`):

| file | content |
|---|---|
| `inventory.json` | exactly §4.2 |
| `runs.json` | `[{"count": 412, "scan_count": 912000, "rows": [...]}, {"count": 60, "rows": [...]}, {"count": 2, "rows": [...]}, {"count": 1, "rows": [...]}]` (4 entries, no `errors` entry) — `run()` with `earliest != "0"` returns entries **in call order** (an instance counter); after the last entry the last entry repeats, so every gate call past the script is clean. An entry with `errors` yields `count=None`; a test that needs one writes its own `runs.json` (`test_splunk`). The shared fixture must never script an error: a real-inference run on the mock reaches whatever the 5th call is regardless of the draft's content, and runs 1 and 3 each burned their last, opus tune on a scripted parse error there. The mock recall gate (`recall.json = [1]`) never evaluates evasion events; only real Splunk does. |
| `recall.json` | `[1]` — `run()` with `earliest == "0"` (the recall gate's signature) returns `Run(count=<next entry>)` in call order, last entry repeating; missing file ⇒ `[1]` |
| `ingested.jsonl` | written by `ingest`: one JSON line `{"index","sourcetype","host","raw"}` per event; returns `len(raws)` |
| `published.conf` | appended by `publish`: `[name]\nsearch = ...\n<k = v>...\n\n`; by `publish_macro`: `[name]\ndefinition = ...\n\n`; returns `name` |

~35 LOC. The mock does not evaluate SPL; routing behaviour is scripted by `runs.json`/`recall.json` order (tests document the order they rely on).

### 8.2 RealSplunk (splunk-sdk 3.0.1)

Construction `RealSplunk.from_env()`; env vars: `SPLUNK_HOST` (required), `SPLUNK_PORT` (8089), **`SPLUNK_TOKEN`** (bearer token, required), `SPLUNK_APP` (`search`), `SPLUNK_OWNER` (`nobody`), `SPLUNK_VERIFY` (`1`; `0` disables TLS verification).

```python
self.svc = splunklib.client.connect(host=HOST, port=PORT, scheme="https", splunkToken=TOKEN, autologin=True,
                                    app=APP, owner=OWNER, verify=VERIFY)      # sends Authorization: Bearer <TOKEN>
def _q(self, spl, earliest="-7d", latest="now") -> list[dict]:
    rr = splunklib.results.JSONResultsReader(self.svc.jobs.oneshot(spl, output_mode="json", count=0, earliest_time=earliest, latest_time=latest))
    return [r for r in rr if isinstance(r, dict)]
```

| method | SDK calls | REST behind it |
|---|---|---|
| `inventory` | indexes: `[(i.name, int(i["totalEventCount"])) for i in svc.indexes if not i.name.startswith("_") and int(i["totalEventCount"]) > 0]`; per index sourcetypes: `_q(f"\| tstats count where index={idx} by sourcetype", earliest=window)`; per sourcetype fields: `_q(f'search index={idx} sourcetype="{st}" \| head 2000 \| dedup 100 EventCode keepempty=true \| fieldsummary maxvals=3 \| fields field count values')` → filtered per §4.2 (`count >= 0.05 * max_count`, internal fields dropped, top 60) → `{r["field"]: [v["value"][:80] for v in json.loads(r["values"])][:3]}`; sample: `_q(f'search index={idx} sourcetype="{st}" \| head 1 \| fields _raw')` → `r["_raw"][:600]` or `None`; macros: `sorted({m.name.split("(")[0] for m in svc.confs["macros"]})` (conf titles carry the argcount, e.g. `security_content_ctime(1)`; lint compares bare names); cap `max_sourcetypes` by count | `GET /services/data/indexes?output_mode=json&count=-1`; `POST /services/search/v2/jobs` (exec_mode=oneshot, falls back to `/services/search/jobs`); `GET /services/configs/conf-macros?count=-1` |
| `run` | `job = svc.jobs.create(spl, exec_mode="blocking", earliest_time=earliest, latest_time=latest)`; `count=int(job["resultCount"])`, `scan_count=int(job["scanCount"])`; then, before fetching results, `job.content["messages"]` (`{"fatal": [...], "error": [...]}` when the search failed at dispatch — Splunk 10.6 accepts a bad regex or unparseable SPL as a blocking job with `dispatchState=FAILED` and only `results()` answers 400, which killed real run 2) → `Run(count=None, scan_count, errors=<deduplicated fatal+error>)`; else `rr = JSONResultsReader(job.results(output_mode="json", count=rows))`; `rows=[r for r in rr if isinstance(r, dict)]`; `errors=[m.message for m in rr-messages if m.type == "ERROR"]` (collect `results.Message` items while iterating); on HTTPError 400 from `jobs.create` → `Run(count=None, errors=[str(e)])`; finally `job.cancel()` | `POST /services/search/v2/jobs` (blocking) → `GET /services/search/v2/jobs/{sid}` (`resultCount`, `scanCount`) → `GET /services/search/v2/jobs/{sid}/results?output_mode=json&count=N` → `DELETE /services/search/v2/jobs/{sid}` |
| `ingest` | `idx = svc.indexes[index]` (create via `svc.indexes.create(index)` if missing); `for raw in raws: idx.submit(raw.encode("utf-8"), sourcetype=sourcetype, host=host)`; return `len(raws)`. Bytes, not str: splunk-sdk 3.0.1 forwards the body unchanged to `http.client`, which encodes a str as Latin-1 (`UnicodeEncodeError` on U+2013 etc.; real run 1 crashed on a reviewer event `powershell –enc ...`) and sets `Content-Length` in characters | `POST /services/receivers/simple?index=&sourcetype=&host=` |
| `publish` | `if name in svc.saved_searches: svc.saved_searches[name].update(search=search, **props).refresh() else: svc.saved_searches.create(name, search, **props)` (dotted keys go through the `**dict`; `props` are REST argument names, §7.5) | `POST /servicesNS/{owner}/{app}/saved/searches` / `POST .../saved/searches/{name}` |
| `publish_macro` | `if name in svc.macros: svc.macros[name].update(definition=definition) else: svc.macros.create(name, definition)` | `POST /servicesNS/{owner}/{app}/admin/macros` / `POST .../admin/macros/{name}` |

The SPL handed to `run` always starts with `search ` or `|` (`spl.runnable`). Inventory for N sourcetypes costs 1 + I + 2N + 1 requests; `dea inventory` caches to `inventory.json` and `dea run` reuses it when younger than 24 h (`--refresh` to refetch). Wiring to a real environment = set `SPLUNK_HOST` and `SPLUNK_TOKEN`; no code change.

---

## 9. Article-to-idea tool

`dea ideas <url | file.html | file.pdf | file.txt | file.md> [-o ideas/] [--model claude-sonnet-5-5]` (implemented as `cli.ideas(src: str, out_dir: Path, model: str | None) -> list[Path]`).

1. Text extraction (§7.1): trafilatura for URLs/HTML, pypdf for PDF, raw read for txt/md. Empty text (< 200 chars) → error exit 1.
2. **Inference call #0 `ideas`** (haiku by default; `--model` overrides, e.g. sonnet for a hard article): payload `{"text": text[:100_000]}` → `IdeasOut`. `source_url` is set by code, never sent.
3. For each `IdeaDraft`: filter `mitre_attack_id` by regex, drop drafts with empty `attack_steps` or `log_sources` (warn), truncate title/summary, build `Idea(id=uuid4, source_url=...)`, write `ideas/<stem>.yml` unless it exists.
4. Print written paths; exit 0. Exactly one inference call per article regardless of idea count.

---

## 10. CLI — `src/detection_engineering_agent/cli.py`, console script `dea`, `argparse`

| subcommand | flags | effect / exit |
|---|---|---|
| `dea ideas <src>` | `-o/--out ideas`, `--model` | §9 |
| `dea inventory` | `--splunk mock\|real` (default per `splunk.get`), `--window=-7d`, `--refresh`, `-o inventory.json`, `--max-sourcetypes 200` | fetch (or print cached) inventory; prints `index  sourcetype  count` table to stdout; exit 0 |
| `dea run <idea.yml>` | `--splunk`, `--inventory inventory.json`, `--refresh`, `--resume`, `--tunes 3`, `--remakes 1`, `--reviews 2`, `--max-cost 5.0`, `--window=-7d`, `--attack-index dea_attack`, `--max-scan 50000000`, `--model STEP=MODEL` (repeatable → `config.models`), `-o/--out detections`, `--runs runs`, `-v/--verbose` (→ `config.verbose`) | load idea + inventory, `run_dir = runs/<idea.id>`, build `Pipeline` (or `load` with `--resume`), `drive()`; print terminal state, counters, cost, output paths (or problems / coverage note path); exit codes §5.6. With `-v`, one stderr line per state transition (a `transitions` `after_state_change` callback, `Pipeline.report`): `<from> -> <to>  <last history step>  $<its cost>  <m:ss since run start>`; off by default, stdout unchanged |
| `dea publish <file.yml \| dir>` | `--splunk`, `--es`, `--dry-run` (print props only) | §7.6 for each YAML; exit 0, or 1 on any failure |

`--window` values start with `-`, which argparse reads as an option when space-separated; the documented and tested form is `--window=-7d` (help text says so). `--model` values are validated as `STEP=MODEL` with `STEP ∈ prompts.MODEL`.

Environment: `SPLUNK_HOST/PORT/TOKEN/APP/OWNER/VERIFY`, `DEA_SPLUNK`, `DEA_FIXTURES`. Nothing else.

`main(argv: list[str] | None = None) -> int` returns the exit code (tests call it directly); the console entry wraps it in `sys.exit`. Run status is read from `runs/<idea_id>/state.json` directly (README documents `cat runs/<id>/state.json`); there is no `status` subcommand.

---

## 11. Testing

Framework: `pytest`, fully offline by default; no network, no Splunk, no `claude` binary. `uv run pytest -q`.

### 11.1 Fixtures
- `tests/fixtures/idea.yml` — the §4.1 example (id fixed `3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11`, `attack_examples: []`).
- `tests/fixtures/splunk/inventory.json` — §4.2 with two indexes (`wineventlog`, `proxy`) and three sourcetypes (Sysmon operational, `WinEventLog:Security`, `squid:access`); macros `["sysmon","security_content_ctime"]`.
- `tests/fixtures/splunk/runs.json` — `[412 noisy (rows with ParentImage dominated by explorer.exe, each row carrying a count), 60 noisy, 2 clean, 1 clean]` (4 entries, no error entry, §8.1). `tests/fixtures/splunk/recall.json` — `[1]`.
- `tests/fixtures/llm/*.json` — `author.json` (1 noisy SPL), `tune.json` (2 progressively narrower SPLs), `review.json` (`[{findings: [one medium evasion], evasion_events: [one Sysmon event]}, {findings: [], evasion_events: []}]`), `refine.json` (1), `ideas.json` (2 ideas). Every SPL in fixtures references only inventory fields/sourcetypes and ends in `| stats count ... by ...` so lint passes. **Every scripted SPL within a scenario must be unique after `normalise()`** — the stall rule (`can_tune`) routes a repeated SPL to remake/`failed_noisy` and changes the path.
- `tests/fixtures/llm_noisy/` — scenario 2 of §11.3: `author.json` with 2 distinct SPLs, `tune.json` with 6 SPLs pairwise distinct and distinct from both author SPLs.
- `tests/fixtures/llm/envelope.json` — the real recon envelope shape (`{"type":"result","subtype":"success","is_error":false,...,"structured_output":{...},"total_cost_usd":0.0076}`) with `structured_output` set to a valid `SplOut` (`{"spl": "index=wineventlog ... | stats count by Computer"}`).
- `tests/fixtures/article.html` — a static DFIR-style post (> 2000 chars of body text).
- `conftest.py`: `fixture_dir`, `mock_splunk` (fresh `MockSplunk(tmp copy of fixtures/splunk)`, copied with `ignore_patterns('*.jsonl', '*.conf')` because a `dea run`/`dea publish` on the default mock leaves `ingested.jsonl`/`published.conf` in the fixture directory; both are git-ignored), `fake_llm` (a factory: `fake_llm(dir="tests/fixtures/llm")` monkeypatches `subprocess.run` with a side-effect that reads `--system-prompt`'s step from argv (via a reverse lookup in `prompts.SYSTEM`), pops the next entry of `<dir>/<step>.json`, and returns a `CompletedProcess` whose stdout is the recon envelope with that entry as `structured_output` and `total_cost_usd: 0.0`; raises `IndexError` when a step's list is exhausted, which `drive()` turns into the `error` terminal, so every scenario scripts exactly enough entries; exposes `.calls` = the mock's call list for count assertions), `idea`, `inventory`, `tmp_runs`. There is no fixture backend in `llm.py`; the allowed-keys check in `ask` runs for every fake call too.

### 11.2 Test files (what must pass)

| file | asserts |
|---|---|
| `test_models.py` | idea example validates; bad MITRE id / 100-char title rejected; `Idea.threshold` per type and override; `schema(IdeasOut)["properties"]["ideas"]["items"]` carries `maxLength` 99/600 via `$defs`; `Detection.from_run` on a synthetic draft produces §4.4 fields, search ends with `` `<stem>_filter` ``, rba objects chosen per table, threat types ∈ Literal, two drilldowns with `%original_detection_search%`, `tests` omitted without `attack_data_url`, Hunting omits rba/drilldowns/throttling; `severity` property inverse mapping; `conf_props()` contains `is_scheduled`, `cron_schedule`, `dispatch.earliest_time == "-25m@m"`, `alert.suppress.fields` ⊆ `group_fields`, no `enableSched`; `conf_props(es=True)` contains `action.risk.param._risk` as JSON and `action.correlationsearch.label`; `to_yaml()` round-trips through `Detection.model_validate(yaml.safe_load(...))`; version bump rule; `PipelineState` round-trips drafts as `Draft` objects |
| `test_spl.py` | each lint rule 1–9 positive/negative; near-match → error with hint, unknown without near-match → error `(not in available_fields)` with no warning; `tstats` downgrades rule 6 to warning; function-argument fields (`where match(F, …)`, `eval x=lower(F)`) are referenced fields and fail rule 6 while derived ones (`match(p, …)`, `isnotnull(p)`) do not; nested calls (`match(lower(F), …)`, `mvcount(split(F, …))`, `lower(coalesce(F, ""))`, `len(trim(F))`, `tostring(now())`) lint clean while the inner real field is still checked; `rex field=F`, `fillnull value=NA F`, `table … F` and `fields - F` reference `F`; a quoted `"lower(Fake)"` is ignored; `exclusions` returns `where NOT (...)` segments verbatim, parenthesised `NOT (...)` groups in the base search, and nothing for a `where` without `NOT`; `rex field=` and `fillnull value=` are not referenced fields; `normalise` idempotent, strips `search ` and the filter macro; `runnable` prefixes `search `; `window_seconds("-7d")==604800`, `-24h`, `-30m@m`, invalid raises; `referenced_fields`/`derived_fields` on eval/rename/rex/lookup; `group_fields` for stats-by, tstats-by, table, none; `indexes_in`/`sourcetypes_in`; `exclusions`; `bucketed` for stats with/without `by`, tstats, and passthrough; `top_values` weighted by `count` and skipping high-cardinality fields; `high_cardinality`; `rewrite_index` handles `index=x`, `index="x"`, `index IN (a,b)` and injects `host=` once |
| `test_llm.py` | monkeypatched `subprocess.run` returns `envelope.json`: `ask("tune", {keys ⊆ INPUTS["tune"]}, SplOut)` builds argv containing exactly `--tools ""`, `--max-turns 2`, `--setting-sources ""`, `--no-session-persistence`, `--system-prompt`, `--json-schema <schema>`, passes the payload JSON as `input=` and **not** in argv, and returns `(SplOut, 0.0076)`; `subtype == "error_max_turns"` or invalid structured_output → one retry then `LLMError` (two calls total); payload with a key outside `INPUTS[step]` raises `ValueError` before any subprocess call; explicit `model=`/`effort=` land in argv; every `snake_case` payload key named in `SYSTEM[step]` (author/tune/review/refine) is in `INPUTS[step]` (author may name `available_fields`, which it receives as `sources[].fields`) |
| `test_splunk.py` | `MockSplunk.inventory()` equals the file; `run()` sequence and last-repeat; `errors` entry → `count=None`; `earliest="0"` consumes `recall.json`; `ingest` writes jsonl with host; `publish` appends stanza. `RealSplunk` with a `MagicMock` service: `connect` called with `splunkToken=` and `scheme="https"`; `run` calls `jobs.create(..., exec_mode="blocking")`, reads `resultCount`/`scanCount`, calls `cancel()`; `publish` uses `create` when absent and `update(...).refresh()` when present with dotted keys and `is_scheduled` in the kwargs; `ingest` calls `indexes[idx].submit(raw.encode("utf-8"), sourcetype=..., host=...)` (bytes, also for a non-Latin-1 event); inventory field filtering (5 % rule, internal fields, cap 60) and `confs["macros"]` |
| `test_pipeline.py` | `Pipeline` with all `do_*` monkeypatched to set canned `gates`/`review_log`/`drafts` (no LLM, no Splunk). Exact state/trigger sequences for: happy path (`[match, author, test, review, render]` → `done`); noisy×3 → remake → clean; noisy forever → `failed_noisy` after exactly 2 author + 6 tune calls and `failed_attempts` with 4 entries; fixed-point (tune returns same SPL) → remake after 1 tune; review with medium findings ×Z → `done` with `status_cap == "experimental"`; identical `(category, severity)` findings twice → stops refining after round 1; high residual after Z → `failed_review`; `review_pass` true with only-low findings and false with one medium (no verdict field); no sources → `infeasible` + `coverage.md` exists; `do_author` raising → `error` with `prior_state == "matched"`, `load()` re-enters `matched` with the CLI config and continues to `done`, drafts are `Draft` instances after load; cost cap: `cost_usd` crossing `max_cost_usd` inside `_ask` → `error`; `save()` output has exactly `STATE_FIELDS` keys; with real `do_tune` and a stubbed `_ask`, `model="claude-opus-5-5", effort="high"` (the author model) is passed on exactly the 3rd tune; with real `do_test` and a stubbed `splunk.run`, the SPL that reaches `run` is the bucketed form ending in `\| sort 0 - count` and the author payload's `max_hits_per_day == gates["threshold"]`; `do_refine` ingests evasion events and recall then runs per example with `earliest="0"`; with real `do_test`, a refine draft referencing a field outside the inventory fails lint without a Splunk run (`problems[0]` = the lint line, no warnings) and the next real `do_tune` payload carries that line in `problems` and the evasion notes in `must_keep`; `do_tune` after two review rounds sends `must_keep` = both rounds' evasion notes in order and no finding detail; `do_refine` strips an XML `Data` element whose name is in neither the inventory nor the real sample from the event before ingest and from the `refine` payload (also when its value spans a newline), keeps one whose name is in the inventory only, and leaves `review_log` as the reviewer wrote it |
| `test_cli.py` | `main(["ideas", "tests/fixtures/article.html", "-o", tmp])` with fake llm writes 2 idea files that validate as `Idea` with `source_url` set and the `ideas` payload has only `text`; second run prints "exists" and writes nothing; `main(["run", ..., "--window=-7d"])` parses (monkeypatched `Pipeline.drive`); exit code mapping for each terminal; `publish --dry-run` output contains `is_scheduled = 1` |
| `test_e2e.py` | **the end-to-end offline test (below)** |

### 11.3 End-to-end offline test (must pass)

```
env: DEA_SPLUNK=mock, DEA_FIXTURES=<tmp copy of tests/fixtures/splunk>; fake_llm("tests/fixtures/llm")
rc = cli.main(["run", "tests/fixtures/idea.yml", "--runs", tmp/"runs", "-o", tmp/"detections", "--inventory", tmp/"inventory.json", "--refresh"])
```
Asserts:
- `rc == 0`; `state.json` has `state == "done"`, `tunes == 2`, `remakes == 0`, `reviews == 1`, `len(drafts) == 4`, `len(examples) == 1` (the evasion event), `cost_usd == 0.0`.
- `[h["step"] for h in history] == ["match","author","test","tune","test","tune","test","review","refine","test","review","render"]`.
- fake llm call counts: author 1, tune 2, review 2, refine 1 (6 calls total); every payload passed the allowed-key check (a violation would have raised).
- `gates["recall"] == {"ran": true, "counts": [1], "ok": true}` on the final draft; `tmp/detections/office_app_spawns_encoded_powershell.yml` validates as `Detection`; `status == "experimental"` (`status_cap` set because the idea has no attack examples); search ends with `` `office_app_spawns_encoded_powershell_filter` ``; `macros/office_app_spawns_encoded_powershell_filter.yml` exists; no `.conf` file is written.
- `cli.main(["publish", tmp/"detections", "--splunk", "mock"]) == 0` and `published.conf` contains `[office_app_spawns_encoded_powershell_filter]\ndefinition = search *` **before** `[Office app spawns encoded PowerShell]`, `is_scheduled = 1` and `cron_schedule = */15 * * * *`.
- Second scenario in the same file: `fake_llm("tests/fixtures/llm_noisy")` and `runs.json` replaced by all-noisy entries → `rc == 3`, `state == "failed_noisy"`, 2 author + 6 tune fake calls, `failed_attempts` has 4 entries.
- Third scenario: idea with `log_sources[*].keywords = ["nonexistent"]` → `rc == 2`, `state == "infeasible"`, zero llm calls, `coverage.md` exists.
All scenarios pass `--inventory tmp/"inventory.json" --refresh` so no repo-level `inventory.json` is read or written.

### 11.4 CI — `.github/workflows/ci.yml`
- job `test` (ubuntu, `astral-sh/setup-uv`, `uv python install 3.13`, `uv sync --group dev`, `uv run pytest -q`).
- job `publish` (on push to `main`, needs `test`): job-level `env: SPLUNK_HOST: ${{ secrets.SPLUNK_HOST }}`, `SPLUNK_TOKEN: ${{ secrets.SPLUNK_TOKEN }}`; the single step `uv run dea publish detections/ --splunk real ${{ vars.DEA_ES == '1' && '--es' || '' }}` is guarded with `if: env.SPLUNK_TOKEN != '' && hashFiles('detections/*.yml') != ''` (the `secrets` context is not available in a job-level `if`; the `hashFiles` guard keeps the first push to `main` green before any detection is committed; repository variable `DEA_ES=1` enables Enterprise Security keys).
No contentctl job: the YAML is contentctl-shaped by construction (§4.4 enums, two drilldowns, no rba for Hunting) and validated by the `Detection` model; a user who wants `contentctl validate` drops the files into a `contentctl init` repo by hand (README). `dea run` is an operator step (OAuth claude login) and never runs in CI. There are no live tests; `uv run pytest -q` needs no network, `claude` binary or Splunk (CONTRIBUTING.md).

---

## 12. Module build order and interfaces

Items in the same tier touch disjoint files and can be built in parallel. Each item is complete only when its acceptance test passes with `uv run pytest tests/<file> -q`.

### Tier 0 — foundation (sequential, one implementer)

**0.1 Project scaffold** — files: `pyproject.toml`, `.python-version`, `.gitignore`, `README.md`, `src/detection_engineering_agent/__init__.py`, `tests/conftest.py` (fixture names only; bodies may import modules that appear later — use lazy imports inside fixtures), all `tests/fixtures/**` files listed in §2 (content per §11.1; the LLM fixture SPLs must satisfy the lint rules against the fixture inventory and be unique per scenario). Deps: none. Acceptance: `uv sync --group dev` succeeds; `uv run python -c "import detection_engineering_agent"`; every fixture JSON/YAML parses.

**0.2 Contracts** — file: `src/detection_engineering_agent/models.py` (data classes only: `LogSource`, `AttackExample`, `Idea` (+`stem`, `threshold`, `load`), `Sourcetype`, `Index`, `Inventory` (+helpers), `Source`, `Example`, `Draft`, `ReviewRound`, `IdeaDraft`, `IdeasOut`, `SplOut`, `Finding`, `EvasionEvent`, `ReviewOut`, `Detection` and its sub-models `Drilldown`, `RiskObject`, `ThreatObject`, `Rba`, `Tags`, `Throttling`, `Test`, `AttackData`; `SOURCETYPE_META`; `schema(model) -> dict`). Deps: 0.1. Acceptance: `test_models.py` validation and schema cases (rendering cases are added by 1.4).

### Tier 1 — independent modules (parallel)

**1.1 SPL helpers** — file: `spl.py`. Public: `normalise, runnable, with_filter, window_seconds, referenced_fields, derived_fields, group_fields, indexes_in, sourcetypes_in, exclusions, bucketed, Lint(BaseModel: errors, warnings), lint(spl, inventory, stem, sources: list[str]) -> Lint, top_values, high_cardinality, project, rewrite_index` (§7.3). Deps: 0.2 (`Inventory`). Acceptance: `test_spl.py`.

**1.2 Inference wrapper** — files: `prompts.py`, `llm.py`. Public: `prompts.SYSTEM, INPUTS, MODEL, EFFORT, RULES, SCHEDULE`; `llm.ask(step, payload, out, model=None, effort=None) -> tuple[T, float]`, `llm.LLMError`, `llm.CostCapExceeded` (§6). Deps: 0.2 (`schema`). Acceptance: `test_llm.py`.

**1.3 Splunk adapter** — file: `splunk.py`. Public: `Run`, `Splunk` Protocol, `MockSplunk(fixture_dir)`, `RealSplunk.from_env()`, `get(kind=None)` (§8). Deps: 0.2 (`Inventory`). Acceptance: `test_splunk.py`.

**1.4 Rendering** — file: `models.py` (append only: `Detection.from_run(idea, draft, sources, findings, status, out_dir) -> Detection`, `Detection.severity` property, `to_yaml`, `conf_props(es=False)`, `macro_yaml(stem)`, `SEVERITY_ALERT`, `SEVERITY_SCORE`, risk/threat field tables) (§7.5). Imports `spl.with_filter` lazily (1.1 may land simultaneously; tests for 1.4 run after 1.1). Deps: 0.2, 1.1. Acceptance: rendering cases in `test_models.py`.

### Tier 2 — orchestration

**2.1 Pipeline** — file: `pipeline.py`. Public: `Config(BaseModel)`, `PipelineState(BaseModel)`, `STATE_FIELDS`, `STATES`, `TRANSITIONS`, `NEXT`, `TERMINAL`, `EXIT_CODES = {"done":0,"error":1,"infeasible":2,"failed_noisy":3,"failed_review":4}`, `event_fields(raw) -> set[str]`, `strip_fields(raw, names) -> str` (§5.5), `class Pipeline(idea: Idea, inventory: Inventory, splunk: Splunk, config: Config, run_dir: Path, idea_path: str)` with `drive() -> str`, `save()`, `classmethod load(run_dir, idea, inventory, splunk, config) -> Pipeline`, step callbacks `do_match, do_author, do_test, do_tune, do_review, do_refine, do_render`, guards/callbacks of §5.3, `_ask(step, payload, out, model=None, effort=None)` (resolves the model per §6.1 precedence, wraps `llm.ask`, adds cost, raises `CostCapExceeded` when `cost_usd > config.max_cost_usd`, appends history). Deps: 1.1, 1.2, 1.3, 1.4. Acceptance: `test_pipeline.py`.

### Tier 3 — surface

**3.1 CLI + ideas tool** — file: `cli.py`. Public: `main(argv=None) -> int`, `ideas(src, out_dir, model=None) -> list[Path]`, `extract_text(src) -> tuple[str, str]` (text, source_url), `load_inventory(path, splunk, window, refresh, max_age_h=24) -> Inventory`, `publish(paths, splunk, es, dry_run) -> int`. Deps: 2.1, 1.2, 1.3. Acceptance: `test_cli.py`, `test_e2e.py`.

**3.2 CI workflow** — file: `.github/workflows/ci.yml` (§11.4). Deps: 3.1 for the publish job to mean anything; can be authored in parallel with 3.1. Acceptance: `actionlint`-clean YAML; `test` job runs `uv run pytest -q`.

---

## 13. Non-goals

- No agentic loop, no model-chosen next step (not even a verdict field), no tool use inside inference calls, no chat history between calls.
- No inference for: source selection, metadata prose, group/used field extraction, lint, counting, thresholds, rendering, publishing.
- No SPL parser or mock SPL evaluator; Splunk itself is the parser (its ERROR messages are routed into the tuner), regex lint is the only local check.
- No Sigma export, no contentctl dependency or CI job, no `contentctl build`/`deploy_acs`, no app tarball, no `savedsearches.conf`/`macros.conf` file, no Splunk Cloud ACS deploy (publish = macro + saved-search REST only; `--es` adds notable/risk/correlation keys).
- No datamodel-aware authoring or `tstats` field inventory (tstats searches get lint warnings, not errors).
- No cron-by-severity, no per-severity noise thresholds (per-type default + per-idea override only).
- No chunking of articles longer than 100 000 chars (head-truncated with a warning), no multi-article merging.
- No HEC ingestion; the recall gate uses `index.submit()` only and runs only when attack examples (from the idea or from review) exist. No cleanup of the attack index (per-run host prefixes make stale events inert).
- No environment-variable overrides for models or LLM fixtures; no `dea status` subcommand.
- No live tests in CI; `dea run` never runs in CI (OAuth `claude` login is an operator-workstation concern).
- No web UI, no database, no concurrency; one idea per `dea run` invocation.
