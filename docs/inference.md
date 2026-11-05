# Inference

Every model call in `dea` goes through one function, `llm.ask(step, payload, out, model=None, effort=None)`, which runs the local `claude -p` CLI once and returns `(validated pydantic object, cost_usd)`. There is no SDK, no API key, no session and no tool use. [SPEC.md §6](SPEC.md) is the law; the prompt text lives in [`src/detection_engineering_agent/prompts.py`](../src/detection_engineering_agent/prompts.py) and is not duplicated here.

## The subprocess

Verbatim from `llm.py`:

```python
argv = ["claude", "-p",
        "--model", model or prompts.MODEL[step], "--effort", effort or prompts.EFFORT[step],
        "--tools", "", "--max-turns", "2",
        "--setting-sources", "", "--no-session-persistence", "--disable-slash-commands",
        "--max-budget-usd", "2.00",
        "--system-prompt", prompts.SYSTEM[step],
        "--output-format", "json",
        "--json-schema", json.dumps(models.schema(out))]
stdin = json.dumps(payload, ensure_ascii=False)
```

- `--tools ""`: the model has no tools. It sees the system prompt and the payload JSON on stdin, nothing else: no CLAUDE.md (`--setting-sources ""`), no history (`--no-session-persistence`), no slash commands.
- `--json-schema`: the schema is `Model.model_json_schema()` of the output model below; the CLI returns `structured_output`, which is validated again by pydantic.
- `--max-turns 2`, not 1: the structured output is delivered through a tool call that counts as a turn.
- `--max-budget-usd 2.00` caps one call; `timeout=600` seconds per subprocess.
- The payload goes to stdin, never argv (an `ideas` payload is up to 100,000 characters).
- Failure handling: a non-zero exit, `subtype != "success"`, `is_error`, a missing `structured_output` or a pydantic validation error triggers exactly one retry with the same argv and input; a second failure raises `LLMError`, which the pipeline turns into the `error` terminal. The error text includes the CLI's `api_error_status` and `result` when stderr is empty (an unsupported model id is reported that way).

Before any subprocess starts, `ask` rejects a payload with a key outside `prompts.INPUTS[step]` (`ValueError`). This is the whole-system guarantee that each call receives exactly the fields listed below.

## The five calls

| step | where | model (default) | effort | payload keys (`prompts.INPUTS`) | output model |
|---|---|---|---|---|---|
| `ideas` | `dea ideas` (not in the pipeline) | `claude-haiku-5-5` | medium | `text` | `IdeasOut` |
| `author` | `do_author`; first draft and remake | `claude-opus-5-5` | high | `summary`, `attack_steps`, `indicators`, `max_hits_per_day`, `false_positive_notes`, `schedule`, `sources`, `failed_attempts` | `SplOut` |
| `tune` | `do_tune`; noisy or broken draft | `claude-sonnet-5-5`; the author model at effort high on the last allowed round | medium | `spl`, `problems`, `attack_steps`, `available_fields`, `sample_rows`, `max_hits_per_day`, `false_positive_notes`, `schedule`, `must_keep` | `SplOut` |
| `review` | `do_review`; clean draft | `claude-opus-5-5` | high | `spl`, `attack_steps`, `indicators`, `available_fields`, `samples`, `warnings`, `hits_per_day`, `sample_rows`, `top_values`, `exclusions`, `schedule`, `prior_findings` | `ReviewOut` |
| `refine` | `do_refine`; after a review with findings above low | `claude-opus-5-5` | high | `spl`, `findings`, `evasion_events`, `available_fields`, `max_hits_per_day`, `false_positive_notes`, `schedule` | `SplOut` |

Payload values, as the pipeline builds them:

- `max_hits_per_day` = `idea.threshold` (the resolved number); `schedule` = `{"cron": "*/15 * * * *", "window": "20m"}`; `false_positive_notes` = the idea's text or null.
- `sources` (author) = `[{index, sourcetype, fields: {name: [up to 3 top values]}, sample}]` for every matched source, or, once examples have been ingested, only the matched sources whose sourcetype an ingested example carries (recall runs every example, so a remake on another sourcetype could never pass it); `sample` is the inventory's one raw event per sourcetype (at most 600 characters).
- `available_fields` = the inventory's field map merged over the sourcetypes the SPL names (fallback: all matched sources); `samples` (review) = the raw sample per such sourcetype.
- `problems` and `sample_rows` (tune), `hits_per_day`, `sample_rows`, `top_values`, `warnings` (review): from `gates`, see [gates.md](gates.md). `exclusions` = `spl.exclusions(spl)`: every `NOT field=value`, `field!=value`, `NOT (...)` group and `where ... NOT ...` segment, verbatim.
- `must_keep` (tune) = the `note` of every evasion event of every review round so far, oldest first; never finding details.
- `failed_attempts` (author) = `[{spl, reason}]` of the abandoned line after a remake, else `[]`.
- `prior_findings` (review) = `{category, severity, detail}` of the previous round, else `[]`.
- `findings` (refine) = the last round's findings, high and critical first; `evasion_events` = every round's events after the field guard, with the sourcetype each was ingested under.

Output models (`models.py`): `SplOut {spl}`; `ReviewOut {findings: [Finding], evasion_events: [EvasionEvent]}` with `Finding {category: evasion|false_positive|logic|performance|brittleness, severity: low|medium|high|critical, detail, fix_hint}` and `EvasionEvent {sourcetype, raw, note}`; `IdeasOut {ideas: [IdeaDraft]}`. There is no verdict field anywhere: routing after a review is computed from the severities in `findings` ([pipeline.md](pipeline.md)).

## Rules sent to every authoring call

`prompts.RULES`, appended verbatim to the `author`, `tune` and `refine` system prompts:

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

The `review` prompt binds severity to the idea: `attack_steps` is the claim under test, every variant of it (renamed binary, path, encoding, case, spacing, quoting, abbreviated or colon-separated switch, missing field) keeps full severity and gets an evasion event, and an attack the steps do not describe is reported at most as low with no event. Runs 2 to 4 ([development/e2e-findings.md](development/e2e-findings.md), [development/build-log.md](development/build-log.md)) are why: an unbounded finding space against two review rounds is `failed_review` by construction.

## Models, overrides and cost

Precedence in `Pipeline._ask`: explicit argument (only the tune ladder uses it) > `config.models[step]` from `--model STEP=MODEL` > `prompts.MODEL[step]`. `STEP` must be one of `ideas`, `author`, `tune`, `review`, `refine`; `dea ideas --model NAME` takes the model name directly. There is no environment-variable override.

Known limit: `claude-opus-5-5` needs Claude Code 2.1.280 or newer; the machine that produced run 5 had 2.1.198, which rejects it, so run 5 used `--model author=claude-opus-4-8 --model review=claude-opus-4-8 --model refine=claude-opus-4-8` (recorded in `config.models` of its state file). Run `claude update`, or pass those overrides.

Cost: `total_cost_usd` from each CLI envelope is added to `cost_usd` and logged in `history` per step. When the total exceeds `--max-cost` (default 5.0) `_ask` raises `CostCapExceeded`, which ends the run in `error`; `--resume --max-cost <higher>` continues it. Run 5 cost $1.30 over 8 calls: author $0.02, two tunes $0.02 each, three reviews $0.22, $0.26 and $0.20, two refines $0.19 and $0.39. Review and refine are the expensive calls because their payloads carry raw samples, sample rows and top values.

## What leaves the machine

For [SECURITY.md](../SECURITY.md): the `claude -p` process receives the idea's `summary`, `attack_steps`, `indicators` and `false_positive_notes`; the matched sourcetypes' field names with up to three top values each; one raw sample event per sourcetype (600 characters); the gate's sample rows and top values; the draft SPL; and, for `ideas`, the article text. Nothing else is in any payload, and `llm.ask` rejects any other key.
