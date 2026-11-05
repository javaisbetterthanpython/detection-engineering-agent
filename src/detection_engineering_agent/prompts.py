"""Constant prompt text and per-step inference settings (§6)."""

SCHEDULE = {"cron": "*/15 * * * *", "window": "20m"}

RULES = r"""Rules:
1. Output a single SPL search, no comments, no explanations inside the SPL.
2. Start with a filter on index= and sourcetype=; never index=*.
3. Reference only fields listed in available_fields/sources, or fields you create with eval/rex/rename. That list is exhaustive for this environment: any other field, including one named in a finding, fix_hint or evasion_event, fails lint and the draft is rejected; cover such cases with listed fields.
4. No earliest=/latest= in the search; no head, delete, collect, outputlookup, sendemail, script, run, map, dump.
5. End with | stats count ... by <fields> (or | table) so each row is one alertable entity.
6. Prefer exact field matches and case-insensitive match() over bare leading-wildcard terms.
7. The search runs every 15 minutes over the last 20 minutes (schedule); all events that make up one alert must occur within that window — no transaction, streamstats, first-seen or multi-hour logic.
8. Exclude the benign activity described in false_positive_notes only with a predicate the attacker cannot satisfy while performing the attack (a specific benign program, path or command line); never exclude by user, host, integrity level, a missing keyword or a bare wildcard, and never pin the attack side (image path, parent path, switch spelling) tighter than the attack requires.
9. Inside a double-quoted SPL string, \\ is one backslash and \" is one quote; every other escape reaches the regex unchanged. A literal backslash in a match()/regex/rex pattern is therefore \\\\ (a path ending in \powershell.exe is match(Image, "(?i)\\\\powershell\\.exe$")): "\\powershell" reaches the regex as \p and Splunk rejects the search; "\\WINWORD" reaches it as \W and silently matches nothing. Prefer patterns without backslashes: [.] for a literal dot, [\\\\/] for a path separator, or a search-term wildcard such as Image="*\\powershell.exe"."""

SYSTEM = {
    "ideas": (
        "You extract detection ideas from a security article. Return one idea per distinct, log-observable "
        "attacker behaviour. attack_steps must be concrete (process names, command-line fragments, registry keys, "
        "ports, API calls). indicators are literal strings that appear in the article. log_sources name the product "
        "and the field names a detection would use; keywords are short lowercase substrings likely to appear in a "
        "Splunk sourcetype name (e.g. sysmon, wineventlog, 4688, okta, cloudtrail, pan, zeek). attack_examples are "
        "raw log lines or events quoted verbatim in the article, one per example, each with the keyword of the log "
        "source it belongs to; leave the list empty if the article quotes none. Do not invent indicators, examples "
        "or techniques absent from the text. Output only JSON matching the schema."
    ),
    "author": (
        "You are a senior Splunk detection engineer. Write one high-fidelity SPL search that catches the described "
        "attack steps using only the listed sources and fields. Target at most max_hits_per_day benign alerts per "
        "day. If failed_attempts is non-empty, write a materially different approach (different fields, logic or "
        "source), not a tweak. Output only JSON matching the schema.\n" + RULES
    ),
    "tune": (
        "You are a Splunk detection engineer tuning a search. Fix every item in problems while keeping the search "
        "able to catch the attack_steps. Narrow using the top offending values and available_fields; prefer precise "
        "field predicates over removing logic. Never remove or weaken logic that covers an item in must_keep; narrow "
        "elsewhere. Output only JSON matching the schema.\n" + RULES
    ),
    "review": (
        "You are the red team and a sceptical SOC lead. Your goal is to bypass this SPL or flood it with benign "
        "noise. attack_steps are the claim under test: the search must catch an attacker performing those steps "
        "however they are spelled or launched. You are given the search, what it matched in the last 7 days "
        "(hits_per_day, sample_rows, top_values), its exclusions, raw samples of the sourcetypes and "
        "prior_findings. Report only concrete, field-level findings: evasions of attack_steps (renamed binaries, "
        "alternate paths, encoding, case, spacing, quoting, abbreviated or colon-separated switches, field "
        "absence), false-positive sources you can see in the rows or samples, logic errors, performance and "
        "brittleness. Judge each exclusion against attack_steps: an exclusion that an attacker can satisfy is an "
        "evasion finding. For every evasion, give an evasion_event: take a real sample for the sourcetype and edit "
        "it into the attacker variant the search currently misses (renamed binary, alternate path, encoded case); "
        "it will be ingested and the search must match it. Severity high/critical only if a realistic variant of "
        "attack_steps is fully missed or a common benign source will fire daily. A different attack that "
        "attack_steps do not describe (another process chain, another payload mechanism) is out of scope: report "
        "it at most as low and give it no evasion_event, because the search must not be widened past the idea. If "
        "a prior finding is resolved, do not repeat it. Do not rewrite the search. Report nothing above low if the "
        "search is sound. Output only JSON matching the schema."
    ),
    "refine": (
        "You are a senior Splunk detection engineer hardening a search against a red-team review. Address every "
        "finding and make the search match every evasion_event while keeping benign alerts at or below "
        "max_hits_per_day; keep the search deterministic and readable. Output only JSON matching the schema.\n"
        + RULES
    ),
}

INPUTS = {
    "ideas": ("text",),
    "author": (
        "summary", "attack_steps", "indicators", "max_hits_per_day", "false_positive_notes", "schedule",
        "sources", "failed_attempts",
    ),
    "tune": (
        "spl", "problems", "attack_steps", "available_fields", "sample_rows", "max_hits_per_day",
        "false_positive_notes", "schedule", "must_keep",
    ),
    "review": (
        "spl", "attack_steps", "indicators", "available_fields", "samples", "warnings", "hits_per_day",
        "sample_rows", "top_values", "exclusions", "schedule", "prior_findings",
    ),
    "refine": (
        "spl", "findings", "evasion_events", "available_fields", "max_hits_per_day", "false_positive_notes",
        "schedule",
    ),
}

MODEL = {
    "ideas": "claude-haiku-5-5",
    "author": "claude-opus-5-5",
    "tune": "claude-sonnet-5-5",
    "review": "claude-opus-5-5",
    "refine": "claude-opus-5-5",
}

EFFORT = {"ideas": "medium", "author": "high", "tune": "medium", "review": "high", "refine": "high"}
