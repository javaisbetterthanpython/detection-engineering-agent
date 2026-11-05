# Example walkthrough: Office app spawns encoded PowerShell

Provenance: run 5 · 2026-11-05 · mock Splunk fixtures · real Claude inference · $1.30. Every value on this page is copied from [`examples/office_app_spawns_encoded_powershell/`](examples/office_app_spawns_encoded_powershell/) (the run's `state.json`, rendered files and `publish --dry-run` output) or from `tests/fixtures/`. Nothing is paraphrased; long blocks are collapsed.

What is real and what is scripted: the models (`claude-opus-4-8` for author, review and refine because the installed Claude Code 2.1.198 rejects `claude-opus-5-5`; `claude-sonnet-5-5` for tune) wrote every SPL draft, every finding and every evasion event, and the costs are the CLI's `total_cost_usd`. The Splunk side is the mock adapter: hit counts come from `tests/fixtures/splunk/runs.json` in call order and every recall check returns `recall.json`'s `1`. The mock does not evaluate SPL. Rerun against a real Splunk ([splunk-test-server.md](splunk-test-server.md)) to make the numbers mean something.

## In: the idea

`tests/fixtures/idea.yml`, unchanged:

```yaml
id: 3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11
title: Office app spawns encoded PowerShell
source_url: https://thedfirreport.com/2026/10/30/example/
summary: >-
  A malicious Word macro launches powershell.exe with -EncodedCommand to fetch a second stage.
attack_steps:
  - "winword.exe or excel.exe or outlook.exe spawns powershell.exe"
  - "powershell.exe command line contains -enc or -EncodedCommand followed by base64"
indicators: ["-EncodedCommand", "-enc ", "powershell.exe"]
mitre_attack_id: [T1059.001, T1566.001]
type: TTP
severity: high
log_sources:
  - product: Windows Sysmon
    keywords: [sysmon]
    fields: [EventCode, Image, ParentImage, CommandLine]
  - product: Windows Security
    keywords: [wineventlog, security, "4688"]
    fields: [EventCode, New_Process_Name, Creator_Process_Name, Process_Command_Line]
sourcetypes: []
max_hits_per_day: null
false_positive_notes: Admin scripts launched from Office automation in finance.
attack_examples: []
attack_data_url: null
```

## Match

The fixture inventory (`tests/fixtures/splunk/inventory.json`) has two indexes and three sourcetypes:

| index | sourcetype | events in -7d | fields |
|---|---|--:|---|
| `wineventlog` | `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational` | 912000 | `EventCode`, `Image`, `ParentImage`, `CommandLine`, `ParentCommandLine`, `User`, `Computer`, `IntegrityLevel` |
| `wineventlog` | `WinEventLog:Security` | 640000 | `EventCode`, `New_Process_Name`, `Creator_Process_Name`, `Process_Command_Line`, `Account_Name`, `ComputerName` |
| `proxy` | `squid:access` | 2210000 | `src_ip`, `dest_ip`, `url`, `http_method`, `status`, `bytes`, `user`, `http_user_agent` |

`do_match` scores each sourcetype as `keyword hits * 10 + field overlap` over the idea's `log_sources` and keeps the top four with at least one keyword hit. `squid:access` matches no keyword and is dropped. The two Windows sourcetypes tie at 24: the Sysmon name contains `sysmon` and `wineventlog` (2 hits, 20) and carries 4 of the wanted fields (`EventCode`, `Image`, `ParentImage`, `CommandLine`); `WinEventLog:Security` contains `wineventlog` and `security` (20) and carries 4 (`EventCode`, `New_Process_Name`, `Creator_Process_Name`, `Process_Command_Line`). From `state.json`:

```json
[
  {
    "index": "wineventlog",
    "sourcetype": "XmlWinEventLog:Microsoft-Windows-Sysmon/Operational",
    "score": 24,
    "data_source": "Sysmon EventID 1",
    "asset_type": "Endpoint",
    "security_domain": "endpoint"
  },
  {
    "index": "wineventlog",
    "sourcetype": "WinEventLog:Security",
    "score": 24,
    "data_source": "Windows Event Log Security 4688",
    "asset_type": "Endpoint",
    "security_domain": "endpoint"
  }
]
```

The idea has no `attack_examples`, so `status_cap` is set to `experimental` here and the recall gate has nothing to check until the first review.

## Drafts

Five drafts. `origin` says which call wrote it; the gate column is the mock's scripted count for that call (`runs.json`: 412, 60, 2, 1, then 1 repeating) turned into a rate over `-7d` against the TTP threshold of 5 per day. The last column is a reading of the diff between consecutive drafts.

| draft | origin | model | gate | what changed |
|--:|---|---|---|---|
| 1 | author | `claude-opus-4-8` | 412 → 58.9/day > 5, noisy | `Image` pinned to `*\\powershell.exe`; ParentImage regex for winword/excel/outlook; CommandLine `\s-enc(odedcommand)?\s+[A-Za-z0-9+/=]{10,}` |
| 2 | tune | `claude-sonnet-5-5` | 60 → 8.6/day > 5, noisy | all three predicates become `match()` calls; switch regex `-e(nc\|ncodedcommand)?`, still a 10-character base64 floor |
| 3 | tune | `claude-sonnet-5-5` | 2 → 0.29/day, clean | moves the predicates into `\| where`; switch list `-(e\|enc\|ec\|encodedcommand)`; base64 floor raised to 20; adds `NOT ... -(file\|f) ... .ps1` to exclude script launches |
| 4 | refine | `claude-opus-4-8` | 1 → 0.14/day, clean | after review 1: drops the `Image` pin (renamed copies), drops the attacker-satisfiable `-file` exclusion, adds a ParentImage pre-filter to the base search, switch by prefix `-e[a-z]*` with `[:\s]+` separator |
| 5 | refine | `claude-opus-4-8` | 1 → 0.14/day, clean; recall 6/6 | after review 2: `[-/]` so `/enc` is caught, optional quote `[\"']?` before the base64 |

**Draft 1** (author); group fields `Computer, User, ParentImage, Image`; fields used `CommandLine, Computer, EventCode, Image, ParentImage, User`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 Image="*\\powershell.exe" (match(ParentImage, "(?i)\\\\(winword|excel|outlook)\\.exe$")) (match(CommandLine, "(?i)\\s-enc(odedcommand)?\\s+[A-Za-z0-9+/=]{10,}")) | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

**Draft 2** (tune); group fields `Computer, User, ParentImage, Image`; fields used `CommandLine, Computer, EventCode, Image, ParentImage, User`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 match(Image, "(?i)\\\\powershell\.exe$") match(ParentImage, "(?i)\\\\(winword|excel|outlook)\.exe$") match(CommandLine, "(?i)\s-e(nc|ncodedcommand)?\s+[A-Za-z0-9+/=]{10,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

**Draft 3** (tune); group fields `Computer, User, ParentImage, Image`; fields used `CommandLine, Computer, EventCode, Image, ParentImage, User`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 | where match(Image, "(?i)\\\\powershell\.exe$") AND match(ParentImage, "(?i)\\\\(winword|excel|outlook)\.exe$") AND match(CommandLine, "(?i)\s-(e|enc|ec|encodedcommand)\s+[A-Za-z0-9+/=]{20,}") AND NOT match(CommandLine, "(?i)\s-(file|f)\s+\S+\.ps1") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

**Draft 4** (refine); group fields `Computer, User, ParentImage, Image`; fields used `CommandLine, Computer, EventCode, Image, ParentImage, User`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s-e[a-z]*[:\\s]+[A-Za-z0-9+/=]{20,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

**Draft 5** (refine); group fields `Computer, User, ParentImage, Image`; fields used `CommandLine, Computer, EventCode, Image, ParentImage, User`

```spl
index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s[-/]e[a-z]*[:\\s]+[\"']?[A-Za-z0-9+/=]{20,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image
```

## Review rounds

Three rounds, on drafts 3, 4 and 5. Every finding and every evasion event is verbatim from `review_log`. Round 1's four events and round 2's two were ingested into `dea_attack` under hosts `dea-c5c9d0ae-0` to `dea-c5c9d0ae-5` (the `examples` list) before the `refine` call that followed each round, and every later `test` searched for all of them. Round 3's single event was never ingested: no refine followed it.

### Round 1 (draft 3)

| severity | category | detail | fix_hint |
|---|---|---|---|
| high | evasion | The switch regex `-(e\|enc\|ec\|encodedcommand)` only enumerates four spellings, but PowerShell accepts any unambiguous prefix of -EncodedCommand. Variants such as -en, -enco, -encod, -encode, -encoded, -encodedc, -encodedco, -encodedcom, -encodedcomm, -encodedcomma, -encodedcomman are all honored by powershell.exe and none of them match, so an attacker performing the exact attack_step (office -> powershell with -EncodedCommand base64) is fully missed by choosing e.g. `-enco`. | Match the switch by prefix instead of fixed list, e.g. (?i)\s-e(n(c(o(d(e(d(c(o(m(m(a(n(d)?)?)?)?)?)?)?)?)?)?)?)?)?\s+ or a broader `\s-e[a-z]*\s+[A-Za-z0-9+/=]{20,}` anchored to the encoded-command family. |
| high | evasion | The exclusion `AND NOT match(CommandLine, '(?i)\s-(file\|f)\s+\S+\.ps1')` is attacker-controllable. The CommandLine only has to CONTAIN a ` -f something.ps1` substring to suppress the alert; an attacker can append a harmless decoy token (e.g. ` -f c:\x.ps1`) after the real `-enc <base64>` payload, or the PowerShell format operator `-f "...ps1"` inside a string, and the whole detection is dropped while the encoded command still executes. | Do not use a negative CommandLine filter to distinguish file vs encoded launches; instead gate positively on presence of the encoded-command switch only, and drop the -file/-f exclusion (an encoded command and -File are mutually exclusive anyway). |
| medium | evasion | The regex requires whitespace after the switch (`\s+[A-Za-z0-9+/=]`). PowerShell also accepts colon-delimited parameter syntax, e.g. `-enc:<base64>` or `-e:<base64>`, which contains no space before the value and therefore never matches. | Allow a colon or equals separator: `(?i)\s-e[a-z]*[:\s]+[A-Za-z0-9+/=]{20,}`. |
| medium | evasion | Detection keys only on Image ending in \powershell.exe. Sysmon EventID 1 also carries OriginalFileName, which remains PowerShell.EXE when the binary is copied/renamed (e.g. office macro drops %TEMP%\svc.exe = copy of powershell.exe and spawns it with -enc). Such a renamed-but-still-PowerShell launch from winword/excel/outlook satisfies the attack idea yet Image never matches. | Also test OriginalFileName, e.g. match(OriginalFileName,'(?i)^PowerShell\.EXE$') OR match(Image,...), so renamed copies of powershell.exe are caught. |
| low | performance | The base search retrieves every Sysmon EventCode=1 event and applies four regex via `where match()` with no index-time string pre-filter. On a busy fleet this scans all process-creation events every 15 minutes. Adding cheap CommandLine/ParentImage keyword filters in the base search would prune the dataset before regex. | Add `CommandLine="*powershell*" (ParentImage="*winword*" OR ParentImage="*excel*" OR ParentImage="*outlook*")` to the base search before the where/match stage. |
| low | logic | ParentImage is limited to winword\|excel\|outlook, which matches attack_steps. Other common Office payload launchers (powerpnt.exe, mshta, wscript spawned by Office) are a different chain and out of scope here; noting only that the list is narrow relative to real Office-to-PowerShell abuse. | If desired later, extend the Office parent list, but do not widen past the stated attack_steps for this rule. |

4 evasion event(s):

<details>
<summary>1. Abbreviated-prefix switch -enco (valid PowerShell prefix of -EncodedCommand) is not in the regex alternation (e|enc|ec|encodedcommand), so this office->powershell encoded launch is missed.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS01.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enco SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=</Data><Data Name='User'>CORP\jdoe</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n</Data></EventData></Event>
```

</details>

<details>
<summary>2. Real -enc base64 payload, but a decoy <code> -f c:\decoy.ps1</code> substring triggers the NOT -(file|f) ...\.ps1 exclusion and suppresses the alert.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS04.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA= -f c:\decoy.ps1</Data><Data Name='User'>CORP\bwayne</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\OUTLOOK.EXE"</Data></EventData></Event>
```

</details>

<details>
<summary>3. Colon-delimited parameter syntax -enc:&lt;base64&gt; has no whitespace before the value, so the \s+[A-Za-z0-9+/=]{20,} requirement fails and the event is missed.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS01.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc:SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=</Data><Data Name='User'>CORP\jdoe</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\EXCEL.EXE"</Data></EventData></Event>
```

</details>

<details>
<summary>4. Office macro copies powershell.exe to a renamed path and launches it with -enc; OriginalFileName is still PowerShell.EXE but Image no longer ends in powershell.exe, so the Image regex misses it.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS04.corp.local</Computer></System><EventData><Data Name='Image'>C:\Users\Public\svc.exe</Data><Data Name='OriginalFileName'>PowerShell.EXE</Data><Data Name='CommandLine'>"C:\Users\Public\svc.exe" -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAA=</Data><Data Name='User'>CORP\bwayne</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"</Data></EventData></Event>
```

</details>

### Round 2 (draft 4)

| severity | category | detail | fix_hint |
|---|---|---|---|
| high | evasion | The CommandLine regex `(?i)\s-e[a-z]*[:\s]+[A-Za-z0-9+/=]{20,}` requires the character immediately after the switch separator to be a base64 character. PowerShell accepts the encoded blob wrapped in quotes (e.g. `-enc "<base64>"`, also single quotes), which it strips before decoding. When the value is quoted, the char after `[:\s]+` is `"` (not in `[A-Za-z0-9+/=]`), so the match fails and the exact attack_step (office -> powershell -enc base64) is fully missed. This is independent of the four prior findings. | Allow an optional quote between the separator and the base64, e.g. `[:\s]+[\"']?[A-Za-z0-9+/=]{20,}`, or extract/normalise the -enc argument value before matching. |
| medium | evasion | The switch pattern hardcodes a hyphen (`\s-e[a-z]*`). powershell.exe also honours the forward-slash parameter prefix, so `powershell /enc <base64>` (or `/e`, `/encodedcommand`) executes the same encoded payload but never matches because the regex only looks for `-e`. A realistic variant of the attack_step is fully missed. | Accept either prefix in the regex, e.g. `\s[-/]e[a-z]*[:\s]+...`. |
| low | brittleness | Detection relies solely on ParentImage office filter plus the CommandLine `-e*` regex and places no constraint on Image/OriginalFileName. This correctly catches renamed-powershell children (good, resolving the prior Image-only concern), but it also means any office-parented child whose CommandLine happens to carry a 20+ char token after a `-e...` switch will fire; no benign source is visible in the rows, so impact is low. | Optionally add an OriginalFileName=PowerShell.EXE OR Image ...powershell.exe assertion to reduce incidental matches while keeping rename coverage. |
| low | logic | ParentImage is limited to winword\|excel\|outlook, matching attack_steps. Other Office launchers (powerpnt.exe, mshta/wscript spawned by Office) are a different chain and out of scope; noted only as narrow coverage, no change requested. | No action required within the current attack idea. |

2 evasion event(s):

<details>
<summary>1. WINWORD spawns powershell with -enc and the base64 wrapped in double quotes. The quote sits where the regex expects a base64 char ([:\s]+ then [A-Za-z0-9+/=]), so match() fails and the alert is dropped though the encoded command still runs.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS01.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -enc "SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA="</Data><Data Name='User'>CORP\jdoe</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n</Data></EventData></Event>
```

</details>

<details>
<summary>2. WINWORD spawns powershell using the forward-slash prefix /enc instead of -enc. PowerShell honours /enc identically, but the regex only matches <code>\s-e</code>, so this is missed.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS01.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" /enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAKQA=</Data><Data Name='User'>CORP\jdoe</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n</Data></EventData></Event>
```

</details>

### Round 3 (draft 5)

| severity | category | detail | fix_hint |
|---|---|---|---|
| medium | evasion | The CommandLine regex floors the base64 blob at 20 characters (`[A-Za-z0-9+/=]{20,}`). PowerShell encoded commands for short payloads are well under 20 chars: a short bootstrap/stager such as `-enc` of a 4-8 char command encodes to ~12-16 base64 chars. e.g. `calc` in UTF-16LE base64 is `YwBhAGwAYwA=` (12 chars), and a terse download/`iex` one-liner stager can also be crafted short. An office->powershell -enc chain (the exact attack_step) with a short encoded value is fully missed. The floor is purely a noise guard an attacker can stay under. | Lower the minimum token length (e.g. {8,} or {4,}), or key the detection on the presence of the `-e*`/`/e*` encoded switch itself (Image=powershell + switch) rather than on blob length. |
| low | logic | The switch regex matches a single prefix char `[-/]e[a-z]*`. PowerShell 7 (pwsh.exe) and some invocations honour the POSIX double-dash form `--encodedcommand <b64>`; `\s--encodedcommand` would see `-` then `-` (not `e`) and fail. attack_steps name powershell.exe specifically and 5.1 does not accept `--`, so this is narrow/edge coverage only; no change requested. | If pwsh.exe is in scope, allow `-{1,2}` before the `e` switch. |
| low | performance | Schedule runs every 15 minutes (`*/15`) with a 20-minute lookback window, so each 5-minute overlap re-reads events already alerted on, producing duplicate alerts for the same encoded-command event. hits_per_day is 0.14 so volume impact is negligible, but duplicate notables are possible. | Align window to the cadence (15m window for */15) or dedup on Computer+CommandLine+firstTime. |

1 evasion event(s):

<details>
<summary>1. Real WINWORD->powershell -enc chain (exact attack_step) but the encoded blob <code>YwBhAGwAYwA=</code> is only 12 base64 chars, below the regex <code>{20,}</code> floor, so the search never matches. A short encoded stager/launcher evades purely by length.</summary>

Sourcetype `XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`.

```xml
<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Computer>WS01.corp.local</Computer></System><EventData><Data Name='Image'>C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe</Data><Data Name='CommandLine'>powershell.exe -enc YwBhAGwAYwA=</Data><Data Name='User'>CORP\jdoe</Data><Data Name='ParentImage'>C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE</Data><Data Name='ParentCommandLine'>"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE" /n</Data></EventData></Event>
```

</details>

Routing, as the guards computed it ([pipeline.md](pipeline.md)):

- Round 1: findings above low exist, `reviews` 0 < 2, so `can_refine` → `revising` (`reviews` = 1).
- Round 2: `finding_key` `[(evasion, high), (evasion, medium), (brittleness, low), (logic, low)]` differs from round 1's and `reviews` 1 < 2, so `can_refine` → `revising` (`reviews` = 2).
- Round 3: `reviews` 2 == 2, so `can_refine` is false; no high or critical finding remains, so `residual_acceptable` → `approved` with `cap_experimental`. The medium finding (a 12-character encoded `calc` stays under the 20-character base64 floor) is left in the record, not fixed.

## Final gates

`gates` for draft 5, verbatim (`gate_spl` is the schedule-shaped form the noise run executed):

```json
{
  "draft": 5,
  "lint": {
    "errors": [],
    "warnings": []
  },
  "gate_spl": "search index=wineventlog sourcetype=\"XmlWinEventLog:Microsoft-Windows-Sysmon/Operational\" EventCode=1 (ParentImage=\"*WINWORD.EXE\" OR ParentImage=\"*EXCEL.EXE\" OR ParentImage=\"*OUTLOOK.EXE\") | where match(ParentImage,\"(?i)\\\\\\\\(winword|excel|outlook)\\\\.exe$\") AND match(CommandLine,\"(?i)\\\\s[-/]e[a-z]*[:\\\\s]+[\\\"']?[A-Za-z0-9+/=]{20,}\") | bin _time span=20m | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by _time Computer, User, ParentImage, Image | sort 0 - count",
  "run": {
    "count": 1,
    "scan_count": 912000,
    "errors": []
  },
  "recall": {
    "ran": true,
    "counts": [
      1,
      1,
      1,
      1,
      1,
      1
    ],
    "ok": true
  },
  "rate_per_day": 0.14285714285714285,
  "threshold": 5,
  "window_seconds": 604800,
  "top_values": {},
  "sample_rows": [
    {
      "Computer": "WS01.corp.local",
      "User": "CORP\\jdoe",
      "ParentImage": "C:\\Program Files\\Microsoft Office\\root\\Office16\\WINWORD.EXE",
      "Image": "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe",
      "count": "1"
    }
  ],
  "problems": [],
  "ok": true
}
```

## Out: the detection

`detections/office_app_spawns_encoded_powershell.yml` (the `date` is the local date at render time; the run's UTC timestamps are on 2026-11-05):

```yaml
name: Office app spawns encoded PowerShell
id: 3f0e6b5a-1d0c-4c6e-9d3e-5b2d6a8c1f11
version: 1
date: '2026-11-04'
author: detection-engineering-agent
status: experimental
type: TTP
description: 'A malicious Word macro launches powershell.exe with -EncodedCommand to fetch a second stage.


  Detects: winword.exe or excel.exe or outlook.exe spawns powershell.exe; powershell.exe command line contains -enc or -EncodedCommand followed by base64'
data_source:
- Sysmon EventID 1
- Windows Event Log Security 4688
search: index=wineventlog sourcetype="XmlWinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 (ParentImage="*WINWORD.EXE" OR ParentImage="*EXCEL.EXE" OR ParentImage="*OUTLOOK.EXE") | where match(ParentImage,"(?i)\\\\(winword|excel|outlook)\\.exe$") AND match(CommandLine,"(?i)\\s[-/]e[a-z]*[:\\s]+[\"']?[A-Za-z0-9+/=]{20,}") | stats count min(_time) as firstTime max(_time) as lastTime values(CommandLine) as CommandLine by Computer, User, ParentImage, Image | `office_app_spawns_encoded_powershell_filter`
how_to_implement: 'Ingest Windows Sysmon as sourcetype XmlWinEventLog:Microsoft-Windows-Sysmon/Operational into index wineventlog. Ingest Windows Security as sourcetype WinEventLog:Security into index wineventlog. Fields used: CommandLine, Computer, EventCode, Image, ParentImage, User. Adjust the index/sourcetype or the office_app_spawns_encoded_powershell_filter macro for your environment.'
known_false_positives: Admin scripts launched from Office automation in finance.
references:
- https://thedfirreport.com/2026/10/30/example/
drilldown_searches:
- name: View the detection results for $Computer$
  search: '%original_detection_search% | search Computer="$Computer$"'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
- name: View risk events for the last 7 days for $Computer$
  search: '| from datamodel Risk.All_Risk | search normalized_risk_object IN ("$Computer$") starthoursago=168 | stats count min(_time) as firstTime max(_time) as lastTime values(search_name) as "Search Name" values(risk_message) as "Risk Message" values(analyticstories) as "Analytic Stories" values(annotations._all) as "Annotations" values(annotations.mitre_attack.mitre_tactic) as "ATT&CK Tactics" by normalized_risk_object'
  earliest_offset: $info_min_time$
  latest_offset: $info_max_time$
rba:
  message: Office app spawns encoded PowerShell on $Computer$ by $User$
  risk_objects:
  - field: Computer
    type: system
    score: 70
  - field: User
    type: user
    score: 70
  threat_objects:
  - field: ParentImage
    type: parent_process_name
  - field: Image
    type: process_name
tags:
  analytic_story:
  - Office app spawns encoded PowerShell
  asset_type: Endpoint
  mitre_attack_id:
  - T1059.001
  - T1566.001
  product:
  - Splunk Enterprise
  - Splunk Enterprise Security
  - Splunk Cloud
  security_domain: endpoint
  throttling:
    fields:
    - Computer
    - User
    period: 86400s
```

`detections/macros/office_app_spawns_encoded_powershell_filter.yml`:

```yaml
name: office_app_spawns_encoded_powershell_filter
definition: search *
description: Update this macro to limit the output results to filter out false positives.
```

`dea publish ... --dry-run`:

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

## Cost and time

| step | model | cost (USD) | UTC |
|---|---|--:|---|
| match |  | 0.0000 | 04:27:26 |
| author | claude-opus-4-8 | 0.0201 | 04:27:39 |
| test |  | 0.0000 | 04:27:39 |
| tune | claude-sonnet-5-5 | 0.0162 | 04:27:43 |
| test |  | 0.0000 | 04:27:43 |
| tune | claude-sonnet-5-5 | 0.0159 | 04:27:46 |
| test |  | 0.0000 | 04:27:46 |
| review | claude-opus-4-8 | 0.2160 | 04:29:15 |
| refine | claude-opus-4-8 | 0.1942 | 04:30:23 |
| test |  | 0.0000 | 04:30:23 |
| review | claude-opus-4-8 | 0.2555 | 04:32:20 |
| refine | claude-opus-4-8 | 0.3860 | 04:34:55 |
| test |  | 0.0000 | 04:34:55 |
| review | claude-opus-4-8 | 0.1967 | 04:36:32 |
| render |  | 0.0000 | 04:36:32 |

Total `cost_usd` 1.3007 (printed as 1.30); 15 steps, 8 inference calls, 04:27:26Z to 04:36:32Z = 9 minutes 6 seconds. Terminal line: `done  tunes=2 remakes=0 reviews=2 cost_usd=1.30`, exit 0.

## What a detection engineer should take from it

- The red team found real gaps in drafts 3 and 4 (`-enco` prefix, decoy `-f x.ps1`, `-enc:` colon syntax, renamed binary, quoted base64, `/enc`) and each one became an event the next draft had to match. That loop is the product.
- The run ended `experimental`, not `production`, for two independent reasons: the idea had no attack examples, and one medium finding survived the review budget. Both are visible in `state.json` (`status_cap`, `review_log[2]`).
- `data_source` lists both matched sources although the final search uses only Sysmon, because both share `index=wineventlog` (known limit, [detection-format.md](detection-format.md)).
- The hit counts were scripted. Against a real Splunk the same drafts would meet real noise and real recall, and the run could end differently.
