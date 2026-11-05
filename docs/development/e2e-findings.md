# Real-inference end-to-end run 1 (2026-11-04, mock Splunk, --model author/review/refine=claude-opus-4-8)

Command: `DEA_SPLUNK=mock DEA_FIXTURES=<copy of tests/fixtures/splunk> uv run dea run tests/fixtures/idea.yml --splunk mock --max-cost 4 --refresh ...`
Result: `failed_review` (exit 4), cost $1.63, tunes=3 remakes=0 reviews=2.
Steps: match, author, test, tune, test, tune, test, review, refine, test, review, refine, test, tune, test, review.
Full state: runs/e2e_run1_state.json (drafts, gates, review_log with findings + evasion_events).

## Why it failed review (3rd review, draft 6)
- HIGH (brittleness): the refined SPL relies on `OriginalFileName` for renamed-binary coverage; the inventory has no such field
  (lint emitted only `warning: unverified field 'OriginalFileName'`). Refine introduced an unverified field to satisfy the
  previous round's evasion finding; the reviewer correctly flagged it. The loop can oscillate: review demands renamed-binary
  coverage -> refine reaches for a field we cannot verify -> review flags brittleness -> out of review rounds (Z=2).
- MEDIUM x3: fixed LOLBin parent allowlist; attacker-satisfiable IntegrityLevel exclusion; intermediary branch not tied to Office lineage.

## Observations
- Review findings are concrete and field-level (good teeth). Evasion events are generated and ingested (recall check works).
- Lint warnings for unverified fields are advisory; the author/tune/refine prompts are not forced to stay within `available_fields`.
- `review_pass` requires nothing above low; `residual_acceptable` requires no high/critical. With an adversarial reviewer, a
  "high" is easy to earn on round Z, so runs rarely reach `approved`. Convergence needs a deterministic guard, not a softer reviewer.
- Each review call cost ~$0.2-0.5 (large payload: samples + sample_rows + top_values).
- `dea ideas` produced 5 ideas but `attack_examples` was empty even though the article contains a verbatim Sysmon event.
