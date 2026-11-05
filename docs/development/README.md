# Development history

The working files from building `dea`, kept because the real-inference runs are the evidence behind the design decisions in [SPEC.md](../SPEC.md) and the README.

| file | what it is |
|---|---|
| [build-log.md](build-log.md) | the phase checklist and dated log of the build, harden and converge workflows (formerly `tasks/todo.md`) |
| [e2e-findings.md](e2e-findings.md) | post-mortem of the first real-inference run (`failed_review`, $1.63) |
| [lessons.md](lessons.md) | one-line lessons recorded after corrections |
| [runs/e2e_run1_state.json](runs/e2e_run1_state.json) to [runs/e2e_run5_state.json](runs/e2e_run5_state.json) | the five real-inference end-to-end runs on the fixture idea against mock Splunk. Runs 1 to 4 ended `failed_review` and each fixed one thing (unverified-field lint, all-rounds evasion events for refine, all-rounds evasion notes for tune, scope-anchored review prompt); run 5 ended `done` and is the source of every artifact in the README and [example-walkthrough.md](../example-walkthrough.md) |
| [runs/droplet_validation_state.json](runs/droplet_validation_state.json) | the validated droplet cycle's run of the fixture idea against Splunk Enterprise 10.6.1.1 (`splunk_kind: real`, `--window=-24h`): `done`, $0.94, 1 tune, 0 remakes, 2 reviews, recall 4/4 on ingested evasion events, 3.0 alerts per day; the run behind the record in [splunk-test-server.md](../splunk-test-server.md#record-of-real-runs) |
| [runs/droplet_idea_state.json](runs/droplet_idea_state.json) | the same cycle's run of an idea `dea ideas` wrote from the fixture article (`office download cradle`): `done`, $1.03, 1 tune, 0 remakes, 2 reviews, recall 4/4, 2.0 alerts per day |
| [runs/droplet_run1_state.json](runs/droplet_run1_state.json) | the run recorded for the README GIF, a later pass on the same droplet: the fixture idea against Splunk Enterprise 10.6.1.1 on the DigitalOcean droplet (`splunk_kind: real`, `--window=-24h`, `-v`); `done`, $0.60, 1 tune, 3 drafts, 2 review rounds, recall 3/3 on ingested evasion events, 3.0 alerts per day. Unedited; it holds no host or token. The full validation record is in [splunk-test-server.md](../splunk-test-server.md#record-of-real-runs) |

The run files are the pipeline's `runs/<idea_id>/state.json` with one mechanical edit: the absolute scratchpad directory was stripped from `config.out_dir`, `outputs` and, for the idea run, `idea_path` (so they read `detections/...`, `detections_idea/...`, `ideas/...`). Nothing else was changed.

All five mock runs: `idea_path: tests/fixtures/idea.yml`, `splunk_kind: mock`, `--model author/review/refine=claude-opus-4-8` (the installed Claude Code 2.1.198 rejects `claude-opus-5-5`). The droplet runs used the same models.

| run | result | exit | cost | tunes | remakes | reviews | steps |
|--:|---|--:|--:|--:|--:|--:|--:|
| 1 | `failed_review` | 4 | $1.63 | 3 | 0 | 2 | 16 |
| 2 | `failed_review` | 4 | $1.48 | 3 | 0 | 2 | 16 |
| 3 | `failed_review` | 4 | $1.34 | 3 | 0 | 2 | 16 |
| 4 | `failed_review` | 4 | $1.24 | 2 | 0 | 2 | 14 |
| 5 | `done` | 0 | $1.30 | 2 | 0 | 2 | 15 |
| droplet validation | `done` | 0 | $0.94 | 1 | 0 | 2 | 13 |
| droplet idea | `done` | 0 | $1.03 | 1 | 0 | 2 | 13 |
| droplet GIF | `done` | 0 | $0.60 | 1 | 0 | 1 | 10 |
