# Security

## Reporting

Use GitHub's private vulnerability reporting on this repository (Security tab, "Report a vulnerability"). No public issues for exploitable findings. Supported: the `main` branch only.

## Scope

This CLI, its prompts and its Splunk REST path. Splunk itself and the `claude` CLI are out of scope.

## What an operator must know

These are properties of the tool, not vulnerabilities:

- **`dea run` executes model-written SPL on your Splunk with your token's permissions.** Lint rejects `| head`, `delete`, `collect`, `outputlookup`, `sendemail`, `script`, `run`, `map`, `dump`, `rest`, `dbxquery` and `index=*` before anything is sent, and only search jobs are created; the token's permissions are the real boundary. Scope it to search plus the attack index plus, for `dea publish` only, macro and saved-search writes in one app (`SPLUNK_APP`). Never an admin token, never in CI beyond `SPLUNK_HOST`/`SPLUNK_TOKEN` secrets.
- **Evasion events are model-authored attack-shaped events and are ingested into Splunk** under host `dea-<run_id>-<n>` in `--attack-index` (default `dea_attack`). Use a scratch index. They are never deleted; per-run host prefixes make old ones inert.
- **Read the detection YAML before `dea publish` without `--dry-run`.** The SPL is model output; the filter macro ships as `search *`.
- **`inventory.json` and `runs/` carry data from your environment**: field values, one raw event per sourcetype, sample result rows, ingested events. Both are git-ignored. Do not commit them from a real Splunk.
- **What the model sees.** Claude runs with `--tools ""`, no settings, no history, and receives only the keys in `prompts.INPUTS[step]`: the idea text, the matched sourcetypes' field names with up to three top values each, one raw sample per sourcetype, the gate's sample rows and top values, and the draft SPL; `dea ideas` sends the article text. Exact keys per step are in [docs/inference.md](docs/inference.md).
- **`SPLUNK_VERIFY=0` disables TLS verification.** Use it only against the throwaway droplet in [docs/splunk-test-server.md](docs/splunk-test-server.md), never against a production host.
- **No secrets in the repo**: `SPLUNK_TOKEN` is read from the environment only.
