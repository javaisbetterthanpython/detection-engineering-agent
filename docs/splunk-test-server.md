# Splunk test server (DigitalOcean droplet)

A disposable Splunk Enterprise instance to run `dea` against real search, real ingest and real publish, then destroy. Everything is in [`scripts/splunk-droplet.sh`](../scripts/splunk-droplet.sh) and its cloud-init, [`scripts/cloud-init.yml`](../scripts/cloud-init.yml); this page is read from them. The droplet is the only place to use `SPLUNK_VERIFY=0`.

Why a droplet and not the laptop: Splunk Enterprise wants 4 GB of RAM and a TLS management port that `splunk-sdk` can reach, and a cloud host that lives for an hour is cheaper than keeping that on a workstation.

## Prerequisites

`doctl` (authenticated with `doctl auth init`; set `DO_CONTEXT=<name>` if you use a named context), `curl`, `ssh`, `ssh-keygen`, `python3`, `awk`. Nothing is installed on your machine; Splunk is installed on the droplet by cloud-init.

Knobs, all environment variables with defaults: `DO_CONTEXT=default` (your doctl context name), `DROPLET=dea-splunk` (also the firewall name), `REGION=tor1`, `IMAGE=ubuntu-24-04-x64`, `SIZE=s-2vcpu-4gb`, `SSH_KEY=~/.ssh/dea-splunk`, `WAIT_SECS=900`.

## Cost

`s-2vcpu-4gb` is billed hourly at DigitalOcean's list price for that slug ($24 per month, $0.0357 per hour, at the time of writing; confirm with `doctl compute size list --format Slug,PriceMonthly,PriceHourly`). `up` takes several minutes (apt, a 1.4 GB Splunk download, first start; 410 seconds on the validated run); a full `up`, `seed`, inventory, run, publish, `down` cycle fits well inside an hour. A forgotten droplet costs the monthly price, so `down` is part of the workflow. Pass a size to `up` (`up s-4vcpu-8gb`) only if Splunk refuses to start on 4 GB; cloud-init also adds 2 GB of swap.

**License.** cloud-init downloads the Splunk Enterprise 10.6.1.1 `.deb` from download.splunk.com and starts it with `--accept-license`, so running `up` accepts the [Splunk Software License Agreement](https://www.splunk.com/en_us/legal/splunk-software-license-agreement.html) on your behalf. The instance runs on the built-in Enterprise trial license: 60 days, 500 MB of indexing per day, no clustering; `seed` indexes well under 1 MB. The droplet is meant to live for an hour, not 60 days.

## Verbs

| verb | what it does |
|---|---|
| `up [size]` | Generates an ed25519 key at `~/.ssh/dea-splunk` if missing and imports it to DigitalOcean as `dea-splunk`. Creates droplet `dea-splunk` from the cloud-init (Splunk Enterprise 10.6.1.1 `.deb`, sha512-verified, run as a `splunk` service user under systemd, Splunk Web on 8000 with SSL, `props`/`transforms` for the two Windows sourcetypes) with a random 20-character admin password. Creates or updates the cloud firewall `dea-splunk`: inbound tcp 22, 8000 and 8089 **from your current public IP only** (`/32`, looked up on api.ipify.org), outbound open. Waits up to `WAIT_SECS` for splunkd, enables token auth, creates a bearer token (user `admin`, audience `dea`, 30 days), creates indexes `wineventlog` and `dea_attack`, and writes `.env.local` at the repo root (mode 600). Idempotent: rerunning keeps the droplet, refreshes the firewall to your current IP and reuses the token while it is valid. Secrets are never printed. |
| `seed` | Generates 60 Sysmon EventCode 1 XML events (57 benign process chains and exactly 3 Office to `powershell.exe -EncodedCommand` launches with real base64) and 40 Security 4688 events, spread over the last 24 hours across hosts `WS01` to `WS03` and `DC01`, and posts each one through `/services/receivers/simple` into `index=wineventlog` with the sourcetypes the fixture inventory uses (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`, `WinEventLog:Security`) and `source=dea-seed`. Waits up to 240 seconds until they are searchable, then prints verification searches (counts and time span per sourcetype, Sysmon by `Image`, the 3 Office-to-PowerShell events, Security by `New_Process_Name`) and fails if `Image` or `New_Process_Name` do not extract. A second `seed` is a no-op unless `SEED_FORCE=1`. |
| `status` | Droplet id, IP, state and size; the firewall's inbound rules; Splunk version and web URL; `\| tstats count where index IN (wineventlog, dea_attack) by index, sourcetype`. |
| `down` | Deletes the droplet and the firewall, drops the host from `~/.ssh/known_hosts`, removes `.env.local`. Idempotent. The token dies with the droplet. |
| `ssh [cmd]` | `ssh -i ~/.ssh/dea-splunk root@<ip>`, with an optional command (`ssh tail -50 /var/log/cloud-init-output.log` is the first thing to look at when `up` times out). |

No verb, or an unknown one, prints the usage and exits 2.

## `.env.local` and `.env.example`

`up` writes `.env.local` at the repo root with `SPLUNK_HOST`, `SPLUNK_PORT=8089`, `SPLUNK_TOKEN`, `SPLUNK_VERIFY=0`, `SPLUNK_APP=search`, `SPLUNK_OWNER=admin`, `SPLUNK_ADMIN_PASSWORD` and `SPLUNK_WEB` (the 8000 URL). [`.env.example`](../.env.example) shows the shape with placeholder values and the safe defaults (`SPLUNK_VERIFY=1`, `SPLUNK_OWNER=nobody`); `up` writes the droplet's own values over them. `.gitignore` ignores `.env*` except `.env.example`. Load it into a shell with:

```sh
set -a; . .env.local; set +a
```

`SPLUNK_VERIFY=0` is there because the droplet's Splunk uses a self-signed certificate. Never carry that setting to another host. The firewall-to-your-IP rule makes the server unreachable from anywhere else; when your IP changes, run `up` again.

## The sequence

The commands the script is built for, from idea to scheduled saved search. They are the mock-Splunk commands from the [README](../README.md) with the environment loaded; `--window=-24h` because `seed` spreads its events over the last 24 hours, `--verbose` (`-v`) for one stderr line per state transition.

```sh
scripts/splunk-droplet.sh up
scripts/splunk-droplet.sh seed
set -a; . .env.local; set +a
uv run dea inventory --splunk real --refresh
uv run dea run tests/fixtures/idea.yml --splunk real --window=-24h --verbose
uv run dea publish detections/ --splunk real --dry-run
uv run dea publish detections/ --splunk real
scripts/splunk-droplet.sh down
```

What to expect:

- `inventory` prints `index<TAB>sourcetype<TAB>count` lines; the two seeded sourcetypes must be there or the run ends `infeasible` (exit 2) with `runs/<id>/coverage.md` listing what the inventory had. The inventory also lists `dea_attack` once it holds events.
- `run` executes every gate search with the token, ingests every evasion event the reviewer writes under host `dea-<run_id>-<n>` into `dea_attack`, and recall now means something: an evasion event the refined draft does not match fails the gate (`recall: examples ... produced 0 hits`). The noise numbers are real too (60 Sysmon events over 24 hours, 3 of them the attack, so 3.0 alerts per day against the TTP threshold of 5), so expect a different path from run 5's.
- `publish` creates the `office_app_spawns_encoded_powershell_filter` macro and then the saved search in app `search` as owner `admin` (from `.env.local`); it appears in Splunk Web under Settings, Searches, reports, and alerts. `--dry-run` prints the properties first.
- `down` removes everything.

## Record of real runs

Validated against Splunk Enterprise 10.6.1.1 (build b2ae2962645c) on a DigitalOcean droplet, `s-2vcpu-4gb` ($0.0357 per hour, $24 per month), Ubuntu 24.04, region `tor1`, on 2026-11-05. The script was written and run end to end three times; the numbers below are from the final fresh cycle.

**Server**

| step | result |
|---|---|
| `up` | 410 seconds from `doctl compute droplet create` to a token and `.env.local`; firewall `dea-splunk` with 22, 8000 and 8089 open to one `/32` |
| `seed` | 60 Sysmon `EventCode=1` XML events and 40 Security 4688 events in `index=wineventlog`; `Image`, `ParentImage`, `CommandLine` and `New_Process_Name` extract; exactly 3 Office to `powershell.exe -EncodedCommand` launches |
| `status` | version `10.6.1.1`, `tstats` counts 60 (`XmlWinEventLog:Microsoft-Windows-Sysmon/Operational`) and 40 (`WinEventLog:Security`) |
| `uv run pytest -q` | all tests passed (223 at the time of the cycle; the suite never touches the droplet) |

**`dea` against it**

| step | result |
|---|---|
| `dea inventory --splunk real --refresh` | both sourcetypes listed (57 Sysmon and 38 Security events inside the `-24h` window at that moment) with `Image`, `ParentImage`, `CommandLine`, `User` and `Computer` among the extracted fields |
| `dea run tests/fixtures/idea.yml --splunk real --window=-24h` | `done`, exit 0, $0.94, 1 tune, 0 remakes, 2 reviews ([development/runs/droplet_validation_state.json](development/runs/droplet_validation_state.json)); recall 4/4 (the idea has no `attack_examples`, so all four are evasion events the reviewer wrote and the run ingested into `dea_attack`); 3 hits in 24 hours = 3.0 per day, under the TTP threshold of 5. The final SPL matched exactly the three planted WINWORD/EXCEL to PowerShell events |
| `dea publish detections/ --splunk real` | created macro `office_app_spawns_encoded_powershell_filter`, then the saved search: `is_scheduled=1`, `cron_schedule=*/15 * * * *`, `dispatch.earliest_time=-25m@m`, `dispatch.latest_time=-5m@m`, alert when the result count is greater than 0, `alert.suppress.fields=Computer`, `alert.suppress.period=86400s` |
| dispatch | a manual dispatch of the saved search ran without error and returned the planted events; Splunk's scheduler then ran it on its own with `status=success` |
| second idea | `office download cradle`, written by `dea ideas` from the fixture article: `done`, $1.03, recall 4/4, 2 hits ([development/runs/droplet_idea_state.json](development/runs/droplet_idea_state.json)) |

The README's run GIF is a further pass on the same droplet with `--verbose`: `done`, $0.60, 3 minutes 56 seconds, 1 tune, 3 drafts, 2 review rounds, recall 3/3, 3.0 alerts per day. Its `state.json` is [development/runs/droplet_run1_state.json](development/runs/droplet_run1_state.json). The three droplet state files are `splunk_kind: "real"`; the Splunk host and token are not in them. Every other run in [development/runs/](development/runs/) is `splunk_kind: "mock"`.

To reproduce: the sequence above, with `scripts/splunk-droplet.sh status` between `seed` and `inventory` to confirm the version and the 60/40 counts, and `scripts/splunk-droplet.sh down` at the end. One cycle is one droplet hour plus about $1 of inference.
