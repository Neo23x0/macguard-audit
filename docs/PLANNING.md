# macguard-audit: macOS Security Posture Reporter — Implementation Plan

## Context

The repository is an empty skeleton (`LICENSE` + one-line `README.md`, no code). The goal is to build **posturectl** — a lightweight, dependency-free macOS security posture collector that gathers ~22 local configuration signals, outputs well-structured JSONL, and optionally ships to Splunk HEC or a generic HTTPS ingest endpoint. No MDM required. Runs on macOS 12–15 (Monterey–Sequoia).

Triggering need: continuous endpoint visibility without MDM, no enforcement, pure audit + reporting.

---

## Language Justification

**Primary: bash** (3.2+, always present on macOS)
**JSON marshaling: `/usr/bin/python3`** (Apple-provided; present on macOS 12+ with Xcode CLT — standard on any developer/IT machine; used only for `json.dumps()` and config file parsing)
**HTTP transport: `curl`** (always available on macOS)
**Fallback**: when Python3 is absent, `json_escape_string()` uses manual sed-based escaping and the tool logs a warning. The tool never aborts — it degrades gracefully.

Swift was considered but rejected for v1: requires compilation, harder to deploy as a single file, and all checks are thin wrappers around CLI tools that bash handles natively.

---

## Repository Layout

```
macguard-audit/
├── posturectl.sh                         # main entry point (~400 lines)
├── lib/
│   ├── utils.sh                          # logging, timeout, platform detection
│   ├── checks.sh                         # all 22 check functions
│   ├── json.sh                           # JSON assembly + Python3 marshaling
│   ├── transport.sh                      # Splunk HEC + generic HTTPS POST
│   └── keychain.sh                       # `security` CLI wrapper
├── config/
│   ├── posturectl.json.example           # annotated config template
│   └── posturectl.schema.json            # JSON Schema for config
├── launchd/
│   ├── com.example.posturectl.plist      # LaunchDaemon (root, hourly)
│   └── com.example.posturectl-user.plist # LaunchAgent (user, 4-hourly)
├── tests/
│   ├── run_tests.sh                      # test harness
│   ├── fixtures/                         # golden stdout snippets per check
│   │   ├── fdesetup_enabled.txt
│   │   ├── fdesetup_disabled.txt
│   │   ├── spctl_enabled.txt
│   │   ├── spctl_disabled.txt
│   │   ├── csrutil_enabled.txt
│   │   ├── csrutil_custom.txt
│   │   ├── socketfilterfw_on.txt
│   │   ├── socketfilterfw_off.txt
│   │   ├── softwareupdate_on.txt
│   │   ├── softwareupdate_off.txt
│   │   ├── systemsetup_ssh_on.txt
│   │   ├── systemsetup_ssh_off.txt
│   │   ├── dseditgroup_admin.txt
│   │   ├── dseditgroup_nonadmin.txt
│   │   └── screensaver_300.txt
│   ├── test_checks.sh                    # fixture-driven parser unit tests
│   ├── test_json.sh                      # JSON assembly + escaping tests
│   └── test_transport.sh                 # mock server transport tests
├── tools/
│   └── mock_server.py                    # stdlib-only Python3 HTTPS ingest mock
├── examples/
│   ├── splunk/
│   │   ├── hec_config.conf               # Splunk HEC input stanza
│   │   └── queries.spl                   # 6 sample SPL searches
│   └── output_sample.json                # annotated sample output
├── install.sh                            # deploy: copy binary + launchctl load
├── uninstall.sh
├── docs/
│   ├── PLANNING.md                       # this planning document (in-repo copy)
│   ├── checks.md                         # full check inventory table
│   ├── schema.md                         # JSON schema narrative
│   ├── threat_model.md                   # spoofing/replay/secrets threat model
│   └── operator_manual.md               # run, schedule, troubleshoot
├── LICENSE
└── README.md                             # expand with usage + check list
```

---

## Phase 0 — Research Summary

### Existing tools reviewed
- **SilentKnight / LockRattler** (Howard Oakley): GUI-only; checks firmware, XProtect, MRT, Gatekeeper. Confirms our check set is correct.
- **Pareto Security** (open source): 20 checks covering firewall, AirDrop, remote login, screen lock, Gatekeeper, FileVault. Confirms all these are reliably checkable.
- **macOS Security Compliance Project / mSCP** (NIST): authoritative command references for CIS/DISA STIG; used to validate command choices.
- **Lynis**: comprehensive but requires Homebrew or manual install; confirms we can cover 80% of its macOS checks with built-ins alone.

### Key feasibility findings
- `csrutil status` works in normal mode (no Recovery needed for read), but Custom Configuration requires warn-level handling.
- `spctl --status` still works on macOS 15 but output goes to **stderr** (must capture with `2>&1`).
- `systemsetup` is deprecated in macOS 15 but functional through 15.3; fallback checks built for every `systemsetup` call.
- `socketfilterfw --getglobalstate` requires root; returns empty/error without it — checked silently.
- `softwareupdate --schedule` is slow (5–15s on slow networks) — 15-second timeout mandatory.
- XProtect path changed slightly in macOS 15; probe two paths with fallback.
- APFS FileVault check via `diskutil apfs list` complements `fdesetup status`.
- `bputil -d` (Apple Silicon) / `nvram` GUID key (Intel) enables Secure Boot detection.

---

## Phase 1 — JSON Schema

### Per-check field contract (all fields always present)

```json
{
  "status": "pass | fail | warn | unknown",
  "value":  "<typed: string | integer | boolean | object | null>",
  "raw":    "<raw command output, truncated to 512 chars | null>",
  "privilege": "user | root",
  "check_duration_ms": 214,
  "error": "<human-readable string | null>"
}
```

### Full document schema

```json
{
  "schema_version": "1.0",
  "tool": "posturectl",
  "tool_version": "1.0.0",
  "collected_at": "2026-02-23T10:15:00Z",
  "collection_duration_ms": 4218,
  "run_as_root": false,
  "collection_warnings": ["check firewall_global_state: requires root; skipped"],

  "host": {
    "hostname": "mbp-neo.local",
    "hardware_uuid": "A1B2C3D4-...",
    "serial_hash": "<SHA-256(serial + org_salt) | null if privacy=off>",
    "model": "MacBookPro18,3",
    "arch": "arm64",
    "org_id": "acme-corp",
    "environment": "production",
    "tags": ["finance", "laptop"],
    "mdm_enrolled": true,
    "mdm_server_url": "https://mdm.example.com/mdm"
  },

  "os": {
    "name": "macOS",
    "version": "15.3.1",
    "build": "24D70",
    "major": 15,
    "minor": 3,
    "kernel_version": "Darwin 24.3.0",
    "uptime_seconds": 86400
  },

  "user": {
    "current_user": "neo",
    "console_user": "neo",
    "uid": 501
  },

  "posture": {
    "filevault":              { "status":"pass","value":"enabled","raw":"...","privilege":"user","check_duration_ms":214,"error":null },
    "gatekeeper":             { "status":"pass","value":"enabled","raw":"assessments enabled","privilege":"user","check_duration_ms":88,"error":null },
    "sip":                    { "status":"pass","value":"enabled","raw":"...","privilege":"user","check_duration_ms":102,"error":null },
    "firewall_global_state":  { "status":"unknown","value":null,"raw":null,"privilege":"root","check_duration_ms":0,"error":"requires root; skipped" },
    "firewall_stealth_mode":  { "status":"unknown","value":null,"raw":null,"privilege":"root","check_duration_ms":0,"error":"requires root; skipped" },
    "firewall_logging":       { "status":"unknown","value":null,"raw":null,"privilege":"root","check_duration_ms":0,"error":"requires root; skipped" },
    "ssh_remote_login":       { "status":"pass","value":"disabled","raw":"Remote Login: Off","privilege":"user","check_duration_ms":312,"error":null },
    "screen_lock_timeout":    { "status":"pass","value":300,"raw":"300","privilege":"user","check_duration_ms":45,"error":null },
    "auto_login":             { "status":"pass","value":"disabled","raw":"1","privilege":"user","check_duration_ms":38,"error":null },
    "guest_account":          { "status":"pass","value":"disabled","raw":"0","privilege":"user","check_duration_ms":41,"error":null },
    "xprotect_version":       { "status":"pass","value":"5274","raw":"5274","privilege":"user","check_duration_ms":29,"error":null },
    "mrt_version":            { "status":"pass","value":"1.97","raw":"1.97","privilege":"user","check_duration_ms":27,"error":null },
    "auto_updates":           { "status":"pass","value":"enabled","raw":"Automatic check is on","privilege":"user","check_duration_ms":198,"error":null },
    "is_admin":               { "status":"warn","value":true,"raw":"yes neo is a member of admin","privilege":"user","check_duration_ms":441,"error":null },
    "time_sync":              { "status":"pass","value":"enabled","raw":"Network Time: On","privilege":"user","check_duration_ms":289,"error":null },
    "airdrop":                { "status":"warn","value":"contacts_only","raw":"Contacts Only","privilege":"user","check_duration_ms":33,"error":null },
    "remote_management":      { "status":"pass","value":"disabled","raw":"","privilege":"user","check_duration_ms":55,"error":null },
    "profiles":               { "status":"unknown","value":null,"raw":null,"privilege":"root","check_duration_ms":0,"error":"requires root; skipped" },
    "system_extensions":      { "status":"unknown","value":null,"raw":null,"privilege":"root","check_duration_ms":0,"error":"requires root; skipped" },
    "browser_versions":       { "status":"pass","value":{"safari":"18.3","chrome":"133.0.6943.98","firefox":"not_installed","brave":"not_installed","edge":"not_installed"},"raw":null,"privilege":"user","check_duration_ms":62,"error":null },
    "disk_encryption_apfs":   { "status":"pass","value":"encrypted","raw":"Yes (Unlocked)","privilege":"user","check_duration_ms":177,"error":null },
    "secure_boot":            { "status":"pass","value":"full_security","raw":"...","privilege":"user","check_duration_ms":93,"error":null }
  },

  "summary": {
    "total": 22,
    "pass": 15,
    "fail": 0,
    "warn": 2,
    "unknown": 5,
    "score_pct": 88
  }
}
```

---

## Phase 2 — Check Inventory (22 checks)

| # | Key | Command | Priv | Pass condition | Pitfalls |
|---|-----|---------|------|---------------|---------|
| 01 | `filevault` | `fdesetup status` | user | contains "FileVault is On" | Apple Silicon may append extra text; still "On" |
| 02 | `gatekeeper` | `spctl --status 2>&1` | user | "assessments enabled" | Output is on **stderr**; use `2>&1` |
| 03 | `sip` | `csrutil status` | user | "enabled" without "Custom Configuration" | Custom Config = warn; Recovery not needed for read |
| 04 | `firewall_global_state` | `socketfilterfw --getglobalstate` | **root** | "Firewall is enabled" | Silently skipped if not root |
| 05 | `firewall_stealth_mode` | `socketfilterfw --getstealthmode` | **root** | "Stealth mode enabled" | Same root requirement |
| 06 | `firewall_logging` | `socketfilterfw --getloggingmode` | **root** | "Log mode is on" | Same |
| 07 | `ssh_remote_login` | `systemsetup -getremotelogin` | user | "Remote Login: Off" | Deprecated in macOS 15; fallback: `launchctl list com.openssh.sshd` |
| 08 | `screen_lock_timeout` | `defaults read /Library/Preferences/ByHost/com.apple.screensaver idleTime` | user | 0 < value ≤ 600 | Key missing = unknown; MDM-set timeout not visible here |
| 09 | `auto_login` | `defaults read .../com.apple.loginwindow DisableAutoLogin` | user | value == "1" | Key absent = fail (not explicitly disabled) |
| 10 | `guest_account` | `defaults read .../com.apple.loginwindow GuestEnabled` | user | value == "0" or key missing | Key absent = pass (default off) |
| 11 | `xprotect_version` | `defaults read /Library/Apple/.../XProtect.bundle/Contents/Info.plist CFBundleShortVersionString` | user | non-empty string | Probe two paths (bundle + app) for macOS 15 |
| 12 | `mrt_version` | `defaults read /Library/Apple/.../MRT.app/Contents/Info.plist CFBundleShortVersionString` | user | non-empty string | Cryptex delivery on macOS 15; try alt path |
| 13 | `auto_updates` | `softwareupdate --schedule` | user | "Automatic check is on" | Slow (15s timeout); fallback: `defaults read .../com.apple.SoftwareUpdate AutomaticCheckEnabled` |
| 14 | `is_admin` | `dseditgroup -o checkmember -m "$USER" admin` | user | member = warn, not-member = pass | Check exit code, not text; LDAP may be slow |
| 15 | `time_sync` | `systemsetup -getusingnetworktime` | user | "Network Time: On" | Deprecated in 15; fallback: `launchctl list com.apple.timed` |
| 16 | `airdrop` | `defaults read com.apple.sharingd DiscoverableMode` | user | "Off" = pass, "Contacts Only" = warn, "Everyone" = fail | macOS 13+ key may be in Finder prefs; check both |
| 17 | `remote_management` | `launchctl list com.apple.screensharing` | user | non-zero exit = disabled = pass | Also check `com.apple.RemoteDesktop.agent` |
| 18 | `profiles` | `profiles -P` | **root** | configurable (count profiles) | macOS 15 may need FDA TCC grant |
| 19 | `system_extensions` | `systemextensionsctl list` | **root** | configurable allowlist | Format changed in macOS 13; parse by `[activated enabled]` token |
| 20 | `browser_versions` | `defaults read APP/Contents/Info.plist CFBundleShortVersionString` | user | non-empty per installed browser | Check `/Applications/` and `~/Applications/`; Firefox has no version in Info.plist — read `application.ini` |
| 21 | `disk_encryption_apfs` | `diskutil apfs list` | user | `FileVault: Yes` | Grepping only the FileVault line; non-APFS volumes = unknown |
| 22 | `secure_boot` | arm64: `bputil -d 2>&1`; x86_64: `nvram 94b73556-...:AppleSecureBootPolicy` | user | Full Security / 0x03 | Detect arch via `uname -m`; VMs may not have nvram key |

All checks use `run_with_timeout $TIMEOUT_PER_CHECK COMMAND`.
Root-required checks self-skip with `CHECK_ERROR="requires root; skipped"` when not root.

---

## Phase 2 — Implementation Architecture

### Module responsibilities

**`lib/utils.sh`**
- `log_info/warn/error/debug` — stderr + optional syslog via `logger`
- `run_with_timeout SECS CMD [ARGS]` — background subshell + polling; returns `RWT_OUTPUT` and `RWT_EXIT`; exit 124 = timeout
- `detect_environment` — sets `PLATFORM_*` globals (hostname, HW UUID, model, arch, OS version/build, console user, MDM enrollment, Python3 availability)
- `epoch_ms` — millisecond timestamp (Python3 if available; else `date +%s * 1000`)
- `is_root` — test `id -u == 0`

**`lib/checks.sh`**
- 22 `check_NAME()` functions, each: sets `CHECK_STATUS`, `CHECK_VALUE`, `CHECK_RAW`, `CHECK_ERROR`, `CHECK_DURATION_MS`, `CHECK_PRIVILEGE`
- All errors are caught; check functions never exit non-zero (use `|| true` guards)
- `ENABLED_CHECKS` array and `run_checks()` loop with per-check error isolation

**`lib/json.sh`**
- `json_escape_string VALUE` — Python3 `json.dumps` or manual sed fallback
- `json_null_or_string VALUE` — null if empty, else quoted
- `json_bool VALUE` — true/false literals
- `assemble_check_object CHECK_NAME` — reads `CHECK_*` globals, outputs JSON object
- `assemble_full_report` — wraps all check objects + host/OS/user metadata; Python3 path for pretty-print; manual path as fallback

**`lib/transport.sh`**
- `ship_splunk_hec JSONL TOKEN URL` — wraps in HEC envelope; curl POST; retry loop
- `ship_https_post JSONL TOKEN URL` — direct POST; retry loop
- `_curl_post URL TOKEN AUTH_PREFIX BODY` — shared curl invocation with timeout, retry, TLS flag
- Retry on HTTP 429/503; give up after `TRANSPORT_MAX_RETRIES` (default 3)

**`lib/keychain.sh`**
- `keychain_store SERVICE ACCOUNT TOKEN` — `security add-generic-password -U`; System keychain for root
- `keychain_retrieve SERVICE ACCOUNT` — `security find-generic-password -w`
- `get_token TRANSPORT_TYPE` — resolves from keychain/config/env per config `token_source`
- Config-file token: validates file permissions ≤ 600 before reading; warns if not

**`posturectl.sh` (main)**
- `parse_args` — manual `while/case` loop (no `getopt`; not portable on macOS without Homebrew)
- `load_config` — reads JSON config with Python3 (`json.load`); exports as shell globals
- `main` — parse → load config → detect env → run checks → assemble → write → ship

### CLI interface

```
posturectl.sh [OPTIONS]

  -c, --config FILE     Config file (default: /etc/posturectl/posturectl.json,
                        then ~/.config/posturectl/posturectl.json)
  -o, --output FILE     Write output to FILE ("-" for stdout)
  -n, --dry-run         Collect and write, do not ship
  -v, --verbose         Print each check result to stderr as it completes
  -p, --pretty          Pretty-print JSON (2-space indent, requires Python3)
  --checks-only         Run checks and print to stdout; no transport
  --ship-only           Read last output file and ship (no recollection)
  --check NAME          Run only the named check (for debugging)
  --list-checks         Print all check names and exit
  --version             Print version and exit
  --help                Usage
```

### Config file fields (all optional with defaults)

```json
{
  "collection": {
    "enabled_checks": "all",
    "disabled_checks": [],
    "timeout_per_check_secs": 15,
    "timeout_total_secs": 120,
    "run_root_checks": false
  },
  "output": {
    "file": "/var/log/posturectl/posture.jsonl",
    "rotate_max_lines": 1000,
    "atomic_write": true
  },
  "thresholds": {
    "screen_lock_timeout_max_secs": 600,
    "airdrop_policy": "contacts_or_off",
    "is_admin_is_fail": false
  },
  "transport": {
    "enabled": true,
    "type": "splunk_hec",
    "splunk_hec": {
      "url": "https://splunk.example.com:8088/services/collector/event",
      "token_source": "keychain",
      "token_keychain_service": "posturectl",
      "token_keychain_account": "splunk_hec_token",
      "token_config_value": "",
      "token_env_var": "POSTURECTL_SPLUNK_TOKEN",
      "index": "macos_security",
      "sourcetype": "posturectl:posture",
      "tls_verify": true,
      "connect_timeout_secs": 10,
      "max_retries": 3,
      "retry_delay_secs": 5
    },
    "https_post": {
      "url": "https://ingest.example.com/api/v1/events",
      "auth_header": "Authorization",
      "token_source": "keychain",
      "token_keychain_service": "posturectl",
      "token_keychain_account": "https_post_token",
      "extra_headers": {},
      "tls_verify": true,
      "connect_timeout_secs": 10,
      "max_retries": 3
    }
  },
  "privacy": {
    "hash_serial": true,
    "hash_salt": "replace-with-org-wide-secret"
  },
  "logging": {
    "level": "info",
    "syslog": true,
    "syslog_facility": "local0"
  },
  "org_id": "acme-corp",
  "environment": "production",
  "tags": []
}
```

### Atomic write

```bash
write_report() {
    local dir; dir=$(dirname "$OUTPUT_FILE")
    local tmp="${dir}/.posturectl_tmp_$(date +%s)_$$"
    printf '%s\n' "$REPORT_JSON" > "$tmp" && mv "$tmp" "$OUTPUT_FILE"
}
```

---

## Phase 3 — Packaging and Scheduling

### LaunchDaemon (`/Library/LaunchDaemons/com.example.posturectl.plist`)
- `UserName`: root (enables root checks: firewall, profiles, system_extensions)
- `StartInterval`: 3600 (every hour)
- `RunAtLoad`: true
- `ThrottleInterval`: 60
- `StandardOutPath`: `/var/log/posturectl/daemon.out.log`
- `StandardErrorPath`: `/var/log/posturectl/daemon.err.log`
- Config: `/etc/posturectl/posturectl.json` with `run_root_checks: true`

### LaunchAgent (`/Library/LaunchAgents/com.example.posturectl-user.plist`)
- Runs as logged-in user
- `StartInterval`: 14400 (every 4 hours)
- Config: `/Library/Application Support/posturectl/posturectl.json` with `run_root_checks: false`
- Useful when root daemon not desired

### Install script (`install.sh`)
```
1. Copy posturectl.sh -> /usr/local/bin/posturectl.sh (chmod 755, chown root:wheel)
2. Copy lib/ -> /usr/local/lib/posturectl/
3. mkdir -p /etc/posturectl /var/log/posturectl
4. Copy config/posturectl.json.example -> /etc/posturectl/posturectl.json (chmod 600)
5. Copy launchd/com.example.posturectl.plist -> /Library/LaunchDaemons/
6. chmod 644, chown root:wheel
7. launchctl load -w /Library/LaunchDaemons/com.example.posturectl.plist
8. Print: "Store token: security add-generic-password -k /Library/Keychains/System.keychain -s posturectl -a splunk_hec_token -w YOUR_TOKEN"
```

### Log rotation
- Output JSONL: rotate when `rotate_max_lines` exceeded (tail -n N to rotate in-place)
- LaunchDaemon stderr/stdout: use `newsyslog` or `logrotate` entry; alternatively rotate in `install.sh`

---

## Threat Model Summary

| Threat | Mitigation |
|--------|-----------|
| Token exposure in config | File permission check (must be ≤ 600); prefer Keychain |
| Token replay | Splunk HEC uses per-request auth; short-lived tokens where possible |
| Report tampering in transit | HTTPS with TLS verify (configurable; warn loudly if disabled) |
| Report tampering at rest (local JSONL) | File owned by root; future: HMAC signing |
| Spoofed host identity | Hardware UUID in report; hostname is advisory only |
| Privilege escalation via script | Script owned root:wheel, chmod 755; lib/ chmod 644 |
| Sensitive data exposure | Serial hashed; no browsing history/process list/credentials collected |
| Adversary disabling posturectl | LaunchDaemon restart-on-failure; monitor via `launchctl list` |

Full threat model in `docs/threat_model.md`.

---

## Test Strategy

### Unit tests (fixture-driven, no live commands)
- `tests/test_checks.sh`: overrides `run_with_timeout` to feed fixture file content; tests all 22 parsers with pass/fail/edge-case inputs
- `tests/test_json.sh`: validates `json_escape_string` with special chars (quotes, backslash, newlines, Unicode); validates `assemble_check_object` produces valid JSON via `python3 -c "import json; json.loads(...)"`

### Integration tests
- `tests/test_transport.sh`: starts `tools/mock_server.py` on localhost:18765; calls `ship_splunk_hec` with TLS verify=false; asserts HTTP 200 on valid token, HTTP 403 on bad token; checks `GET /_events` to verify correct HEC envelope structure

### End-to-end smoke test
```bash
bash posturectl.sh --config tests/fixtures/config_minimal.json --dry-run --output -
# Pipe to: python3 -c "import json,sys; json.loads(sys.stdin.read()); print('valid JSON')"
```

### `config_minimal.json` (for CI/local runs without a real endpoint)
```json
{
  "collection": { "timeout_per_check_secs": 5 },
  "output": { "file": "-" },
  "transport": { "enabled": false }
}
```

---

## Sample Splunk Queries

```spl
// 1. All hosts where firewall disabled (latest report per host)
index=macos_security sourcetype="posturectl:posture"
| dedup host sortby -_time
| where posture.firewall_global_state.status="fail"
| table host, collected_at, posture.firewall_global_state.value

// 2. Hosts missing latest macOS build (adapt BUILD constant)
index=macos_security sourcetype="posturectl:posture"
| dedup host sortby -_time
| where os.build!="24D70"
| table host, os.version, os.build, collected_at

// 3. Admin users with FileVault off
index=macos_security sourcetype="posturectl:posture"
| dedup host sortby -_time
| where posture.is_admin.value=true AND posture.filevault.status="fail"
| table host, user.current_user, os.version, collected_at

// 4. Pass rate trend (per check, last 30 days)
index=macos_security sourcetype="posturectl:posture" earliest=-30d
| timechart span=1d
    avg(eval(if(posture.filevault.status="pass",1,0))) as filevault_pass_rate,
    avg(eval(if(posture.gatekeeper.status="pass",1,0))) as gatekeeper_pass_rate,
    avg(eval(if(posture.sip.status="pass",1,0))) as sip_pass_rate
```

---

## Mock Server (`tools/mock_server.py`)

Stdlib-only Python3 HTTPS server (no pip). Features:
- Generates self-signed cert via `openssl` subprocess at startup
- Validates `Authorization: Splunk TOKEN` or `Authorization: Bearer TOKEN`
- Returns `{"text":"Success","code":0}` on 200 or `{"text":"Invalid token","code":4}` on 403
- `GET /_events` — dump all received event bodies (for test assertions)
- `GET /_health` — liveness
- `GET /_reset` — clear event log
- `--mode http` — plain HTTP for simpler curl tests

---

## Implementation Sequence

1. **Foundation**: `lib/utils.sh` (logging, `run_with_timeout`, `detect_environment`) + `tests/test_json.sh` scaffold
2. **JSON layer**: `lib/json.sh` (`json_escape_string`, `assemble_check_object`, `assemble_full_report`) + JSON unit tests
3. **Checks**: `lib/checks.sh` (all 22 functions) + fixture files + `tests/test_checks.sh`
4. **Report assembly + output**: `posturectl.sh` main loop + atomic write + `--dry-run` working end-to-end
5. **Transport**: `lib/transport.sh`, `lib/keychain.sh`, `tools/mock_server.py`, `tests/test_transport.sh`
6. **Config + CLI**: `load_config` (Python3 JSON parse), `parse_args`, `config/posturectl.json.example`
7. **Packaging**: `launchd/*.plist`, `install.sh`, `uninstall.sh`
8. **Docs + examples**: `docs/`, `examples/splunk/`, `examples/output_sample.json`, expand `README.md`

---

## Critical Files

- [posturectl.sh](posturectl.sh) — main entry point; CLI, config loading, orchestration
- [lib/checks.sh](lib/checks.sh) — 22 check functions; highest maintenance surface
- [lib/utils.sh](lib/utils.sh) — `run_with_timeout` correctness is critical (no-hang guarantee)
- [lib/json.sh](lib/json.sh) — Python3/manual JSON split; output validity must be testable
- [lib/transport.sh](lib/transport.sh) — Splunk HEC + HTTPS POST with retry
- [lib/keychain.sh](lib/keychain.sh) — secrets handling via `security` CLI
- [tools/mock_server.py](tools/mock_server.py) — enables offline transport tests
- [tests/test_checks.sh](tests/test_checks.sh) — fixture-driven parser unit tests

---

---

## SilentKnight / silnite Delta Analysis

silnite (Howard Oakley / Eclectic Light Company) performs ~40+ checks. Mapping against our current plan:

### Already Covered

| silnite field | posturectl equivalent |
|---|---|
| Mac model identifier | `host.model` (from `sysctl -n hw.model`) |
| macOS version + build | `os.version`, `os.build` |
| SIP enabled/disabled | `posture.sip` |
| FileVault enabled | `posture.filevault` |
| Gatekeeper/assessments enabled | `posture.gatekeeper` |
| Secure Boot level (Apple Silicon) | `posture.secure_boot` |
| XProtect version | `posture.xprotect_version` |
| MRT version | `posture.mrt_version` |

### Missing — Added Now

#### Core v1 additions

**Check 23 — `firmware_version`** (core v1)
- **Source**: `system_profiler SPHardwareDataType` (slow: apply 30s timeout)
  - Intel (no T2): grep `"Boot ROM Version:"`
  - Intel (T2): also grep `"Bridge OS Version:"` for iBridge
  - Apple Silicon: grep `"System Firmware Version:"` (reports iBoot version)
- **Arch detection**: `uname -m` — `arm64` vs `x86_64`
- **Privilege**: user
- **JSON value**: `{"firmware_type":"efi|iboot","firmware_version":"<string>","bridge_version":"<string>|null"}`
- **status**: always `"pass"` (inventory only; no baseline comparison in v1 — see v2 note)
- **macOS stability**: stable 12–15; key name may vary; always grep for substring
- **Pitfall**: `system_profiler` is the slowest check (~2–5s). Run last. Rosetta on Apple Silicon returns Intel firmware info when called from an Intel binary — ensure script runs native (arm64 shell is native on Apple Silicon by default).

**Check 24 — `xprotect_remediator_version`** (core v1)
- silnite v7+ distinguishes **XProtect.bundle** (signature data, e.g. "5274") from **XProtect Remediator** (background scanner, e.g. "157") — two separate components.
- **Source**: `defaults read /Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist CFBundleShortVersionString`
- **Fallback**: `stat -f "%z" /Library/Apple/System/Library/CoreServices/XProtect.app` (non-zero = present)
- **Note**: On macOS 15 (Sequoia), XProtect data moved to `/private/var/protected/xprotect/`; XProtect.app remains in CoreServices. Add path probe for both.
- **Privilege**: user
- **status**: `"pass"` if non-empty version returned; `"unknown"` if path missing

**Check 25 — `xprotect_last_update`** (core v1)
- silnite reports XProtect last update timestamp; valuable for "is this machine receiving security updates?"
- **Source**: file modification time of XProtect.bundle
  ```bash
  stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" \
    /Library/Apple/System/Library/CoreServices/XProtect.bundle
  ```
- **Fallback** (macOS 15): same but `/private/var/protected/xprotect/XProtect.bundle`
- **Privilege**: user
- **JSON value**: RFC3339 timestamp string
- **status**: `"pass"` if within configurable staleness threshold (default: 30 days); `"fail"` if older; `"unknown"` if stat fails
- **macOS stability**: `stat -f "%Sm"` format stable 12–15

**Check 26 — `mrt_last_update`** (core v1)
- Same rationale as above
- **Source**: `stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" /Library/Apple/System/Library/CoreServices/MRT.app`
- **Privilege**: user
- **status**: same staleness logic as xprotect_last_update

**Check 27 — `pending_updates`** (core v1)
- silnite sets `UpdateWaiting=1` when software updates are pending
- **Source**: read cached SoftwareUpdate plist — NO network call:
  ```bash
  defaults read /Library/Preferences/com.apple.SoftwareUpdate RecommendedUpdates 2>/dev/null
  ```
  Returns an array of plist dicts (update names) or empty/error.
- **Fallback**: `defaults read /Library/Preferences/com.apple.SoftwareUpdate LastUpdatesAvailable` (integer count)
- **Privilege**: user
- **JSON value**: integer count of pending updates (0 = none)
- **status**: `"pass"` if count == 0; `"warn"` if count > 0 (updates available but not emergency); `"unknown"` if key missing
- **Pitfall**: This plist reflects the last background check by `softwareupdated`, not a live query. May be stale if SU daemon is broken. Report `collected_from: "cached_plist"` in evidence.

#### Optional v1 additions

**Check 28 — `tcc_version`** (optional v1)
- silnite reports the TCC private data version (e.g. "150.19"); useful for confirming TCC is up-to-date with OS patches
- **Source**:
  ```bash
  defaults read /System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/Info.plist \
    CFBundleVersion 2>/dev/null
  ```
- **Privilege**: user (read-only; TCC.framework is in SIP-protected area but readable)
- **macOS stability**: path structure stable 12–14; on 15 the framework may be in the dyld shared cache only — if path missing, mark `unknown` and note in error field
- **status**: always `"pass"` (version is inventory only; no expected-version comparison in v1)
- **Enable in config**: `"disabled_checks": []` leaves it in; `"disabled_checks": ["tcc_version"]` skips it

**Check 29 — `xprotect_assessments_enabled`** (optional v1)
- silnite explicitly reports whether XProtect assessments are active (separate from Gatekeeper master switch)
- **Source**: same `spctl --status 2>&1` as `gatekeeper` check — the output confirms both Gatekeeper AND assessments in one call. In practice this duplicates `posture.gatekeeper.value`. We can derive it from the same run.
- **Implementation**: merge into the existing `check_gatekeeper()` function; add `xprotect_assessments_enabled` as a sub-field in the value object: `{"state":"enabled","assessments_enabled":true}`
- **No new command needed**; slight schema change to gatekeeper value

#### v2 / Future (not in v1)

| silnite feature | Decision | Rationale |
|---|---|---|
| **EFI "expected version" comparison** | v2 | Requires lookup table keyed by model × macOS build. silnite fetches from `github.com/hoakleyelc/updates` — we explicitly do NOT want a hard network dependency. v2: bundle a static JSON table + optional cached remote fetch with stale-ok semantics |
| **Gatekeeper "version"** | Skip | Removed from silnite v10 as defunct. Not meaningful on modern macOS |
| **SSV (Signed System Volume) seal** | v2 | `diskutil apfs list` + grep `Sealed` works but is complex to parse reliably across versions; low incremental value vs what SIP check already provides |
| **KEXT exclude list version** | v2 | Kernel extensions largely deprecated on Apple Silicon; value is niche; `kmutil` output parsing is fragile across versions |
| **Studio Display / iBridge firmware** | v2 | Only relevant for T2 Intel Macs and Studio Display owners; can be added as sub-field of `firmware_version` when `bridge_version` is non-null |

### Schema Updates for Delta Checks

Add to `posture` section of the JSON document:

```json
"firmware_version": {
  "status": "pass",
  "value": {"firmware_type": "iboot", "firmware_version": "iBoot-8422.141.2", "bridge_version": null},
  "raw": "System Firmware Version: iBoot-8422.141.2",
  "privilege": "user",
  "check_duration_ms": 3200,
  "error": null
},
"xprotect_remediator_version": {
  "status": "pass",
  "value": "157",
  "raw": "157",
  "privilege": "user",
  "check_duration_ms": 31,
  "error": null
},
"xprotect_last_update": {
  "status": "pass",
  "value": "2026-02-17T09:22:11Z",
  "raw": "2026-02-17T09:22:11Z",
  "privilege": "user",
  "check_duration_ms": 18,
  "error": null
},
"mrt_last_update": {
  "status": "pass",
  "value": "2026-01-30T14:05:44Z",
  "raw": "2026-01-30T14:05:44Z",
  "privilege": "user",
  "check_duration_ms": 17,
  "error": null
},
"pending_updates": {
  "status": "warn",
  "value": 2,
  "raw": "(macOS 15.3.2, XProtect Data 2025-02-20)",
  "privilege": "user",
  "check_duration_ms": 42,
  "error": null
},
"tcc_version": {
  "status": "pass",
  "value": "150.19",
  "raw": "150.19",
  "privilege": "user",
  "check_duration_ms": 22,
  "error": null
}
```

Gatekeeper value updated (backward-compatible — adding sub-key to existing object):
```json
"gatekeeper": {
  "status": "pass",
  "value": {"state": "enabled", "assessments_enabled": true},
  "raw": "assessments enabled",
  "privilege": "user",
  "check_duration_ms": 88,
  "error": null
}
```

### Updated Check Count: 29 checks (22 original + 7 from silnite delta)

New total in `summary`:
```json
"summary": { "total": 29, "pass": 20, "fail": 0, "warn": 3, "unknown": 6, "score_pct": 87 }
```

### "Expected Version" Design (v2 Preview)

For EFI/iBoot baseline comparison (not v1, documented here for later):

**Approach**: bundle a static JSON file `config/firmware_baseline.json` keyed by model × macOS build:
```json
{
  "MacBookPro18,3": {
    "15.3.1": {"firmware_version": "iBoot-8422.141.2"},
    "14.7.2": {"firmware_version": "iBoot-7459.141.2"}
  }
}
```
Optional remote update: `GET https://your-internal-cdn/posturectl/firmware_baseline.json` with a 10-second timeout, write to local cache at `/Library/Application Support/posturectl/firmware_baseline_cache.json`. If fetch fails: use local cache; if no cache: skip comparison and mark `"baseline_source": "unavailable"`. **Never block the collector run on remote availability.** The silnite approach of fetching from `github.com/hoakleyelc/updates` is explicitly excluded as a hard dependency.

---

## Verification Checklist

```bash
# 1. JSON validity
bash posturectl.sh --dry-run --output - | python3 -c "import json,sys; json.loads(sys.stdin.read()); print('JSON OK')"

# 2. Parser unit tests (no live commands needed)
bash tests/run_tests.sh

# 3. Transport test (mock server)
python3 tools/mock_server.py --port 18765 --mode http &
bash posturectl.sh --config tests/fixtures/config_mock.json
curl -s http://localhost:18765/_events | python3 -m json.tool
kill %1

# 4. Splunk HEC (real endpoint)
bash posturectl.sh --config /etc/posturectl/posturectl.json --verbose

# 5. Timeout test
bash posturectl.sh --check filevault --verbose  # must complete in <15s

# 6. Root vs user mode
bash posturectl.sh --dry-run --output -           # user mode: root checks = unknown
sudo bash posturectl.sh --dry-run --output -      # root mode: all checks run
```
