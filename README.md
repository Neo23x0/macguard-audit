# macguard-audit

Lightweight macOS security posture reporter. Collects 28 local security configuration signals and outputs structured JSON — optionally shipped to Splunk HEC or any HTTPS ingest endpoint.

**No MDM required. No Homebrew. No pip. Runs on macOS 12–15.**

---

## Features

- **28 checks** covering FileVault, Gatekeeper, SIP, firewall, SSH, screen lock, auto-login, guest account, XProtect, MRT, auto-updates, pending updates, admin status, NTP, AirDrop, remote management, browser versions, APFS encryption, Secure Boot, TCC, configuration profiles, system extensions, and firmware version.
- **Pure bash** (3.2+) + Apple-provided `/usr/bin/python3` for JSON marshaling. Zero external dependencies.
- **Splunk HEC** and **generic HTTPS POST** transport with retry logic.
- **macOS Keychain** token storage via `security(1)` — no tokens on disk.
- **LaunchDaemon** (root, hourly) and **LaunchAgent** (user, 4-hourly) scheduling.
- **Atomic file writes**, configurable JSONL rotation.
- **Fixture-driven unit tests** — 118 tests, no live commands required.

---

## Quick Start

```bash
# Clone
git clone https://github.com/example/macguard-audit.git
cd macguard-audit

# Run a scan (no config needed)
bash macguard-audit.sh --checks-only --pretty

# Debug a single check
bash macguard-audit.sh --check filevault --verbose

# List all available checks
bash macguard-audit.sh --list-checks

# Run tests
bash tests/run_tests.sh
```

---

## Checks

| # | Check | Description | Root? |
|---|-------|-------------|-------|
| 01 | `filevault` | FileVault full-disk encryption | No |
| 02 | `gatekeeper` | Gatekeeper / app notarization enforcement | No |
| 03 | `sip` | System Integrity Protection | No |
| 04 | `firewall_global_state` | Application Firewall enabled | **Yes** |
| 05 | `firewall_stealth_mode` | Firewall stealth mode | **Yes** |
| 06 | `firewall_logging` | Firewall logging | **Yes** |
| 07 | `ssh_remote_login` | Remote Login (SSH) disabled | No |
| 08 | `screen_lock_timeout` | Screen lock idle timeout ≤ 10 min | No |
| 09 | `auto_login` | Automatic login disabled | No |
| 10 | `guest_account` | Guest account disabled | No |
| 11 | `xprotect_version` | XProtect signature version | No |
| 12 | `xprotect_remediator_version` | XProtect Remediator version | No |
| 13 | `xprotect_last_update` | XProtect last updated within 30 days | No |
| 14 | `mrt_version` | Malware Removal Tool version | No |
| 15 | `mrt_last_update` | MRT last updated within 30 days | No |
| 16 | `auto_updates` | Automatic software update checks enabled | No |
| 17 | `pending_updates` | No pending software updates | No |
| 18 | `is_admin` | Current user is not an admin (warn) | No |
| 19 | `time_sync` | NTP/network time enabled | No |
| 20 | `airdrop` | AirDrop set to Off or Contacts Only | No |
| 21 | `remote_management` | Screen Sharing / Remote Desktop disabled | No |
| 22 | `browser_versions` | Browser inventory (Safari, Chrome, Firefox, Brave, Edge, Arc) | No |
| 23 | `disk_encryption_apfs` | APFS volume FileVault encrypted | No |
| 24 | `secure_boot` | Secure Boot at Full Security | No |
| 25 | `tcc_version` | TCC framework version (inventory) | No |
| 26 | `profiles` | Configuration profiles inventory | **Yes** |
| 27 | `system_extensions` | System extensions inventory | **Yes** |
| 28 | `firmware_version` | EFI/iBoot firmware version (inventory) | No |

Full details: [docs/checks.md](docs/checks.md)

---

## Output Format

```json
{
  "schema_version": "1.0",
  "tool": "macguard-audit",
  "tool_version": "1.0.0",
  "collected_at": "2026-02-23T21:24:19Z",
  "collection_duration_ms": 7829,
  "run_as_root": false,
  "collection_warnings": [],
  "host": {
    "hostname": "mbp-neo.local",
    "hardware_uuid": "A1B2C3D4-...",
    "model": "Mac14,6",
    "arch": "arm64",
    "org_id": "acme-corp"
  },
  "os": {
    "name": "macOS",
    "version": "15.3.1",
    "build": "24D70"
  },
  "posture": {
    "filevault": {
      "status": "pass",
      "value": "enabled",
      "raw": "FileVault is On.",
      "privilege": "user",
      "check_duration_ms": 142,
      "error": null
    }
  },
  "summary": {
    "total": 28,
    "pass": 20,
    "fail": 0,
    "warn": 2,
    "unknown": 6,
    "score_pct": 91
  }
}
```

See [examples/output_sample.json](examples/output_sample.json) for a complete real-world output.

---

## Transport

### Splunk HEC

```json
{
  "transport": {
    "enabled": true,
    "type": "splunk_hec",
    "splunk_hec": {
      "url": "https://splunk.example.com:8088/services/collector/event",
      "token_source": "keychain",
      "token_keychain_service": "macguard-audit",
      "token_keychain_account": "splunk_hec_token",
      "index": "macos_security",
      "sourcetype": "macguard:posture"
    }
  }
}
```

Store the token:
```bash
sudo security add-generic-password \
  -k /Library/Keychains/System.keychain \
  -s macguard-audit -a splunk_hec_token \
  -w "YOUR_HEC_TOKEN" -U
```

Sample SPL queries: [examples/splunk/queries.spl](examples/splunk/queries.spl)

### Generic HTTPS POST

```json
{
  "transport": {
    "enabled": true,
    "type": "https_post",
    "https_post": {
      "url": "https://ingest.example.com/api/v1/events",
      "token_source": "keychain"
    }
  }
}
```

---

## Installation

```bash
# System-wide (LaunchDaemon, root, hourly)
sudo bash install.sh

# User only (LaunchAgent, every 4 hours)
bash install.sh --user-agent

# Files only, no service
sudo bash install.sh --no-service

# Uninstall
sudo bash uninstall.sh
sudo bash uninstall.sh --purge   # also remove config + logs
```

Config file: `/etc/macguard-audit/macguard-audit.json`
Example: [config/macguard-audit.json.example](config/macguard-audit.json.example)

---

## Development

### Run Tests

```bash
bash tests/run_tests.sh                    # JSON + check parser unit tests (118 tests)
RUN_TRANSPORT_TESTS=true bash tests/run_tests.sh   # also run transport integration tests
```

### Transport Integration Tests (Mock Server)

```bash
# Manual
python3 tools/mock_server.py --port 18765 --mode http &
bash tests/test_transport.sh
kill %1
```

### Verify JSON Output

```bash
bash macguard-audit.sh --checks-only | python3 -c "import json,sys; json.loads(sys.stdin.read()); print('OK')"
```

---

## Compatibility

- macOS 12 Monterey — macOS 15 Sequoia
- Bash 3.2+ (system bash; no Homebrew bash required)
- Python3 (Apple-provided via Xcode CLT; used for JSON marshaling)
- `curl` (pre-installed on macOS)

---

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
