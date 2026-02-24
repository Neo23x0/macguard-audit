# macguard-audit — Operator Manual

## Quick Start

```bash
# 1. Run a one-shot scan to stdout
bash macguard-audit.sh --checks-only --pretty

# 2. Debug a single check
bash macguard-audit.sh --check filevault --verbose

# 3. Run with a config file (no shipping)
bash macguard-audit.sh --config /etc/macguard-audit/macguard-audit.json --dry-run --output /tmp/posture.json
```

## Installation

```bash
sudo bash install.sh             # LaunchDaemon (root, hourly, all checks)
bash install.sh --user-agent     # LaunchAgent (user, every 4h, user-level checks only)
bash install.sh --no-service     # Copy files only; set up service manually
```

## Configuration

Config file: `/etc/macguard-audit/macguard-audit.json` (daemon) or
`/Library/Application Support/macguard-audit/macguard-audit.json` (agent).

Start from the example: `config/macguard-audit.json.example`

Key fields:

| Field | Default | Description |
|-------|---------|-------------|
| `collection.enabled_checks` | `"all"` | List of check names or `"all"` |
| `collection.disabled_checks` | `[]` | Checks to skip |
| `collection.timeout_per_check_secs` | `15` | Max seconds per check |
| `collection.run_root_checks` | `false` | Enable root-required checks (daemon only) |
| `output.file` | `"-"` | Output path (`-` = stdout) |
| `transport.enabled` | `false` | Enable shipping |
| `transport.type` | `"splunk_hec"` | `splunk_hec` or `https_post` |

See `config/macguard-audit.schema.json` for full schema.

## Token Storage

### Recommended: macOS Keychain

```bash
# For daemon (System keychain, requires root):
sudo security add-generic-password \
  -k /Library/Keychains/System.keychain \
  -s macguard-audit -a splunk_hec_token \
  -w "YOUR_TOKEN" -U

# For user agent (login keychain):
security add-generic-password \
  -s macguard-audit -a splunk_hec_token \
  -w "YOUR_TOKEN" -U
```

Set `token_source: "keychain"` in config (default).

### Alternative: Environment Variable

```bash
export MACGUARD_SPLUNK_TOKEN="YOUR_TOKEN"
bash macguard-audit.sh --config ...
```

Set `token_source: "env"` and `token_env_var: "MACGUARD_SPLUNK_TOKEN"` in config.

### Not Recommended: Config File

```json
"token_source": "config",
"token_config_value": "YOUR_TOKEN"
```

Ensure config file permissions are 600: `chmod 600 /etc/macguard-audit/macguard-audit.json`

## Scheduling

### LaunchDaemon (root, hourly)

```
/Library/LaunchDaemons/com.example.macguard-audit.plist
```

Manage:
```bash
sudo launchctl load   -w /Library/LaunchDaemons/com.example.macguard-audit.plist
sudo launchctl unload -w /Library/LaunchDaemons/com.example.macguard-audit.plist
sudo launchctl list com.example.macguard-audit
```

Logs: `/var/log/macguard-audit/daemon.out.log` and `daemon.err.log`

### LaunchAgent (user, every 4 hours)

```
~/Library/LaunchAgents/com.example.macguard-audit-user.plist
```

Manage:
```bash
launchctl load   -w ~/Library/LaunchAgents/com.example.macguard-audit-user.plist
launchctl unload -w ~/Library/LaunchAgents/com.example.macguard-audit-user.plist
```

## CLI Reference

```
macguard-audit.sh [OPTIONS]

  -c, --config FILE     Config JSON file
  -o, --output FILE     Write to FILE ("-" = stdout, default)
  -n, --dry-run         Collect + write; skip shipping
      --checks-only     Run all checks, print to stdout; skip transport
      --ship-only FILE  Ship existing report FILE; skip recollection
      --check NAME      Run only the named check (debug)
      --list-checks     List all available check names
  -v, --verbose         Print each check result to stderr
  -p, --pretty          Pretty-print JSON (requires python3)
      --version         Print version
      --help            Show this message
```

## Troubleshooting

### Command timed out
Increase `timeout_per_check_secs` in config. `firmware_version` is the slowest check (~2–5s typically, up to 30s on loaded systems).

### Checks show `unknown` for firewall/profiles/system_extensions
These require root. Run via LaunchDaemon with `run_root_checks: true`, or use `sudo bash macguard-audit.sh`.

### auto_updates shows `unknown`
The `softwareupdate --schedule` command may be slow or behave differently depending on macOS version and network state. The plist fallback (`AutomaticCheckEnabled`) is tried first. If both fail, `unknown` is reported — this is benign.

### time_sync shows `unknown`
`systemsetup -getusingnetworktime` is deprecated on macOS 15. The `launchctl list com.apple.timed` fallback is tried. If neither works, `unknown` is reported.

### JSON output has `"value": null` for root checks
This is expected when running as a non-root user. Root-required checks produce `status: "unknown"` and `value: null`.

### TLS errors when shipping
- Check that `tls_verify: true` and the endpoint has a valid certificate.
- For testing with `mock_server.py`: set `tls_verify: false` (not for production).
- On macOS, curl uses the system trust store; corporate CAs should be added via Keychain Access.

## Uninstall

```bash
sudo bash uninstall.sh           # Remove files and service
sudo bash uninstall.sh --purge   # Also remove config and logs
```

Keychain tokens are not removed automatically:
```bash
security delete-generic-password -s macguard-audit -a splunk_hec_token
security delete-generic-password -s macguard-audit -a https_post_token
```

## Adding Custom Checks

1. Add a function `check_your_check_name()` to `lib/checks.sh` following the existing pattern.
2. Add the name to `ENABLED_CHECKS` array.
3. Add a fixture file to `tests/fixtures/` and test cases to `tests/test_checks.sh`.
4. Add to `assemble_check_object()` in `lib/json.sh` if the value type is not a plain string.
