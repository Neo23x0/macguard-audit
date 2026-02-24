# macguard-audit — Check Inventory

28 checks in default run order. Root-required checks are skipped (status=`unknown`) when not running as root.

| # | Key | Command | Priv | Pass Condition | Notes |
|---|-----|---------|------|---------------|-------|
| 01 | `filevault` | `fdesetup status` | user | contains "FileVault is On" | Apple Silicon appends extra text; "On" substring is sufficient |
| 02 | `gatekeeper` | `spctl --status 2>&1` | user | "assessments enabled" | Output goes to stderr on macOS 15; use `2>&1` |
| 03 | `sip` | `csrutil status` | user | "enabled" without "Custom Configuration" | Custom Config = warn; Recovery not needed for read |
| 04 | `firewall_global_state` | `socketfilterfw --getglobalstate` | **root** | "Firewall is enabled" | Silently skipped if not root |
| 05 | `firewall_stealth_mode` | `socketfilterfw --getstealthmode` | **root** | "Stealth mode enabled" | Silently skipped if not root |
| 06 | `firewall_logging` | `socketfilterfw --getloggingmode` | **root** | "Log mode is on" | Silently skipped if not root |
| 07 | `ssh_remote_login` | `systemsetup -getremotelogin` | user | "Remote Login: Off" | Deprecated in macOS 15; fallback: `launchctl list com.openssh.sshd` |
| 08 | `screen_lock_timeout` | `defaults read .../com.apple.screensaver idleTime` | user | 0 < value ≤ 600 (configurable) | Key missing = unknown; MDM-managed timeout may not appear here |
| 09 | `auto_login` | `defaults read .../com.apple.loginwindow DisableAutoLogin` | user | value == "1" | Key absent = fail (not explicitly disabled) |
| 10 | `guest_account` | `defaults read .../com.apple.loginwindow GuestEnabled` | user | value == "0" or key missing | Key absent = pass (default off) |
| 11 | `xprotect_version` | `defaults read .../XProtect.bundle/Contents/Info.plist CFBundleShortVersionString` | user | non-empty string | Probes two paths for macOS 15 compatibility |
| 12 | `xprotect_remediator_version` | `defaults read .../XProtect.app/Contents/Info.plist CFBundleShortVersionString` | user | non-empty string | XProtect.app (scanner) is distinct from XProtect.bundle (signatures) |
| 13 | `xprotect_last_update` | `stat -f "%Sm"` on XProtect.bundle | user | mtime within 30 days | Staleness threshold not configurable in v1 |
| 14 | `mrt_version` | `defaults read .../MRT.app/Contents/Info.plist CFBundleShortVersionString` | user | non-empty string | Probes cryptex path for macOS 15 |
| 15 | `mrt_last_update` | `stat -f "%Sm"` on MRT.app | user | mtime within 30 days | |
| 16 | `auto_updates` | `defaults read .../com.apple.SoftwareUpdate AutomaticCheckEnabled` | user | value == "1" | Fallback: `softwareupdate --schedule` (slow, 15s timeout) |
| 17 | `pending_updates` | `defaults read .../com.apple.SoftwareUpdate RecommendedUpdates` | user | count == 0 (pass); count > 0 (warn) | Reads cached plist — no live network call |
| 18 | `is_admin` | `dseditgroup -o checkmember -m $USER admin` | user | non-member = pass; member = warn (or fail if `is_admin_is_fail=true`) | Uses exit code not text |
| 19 | `time_sync` | `systemsetup -getusingnetworktime` | user | "Network Time: On" | Deprecated in macOS 15; fallback: `launchctl list com.apple.timed` |
| 20 | `airdrop` | `defaults read com.apple.sharingd DiscoverableMode` | user | "Off" = pass; "Contacts Only" = warn; "Everyone" = fail | Policy configurable via `airdrop_policy` |
| 21 | `remote_management` | `launchctl list com.apple.screensharing` | user | non-zero exit (disabled) = pass | Also checks `com.apple.RemoteDesktop.agent` |
| 22 | `browser_versions` | `defaults read APP/Contents/Info.plist CFBundleShortVersionString` | user | non-empty per installed browser | Checks Safari, Chrome, Firefox, Brave, Edge, Arc |
| 23 | `disk_encryption_apfs` | `diskutil apfs list` | user | `FileVault: Yes` | Complements `filevault` check; skips non-APFS volumes |
| 24 | `secure_boot` | Apple Silicon: `bputil -d 2>&1`; Intel: `nvram` GUID key | user | Full Security / 0x03 | Detects arch via `uname -m` |
| 25 | `tcc_version` | `defaults read /System/Library/.../TCC.framework/.../Info.plist CFBundleVersion` | user | non-empty (inventory only) | May be absent on macOS 15 (dyld shared cache) |
| 26 | `profiles` | `profiles -P` | **root** | informational (count of profiles; no allowlist in v1) | Skipped without root |
| 27 | `system_extensions` | `systemextensionsctl list` | **root** | informational (no allowlist in v1) | Format changed macOS 13+; parses `[activated enabled]` token |
| 28 | `firmware_version` | `system_profiler SPHardwareDataType` | user | inventory only | Slowest check (~2–5s); runs last |

## Status Values

| Status | Meaning |
|--------|---------|
| `pass` | Check condition met |
| `fail` | Check condition not met |
| `warn` | Condition partially met (e.g., AirDrop = Contacts Only, user is admin) |
| `unknown` | Cannot determine (missing root, command timed out, key not found) |

## Value Types by Check

| Check | Value Type | Example |
|-------|-----------|---------|
| `filevault` | string | `"enabled"` / `"disabled"` |
| `gatekeeper` | object | `{"state":"enabled","assessments_enabled":true}` |
| `sip` | string | `"enabled"` / `"disabled"` / `"custom_configuration"` |
| `firewall_*` | string | `"enabled"` / `"disabled"` |
| `ssh_remote_login` | string | `"enabled"` / `"disabled"` |
| `screen_lock_timeout` | integer | `300` (seconds) |
| `auto_login` | string | `"disabled"` / `"enabled"` / `"not_disabled"` |
| `guest_account` | string | `"disabled"` / `"enabled"` |
| `xprotect_version` | string | `"5330"` |
| `xprotect_remediator_version` | string | `"157"` |
| `xprotect_last_update` | string (RFC3339) | `"2026-02-13T03:14:55Z"` |
| `mrt_version` | string | `"1.93"` |
| `mrt_last_update` | string (RFC3339) | `"2026-02-13T03:14:55Z"` |
| `auto_updates` | string | `"enabled"` / `"disabled"` |
| `pending_updates` | integer | `0` / `2` |
| `is_admin` | boolean | `true` / `false` |
| `time_sync` | string | `"enabled"` / `"disabled"` |
| `airdrop` | string | `"off"` / `"contacts_only"` / `"everyone"` |
| `remote_management` | string | `"disabled"` / `"enabled"` |
| `browser_versions` | object | `{"safari":"18.3","chrome":"133.0","firefox":"not_installed",...}` |
| `disk_encryption_apfs` | string | `"encrypted"` / `"unencrypted"` |
| `secure_boot` | string | `"full_security"` / `"reduced_security"` / `"permissive_security"` |
| `tcc_version` | string | `"150.19"` |
| `profiles` | integer | count of installed profiles |
| `system_extensions` | string | list of activated extension IDs |
| `firmware_version` | object | `{"firmware_type":"iboot","firmware_version":"13822.x","bridge_version":null}` |

## Scoring

```
score_pct = (pass + warn*0.5) / (total - unknown) * 100
```

`unknown` checks are excluded from the denominator so that missing-root runs are not penalized.
