# macguard-audit — Threat Model

## Scope

macguard-audit is a **read-only audit tool**. It collects local security posture signals, structures them as JSON, and optionally ships to a remote ingest endpoint. It does not enforce policy, modify system configuration, or install software.

## Assets

| Asset | Value | Owner |
|-------|-------|-------|
| Splunk/HTTPS ingest token | High — unauthorized access to SIEM | Operator |
| Device serial number | Medium — links report to physical hardware | Organization |
| Posture report (JSONL) | Medium — reveals security state | Organization |
| Shell scripts | Low — no secrets embedded | Organization |

## Threat Actors

- **Opportunistic attacker with local user access** — can read world-readable files, inspect process environment, run commands as the user.
- **Malicious insider (admin)** — can modify scripts, read keychain if they have the user password, disable launchd services.
- **Network attacker (MitM)** — can intercept in-transit data.
- **Compromised endpoint** — if the device is already compromised, the posture report may be falsified by the attacker.

---

## Threat Analysis

### T1: Token Exposure in Config File

**Risk**: Token in plaintext in `macguard-audit.json` is readable by any user who can read the file.

**Mitigations**:
- `lib/keychain.sh::check_config_token_file_permissions()` warns if config permissions exceed 600.
- `install.sh` creates the config with `chmod 600` (daemon) or advises user to set it.
- Recommended `token_source: "keychain"` — token stored in macOS Keychain, never on disk in plaintext.
- `token_source: "env"` is acceptable for ephemeral CI runs where the env is not persisted.

**Residual**: An admin-level attacker with keychain access (e.g., knows the login password) can retrieve the token from the Keychain. This is an accepted risk — the Keychain is the macOS-standard mechanism for this class of secret.

### T2: Token in Transit

**Risk**: Splunk HEC token sent in `Authorization: Splunk TOKEN` header; captured by MitM.

**Mitigations**:
- `tls_verify: true` (default) — curl validates server certificate against system trust store.
- HTTPS-only endpoints assumed.

**Residual**: If `tls_verify: false` is set (testing only), tokens can be captured. A warning is logged when TLS verification is disabled.

### T3: Report Tampering in Transit

**Risk**: Attacker modifies posture report between collection and ingest (replay or injection).

**Mitigations**:
- HTTPS with TLS (same as T2).
- Splunk HEC uses per-request token auth — a replayed request with a valid token will succeed, but Splunk timestamps give ordering context.

**Residual**: No per-report HMAC signing in v1. A v2 enhancement could sign each report with an HMAC keyed on the token for replay-tamper detection.

### T4: Report Tampering at Rest

**Risk**: Local JSONL output file modified after collection (on disk).

**Mitigations**:
- LaunchDaemon output file owned by root, in `/var/log/macguard-audit/` (chmod 750, owner root:wheel).
- Atomic write (`mv(1)`) prevents partial file reads during shipping.

**Residual**: Root-level attacker can modify the file. No cryptographic signing in v1.

### T5: Spoofed Host Identity

**Risk**: Attacker sends a fabricated report with a different hostname to manipulate posture dashboard.

**Mitigations**:
- Reports include `host.hardware_uuid` (hardware-bound, harder to spoof than hostname).
- `host.hostname` is explicitly advisory.
- Serial hash (when `hash_serial: true` + salt set) provides a consistent, privacy-preserving device identifier.

**Residual**: A root-level attacker on the device can set arbitrary values for any field. Endpoint posture reports are fundamentally self-attested — this is an inherent limitation of agent-based approaches without a hardware attestation chain (e.g., Apple Secure Boot + MDM enrollment challenge).

### T6: Privilege Escalation via Scripts

**Risk**: Script with elevated permissions (owned by root) is modified by an attacker to run arbitrary code.

**Mitigations**:
- `install.sh` sets `macguard-audit.sh` and `lib/*.sh` to root:wheel ownership, chmod 755/644.
- LaunchDaemon plist is owned root:wheel, chmod 644.
- These permissions prevent modification by unprivileged users.

**Residual**: Admin-level attacker with `sudo` can modify files. Standard macOS admin privileges boundary applies.

### T7: Sensitive Data in Reports

**Risk**: Reports contain privacy-sensitive information (browsing history, process list, credentials).

**Mitigations**:
- No browsing history, process list, network connections, or credential data is collected.
- Serial number is hashed with an org-controlled salt (`hash_serial: true`, default).
- `current_user` and `console_user` are included by design (necessary for `is_admin` correlation).

**Residual**: Reports contain hostname, hardware UUID, OS version, and username — standard endpoint inventory data. Operators should treat JSONL files and SIEM indices containing this data as sensitive.

### T8: Posturectl Disabled by Attacker

**Risk**: Attacker unloads or kills the LaunchDaemon to suppress future reports, providing a false sense of compliance.

**Mitigations**:
- LaunchDaemon plist is root-owned; non-admin users cannot unload it.
- SIEM-side: alert on hosts that have not submitted a report within 2× the scheduled interval (e.g., 2 hours for hourly runs).
- `launchctl list com.example.macguard-audit` can be checked from a separate monitoring tool.

**Residual**: Admin-level attacker can disable the service. Monitor for gaps in SIEM data.

---

## Security Properties Summary

| Property | Status | Notes |
|----------|--------|-------|
| Confidentiality of token in transit | **Strong** | HTTPS + TLS verification |
| Confidentiality of token at rest | **Strong** | macOS Keychain (recommended) |
| Integrity of report in transit | **Medium** | TLS only; no HMAC in v1 |
| Integrity of report at rest | **Medium** | Root-owned file; no signing in v1 |
| Host authenticity | **Weak** | Self-attested; hardware UUID advisory |
| Least privilege | **Good** | User-level by default; root only when configured |
| Secret minimization | **Good** | No credentials/PII collected |

## Out of Scope

- Physical attacks (Evil Maid, DMA).
- Hardware-level firmware attacks (Thunderstrike, etc.).
- Pre-boot tampering (covered by Secure Boot check as an indicator, not a defense).
- macOS itself being compromised — if the OS is untrusted, so is any agent running on it.
