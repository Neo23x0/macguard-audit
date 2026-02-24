#!/usr/bin/env bash
# tests/test_checks.sh — Fixture-driven parser unit tests for lib/checks.sh
# Overrides run_with_timeout to feed fixture content instead of real commands.
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TESTS_DIR")"
FIXTURES="${TESTS_DIR}/fixtures"

# ── Bootstrap ─────────────────────────────────────────────────────────────────
PYTHON3_AVAILABLE=false
if /usr/bin/python3 --version >/dev/null 2>&1; then PYTHON3_AVAILABLE=true; fi

VERBOSE=false
_LOG_LEVEL=3

source "${REPO_ROOT}/lib/utils.sh"
source "${REPO_ROOT}/lib/json.sh"

# Platform globals needed by checks
PLATFORM_CURRENT_USER="testuser"
PLATFORM_CONSOLE_USER="testuser"
PLATFORM_UID="501"
PLATFORM_ARCH="arm64"
PLATFORM_OS_VERSION="15.3.0"
PLATFORM_OS_MAJOR="15"
RUN_AS_ROOT=false

# Default thresholds
TIMEOUT_PER_CHECK=15
THRESHOLD_SCREEN_LOCK_MAX_SECS=600
THRESHOLD_AIRDROP_POLICY="contacts_or_off"
THRESHOLD_UPDATE_STALENESS_DAYS=30
CFG_IS_ADMIN_IS_FAIL=false

source "${REPO_ROOT}/lib/checks.sh"

# ── Test harness ──────────────────────────────────────────────────────────────
_PASS=0; _FAIL=0

assert_eq() {
    local desc="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        _PASS=$(( _PASS + 1 ))
        printf '  PASS: %s\n' "$desc"
    else
        _FAIL=$(( _FAIL + 1 ))
        printf '  FAIL: %s\n' "$desc"
        printf '    expected: %s\n' "$expected"
        printf '    actual:   %s\n' "$actual"
    fi
}

# ── Fixture override mechanism ────────────────────────────────────────────────
# FIXTURE_FILE: path to file whose content becomes RWT_OUTPUT
# FIXTURE_EXIT: exit code to simulate (default 0)
FIXTURE_FILE=""
FIXTURE_EXIT=0

run_with_timeout() {
    local _timeout="$1"; shift  # ignore timeout and command
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else
        RWT_OUTPUT=""
    fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0  # Always 0; callers inspect RWT_EXIT global
}

# Helper: run a check with a given fixture
run_with_fixture() {
    local fixture_path="$1"
    local exit_code="${2:-0}"
    FIXTURE_FILE="$fixture_path"
    FIXTURE_EXIT="$exit_code"
}

# ── filevault ─────────────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/fdesetup_enabled.txt"
check_filevault
assert_eq "filevault enabled -> status=pass"    "pass"    "$CHECK_STATUS"
assert_eq "filevault enabled -> value=enabled"  "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/fdesetup_disabled.txt"
check_filevault
assert_eq "filevault disabled -> status=fail"     "fail"     "$CHECK_STATUS"
assert_eq "filevault disabled -> value=disabled"  "disabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/fdesetup_enabled_applesilicon.txt"
check_filevault
assert_eq "filevault apple-silicon -> status=pass"   "pass"    "$CHECK_STATUS"
assert_eq "filevault apple-silicon -> value=enabled" "enabled" "$CHECK_VALUE"

# Timeout simulation
FIXTURE_FILE=""
FIXTURE_EXIT=124
RWT_OUTPUT=""
check_filevault
assert_eq "filevault timeout -> unknown" "unknown" "$CHECK_STATUS"
FIXTURE_EXIT=0

# ── gatekeeper ────────────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/spctl_enabled.txt"
check_gatekeeper
assert_eq "gatekeeper enabled -> pass"     "pass"    "$CHECK_STATUS"
assert_eq "gatekeeper enabled -> value"    "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/spctl_disabled.txt"
check_gatekeeper
assert_eq "gatekeeper disabled -> fail"    "fail"    "$CHECK_STATUS"
assert_eq "gatekeeper disabled -> value"   "disabled" "$CHECK_VALUE"

# Verify gatekeeper CHECK_VALUE_JSON contains assessments_enabled
run_with_fixture "${FIXTURES}/spctl_enabled.txt"
check_gatekeeper
[[ "${CHECK_VALUE_JSON:-}" == *'"assessments_enabled":true'* ]] \
    && assert_eq "gatekeeper JSON has assessments_enabled:true" "yes" "yes" \
    || assert_eq "gatekeeper JSON has assessments_enabled:true" "yes" "no"

# ── sip ───────────────────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/csrutil_enabled.txt"
check_sip
assert_eq "sip enabled -> pass"             "pass"    "$CHECK_STATUS"
assert_eq "sip enabled -> value=enabled"    "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/csrutil_disabled.txt"
check_sip
assert_eq "sip disabled -> fail"            "fail"    "$CHECK_STATUS"
assert_eq "sip disabled -> value=disabled"  "disabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/csrutil_custom.txt"
check_sip
assert_eq "sip custom -> warn"                        "warn"               "$CHECK_STATUS"
assert_eq "sip custom -> value=custom_configuration"  "custom_configuration" "$CHECK_VALUE"

# ── firewall (root-required) ──────────────────────────────────────────────────

# Without root, should be unknown + skipped
RUN_AS_ROOT=false
FIXTURE_FILE="${FIXTURES}/socketfilterfw_on.txt"
FIXTURE_EXIT=0
check_firewall_global_state
assert_eq "firewall no-root -> unknown"  "unknown"              "$CHECK_STATUS"
assert_eq "firewall no-root -> error"    "requires root; skipped" "$CHECK_ERROR"

# With root, firewall on
RUN_AS_ROOT=true
run_with_fixture "${FIXTURES}/socketfilterfw_on.txt"
check_firewall_global_state
assert_eq "firewall root+on -> pass"     "pass"    "$CHECK_STATUS"
assert_eq "firewall root+on -> enabled"  "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/socketfilterfw_off.txt"
check_firewall_global_state
assert_eq "firewall root+off -> fail"      "fail"     "$CHECK_STATUS"
assert_eq "firewall root+off -> disabled"  "disabled" "$CHECK_VALUE"

# Stealth mode
run_with_fixture "${FIXTURES}/socketfilterfw_stealth_on.txt"
check_firewall_stealth_mode
assert_eq "stealth on -> pass"    "pass"    "$CHECK_STATUS"
assert_eq "stealth on -> enabled" "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/socketfilterfw_stealth_off.txt"
check_firewall_stealth_mode
assert_eq "stealth off -> fail"     "fail"     "$CHECK_STATUS"
assert_eq "stealth off -> disabled" "disabled" "$CHECK_VALUE"

# Firewall logging
run_with_fixture "${FIXTURES}/socketfilterfw_logging_on.txt"
check_firewall_logging
assert_eq "fw logging on -> pass"    "pass"    "$CHECK_STATUS"

run_with_fixture "${FIXTURES}/socketfilterfw_logging_off.txt"
check_firewall_logging
assert_eq "fw logging off -> fail"   "fail"    "$CHECK_STATUS"

RUN_AS_ROOT=false

# ── ssh_remote_login ──────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/systemsetup_ssh_off.txt"
check_ssh_remote_login
assert_eq "ssh off -> pass"     "pass"     "$CHECK_STATUS"
assert_eq "ssh off -> disabled" "disabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/systemsetup_ssh_on.txt"
check_ssh_remote_login
assert_eq "ssh on -> fail"    "fail"    "$CHECK_STATUS"
assert_eq "ssh on -> enabled" "enabled" "$CHECK_VALUE"

# ── screen_lock_timeout ───────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/screensaver_300.txt"
check_screen_lock_timeout
assert_eq "screen_lock 300 -> pass"   "pass"  "$CHECK_STATUS"
assert_eq "screen_lock 300 -> value"  "300"   "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/screensaver_0.txt"
check_screen_lock_timeout
assert_eq "screen_lock 0 -> fail (never locks)"  "fail" "$CHECK_STATUS"
assert_eq "screen_lock 0 -> value=0"             "0"    "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/screensaver_900.txt"
check_screen_lock_timeout
assert_eq "screen_lock 900 -> warn (too long)"   "warn" "$CHECK_STATUS"
assert_eq "screen_lock 900 -> value=900"         "900"  "$CHECK_VALUE"

# ── auto_login ────────────────────────────────────────────────────────────────

# DisableAutoLogin = 1 -> disabled -> pass
FIXTURE_FILE=""
FIXTURE_EXIT=0
RWT_OUTPUT="1"
run_with_timeout() { RWT_OUTPUT="1"; RWT_EXIT=0; return 0; }
check_auto_login
assert_eq "auto_login disabled (1) -> pass"    "pass"     "$CHECK_STATUS"
assert_eq "auto_login disabled (1) -> value"   "disabled" "$CHECK_VALUE"

# DisableAutoLogin = 0 -> enabled -> fail
run_with_timeout() { RWT_OUTPUT="0"; RWT_EXIT=0; return 0; }
check_auto_login
assert_eq "auto_login enabled (0) -> fail"    "fail"     "$CHECK_STATUS"
assert_eq "auto_login enabled (0) -> value"   "enabled"  "$CHECK_VALUE"

# Key missing -> fail
run_with_timeout() { RWT_OUTPUT=""; RWT_EXIT=1; return 0; }
check_auto_login
assert_eq "auto_login key missing -> fail"         "fail"          "$CHECK_STATUS"
assert_eq "auto_login key missing -> not_disabled"  "not_disabled"  "$CHECK_VALUE"

# Restore fixture-based override
run_with_timeout() {
    local _timeout="$1"; shift
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else
        RWT_OUTPUT=""
    fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0
}

# ── guest_account ─────────────────────────────────────────────────────────────

run_with_timeout() { RWT_OUTPUT="0"; RWT_EXIT=0; return 0; }
check_guest_account
assert_eq "guest disabled (0) -> pass"    "pass"     "$CHECK_STATUS"
assert_eq "guest disabled (0) -> value"   "disabled" "$CHECK_VALUE"

run_with_timeout() { RWT_OUTPUT="1"; RWT_EXIT=0; return 0; }
check_guest_account
assert_eq "guest enabled (1) -> fail"    "fail"    "$CHECK_STATUS"
assert_eq "guest enabled (1) -> value"   "enabled" "$CHECK_VALUE"

# Key missing -> default disabled -> pass
run_with_timeout() { RWT_OUTPUT=""; RWT_EXIT=1; return 0; }
check_guest_account
assert_eq "guest key missing -> pass (default disabled)" "pass" "$CHECK_STATUS"

run_with_timeout() {
    local _timeout="$1"; shift
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else RWT_OUTPUT=""; fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0
}

# ── auto_updates ──────────────────────────────────────────────────────────────

# AutomaticCheckEnabled = 1 -> pass
run_with_timeout() { RWT_OUTPUT="1"; RWT_EXIT=0; return 0; }
check_auto_updates
assert_eq "auto_updates enabled plist -> pass"  "pass"    "$CHECK_STATUS"
assert_eq "auto_updates enabled plist -> value" "enabled" "$CHECK_VALUE"

run_with_timeout() { RWT_OUTPUT="0"; RWT_EXIT=0; return 0; }
check_auto_updates
assert_eq "auto_updates disabled plist -> fail"  "fail"    "$CHECK_STATUS"
assert_eq "auto_updates disabled plist -> value" "disabled" "$CHECK_VALUE"

# Fallback to softwareupdate --schedule
_call_count=0
run_with_timeout() {
    _call_count=$(( _call_count + 1 ))
    if [[ $_call_count -eq 1 ]]; then
        RWT_OUTPUT=""; RWT_EXIT=1; return 0  # plist read fails
    else
        RWT_OUTPUT=$(cat "${FIXTURES}/softwareupdate_on.txt")
        RWT_EXIT=0; return 0
    fi
}
_call_count=0
check_auto_updates
assert_eq "auto_updates fallback softwareupdate on -> pass"  "pass"    "$CHECK_STATUS"

run_with_timeout() {
    local _timeout="$1"; shift
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else RWT_OUTPUT=""; fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0
}

# ── is_admin ──────────────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/dseditgroup_admin.txt" 0
check_is_admin
assert_eq "is_admin member -> warn"  "warn" "$CHECK_STATUS"
assert_eq "is_admin member -> true"  "true" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/dseditgroup_nonadmin.txt" 1
check_is_admin
assert_eq "is_admin non-member -> pass"  "pass"  "$CHECK_STATUS"
assert_eq "is_admin non-member -> false" "false" "$CHECK_VALUE"

# is_admin with CFG_IS_ADMIN_IS_FAIL=true
CFG_IS_ADMIN_IS_FAIL=true
run_with_fixture "${FIXTURES}/dseditgroup_admin.txt" 0
check_is_admin
assert_eq "is_admin member + is_fail=true -> fail"  "fail" "$CHECK_STATUS"
CFG_IS_ADMIN_IS_FAIL=false

# ── time_sync ─────────────────────────────────────────────────────────────────

run_with_fixture "${FIXTURES}/systemsetup_ntp_on.txt"
check_time_sync
assert_eq "time_sync on -> pass"    "pass"    "$CHECK_STATUS"
assert_eq "time_sync on -> enabled" "enabled" "$CHECK_VALUE"

run_with_fixture "${FIXTURES}/systemsetup_ntp_off.txt"
check_time_sync
assert_eq "time_sync off -> fail"     "fail"     "$CHECK_STATUS"
assert_eq "time_sync off -> disabled" "disabled" "$CHECK_VALUE"

# ── airdrop ───────────────────────────────────────────────────────────────────

run_with_timeout() { RWT_OUTPUT="Off"; RWT_EXIT=0; return 0; }
check_airdrop
assert_eq "airdrop Off -> pass" "pass" "$CHECK_STATUS"
assert_eq "airdrop Off -> off"  "off"  "$CHECK_VALUE"

run_with_timeout() { RWT_OUTPUT="Contacts Only"; RWT_EXIT=0; return 0; }
check_airdrop
assert_eq "airdrop ContactsOnly -> warn"          "warn"         "$CHECK_STATUS"
assert_eq "airdrop ContactsOnly -> contacts_only" "contacts_only" "$CHECK_VALUE"

run_with_timeout() { RWT_OUTPUT="Everyone"; RWT_EXIT=0; return 0; }
check_airdrop
assert_eq "airdrop Everyone -> fail"     "fail"     "$CHECK_STATUS"
assert_eq "airdrop Everyone -> everyone" "everyone" "$CHECK_VALUE"

# Key missing -> off -> pass
run_with_timeout() { RWT_OUTPUT=""; RWT_EXIT=1; return 0; }
check_airdrop
assert_eq "airdrop key missing -> pass (default off)" "pass" "$CHECK_STATUS"

run_with_timeout() {
    local _timeout="$1"; shift
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else RWT_OUTPUT=""; fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0
}

# ── profiles (root) ───────────────────────────────────────────────────────────

# Without root
RUN_AS_ROOT=false
run_with_timeout() { RWT_OUTPUT=""; RWT_EXIT=0; return 0; }
check_profiles
assert_eq "profiles no-root -> unknown"    "unknown"              "$CHECK_STATUS"
assert_eq "profiles no-root -> error"      "requires root; skipped" "$CHECK_ERROR"

# With root, no profiles
RUN_AS_ROOT=true
run_with_timeout() {
    RWT_OUTPUT="There are no configuration profiles installed"
    RWT_EXIT=0; return 0
}
check_profiles
assert_eq "profiles root+empty -> pass"    "pass" "$CHECK_STATUS"

# With root, some profiles
run_with_timeout() {
    RWT_OUTPUT='There are 3 configuration profiles installed.
attribute: name: com.example.security
ProfileDisplayName: Security Policy
ProfileIdentifier: com.example.security
attribute: name: com.example.network
ProfileDisplayName: Network Policy
ProfileIdentifier: com.example.network
attribute: name: com.example.wifi
ProfileDisplayName: Wi-Fi
ProfileIdentifier: com.example.wifi'
    RWT_EXIT=0; return 0
}
check_profiles
assert_eq "profiles root+3 -> pass (informational)"  "pass" "$CHECK_STATUS"

RUN_AS_ROOT=false

run_with_timeout() {
    local _timeout="$1"; shift
    if [[ -n "$FIXTURE_FILE" ]] && [[ -f "$FIXTURE_FILE" ]]; then
        RWT_OUTPUT=$(cat "$FIXTURE_FILE")
    else RWT_OUTPUT=""; fi
    RWT_EXIT=$FIXTURE_EXIT
    return 0
}

# ── secure_boot ───────────────────────────────────────────────────────────────

PLATFORM_ARCH="arm64"
run_with_timeout() {
    RWT_OUTPUT="Secure Boot setting: Full Security"
    RWT_EXIT=0; return 0
}
check_secure_boot
assert_eq "secure_boot arm64 full -> pass"         "pass"         "$CHECK_STATUS"
assert_eq "secure_boot arm64 full -> full_security" "full_security" "$CHECK_VALUE"

run_with_timeout() {
    RWT_OUTPUT="Secure Boot setting: Reduced Security"
    RWT_EXIT=0; return 0
}
check_secure_boot
assert_eq "secure_boot arm64 reduced -> warn"           "warn"            "$CHECK_STATUS"
assert_eq "secure_boot arm64 reduced -> reduced_security" "reduced_security" "$CHECK_VALUE"

run_with_timeout() {
    RWT_OUTPUT="Secure Boot setting: Permissive Security"
    RWT_EXIT=0; return 0
}
check_secure_boot
assert_eq "secure_boot arm64 permissive -> fail"             "fail"               "$CHECK_STATUS"
assert_eq "secure_boot arm64 permissive -> permissive_security" "permissive_security" "$CHECK_VALUE"

# Intel fallback
PLATFORM_ARCH="x86_64"
run_with_timeout() {
    RWT_OUTPUT="94b73556-2197-4702-82a8-3e1337dafbfb:AppleSecureBootPolicy	%03"
    RWT_EXIT=0; return 0
}
check_secure_boot
assert_eq "secure_boot intel 03 -> pass" "pass" "$CHECK_STATUS"

PLATFORM_ARCH="arm64"

# ── run_checks integration smoke test ────────────────────────────────────────

# Restore real run_with_timeout for integration test
unset -f run_with_timeout
source "${REPO_ROOT}/lib/utils.sh"

# This runs a subset of checks against the real system.
# We just want to verify run_checks doesn't crash and produces valid JSON.
CFG_ENABLED_CHECKS="filevault,gatekeeper,sip,guest_account,auto_login"
CFG_DISABLED_CHECKS=""
TIMEOUT_PER_CHECK=10

run_checks

posture_json=$(build_posture_json)

if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
    if /usr/bin/python3 -c "import json,sys; json.loads(sys.argv[1])" "$posture_json" 2>/dev/null; then
        _PASS=$(( _PASS + 1 ))
        printf '  PASS: run_checks produces valid JSON posture object\n'
    else
        _FAIL=$(( _FAIL + 1 ))
        printf '  FAIL: run_checks posture JSON is invalid\n'
        printf '    json: %s\n' "${posture_json:0:200}"
    fi
else
    printf '  SKIP: run_checks JSON validation (python3 unavailable)\n'
fi

# ── Final tally ───────────────────────────────────────────────────────────────

echo ""
printf '  checks tests: %d pass, %d fail\n' "$_PASS" "$_FAIL"

if [[ $_FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
