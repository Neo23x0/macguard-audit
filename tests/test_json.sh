#!/usr/bin/env bash
# tests/test_json.sh — Unit tests for lib/json.sh
# Uses assert_eq helper; no live commands needed.
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TESTS_DIR")"

# ── Bootstrap ─────────────────────────────────────────────────────────────────
PYTHON3_AVAILABLE=false
if /usr/bin/python3 --version >/dev/null 2>&1; then
    PYTHON3_AVAILABLE=true
fi

VERBOSE=false
_LOG_LEVEL=3  # suppress logs during tests

source "${REPO_ROOT}/lib/utils.sh"
source "${REPO_ROOT}/lib/json.sh"

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

assert_valid_json() {
    local desc="$1" value="$2"
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        if /usr/bin/python3 -c "import json,sys; json.loads(sys.argv[1])" "$value" 2>/dev/null; then
            _PASS=$(( _PASS + 1 ))
            printf '  PASS: %s (valid JSON)\n' "$desc"
        else
            _FAIL=$(( _FAIL + 1 ))
            printf '  FAIL: %s (invalid JSON)\n' "$desc"
            printf '    value: %s\n' "$value"
        fi
    else
        printf '  SKIP: %s (python3 unavailable for JSON validation)\n' "$desc"
    fi
}

# ── Tests: json_escape_string ─────────────────────────────────────────────────

# Simple string
result=$(json_escape_string "hello")
assert_eq "escape simple string" '"hello"' "$result"

# Double quote
result=$(json_escape_string 'say "hello"')
assert_eq "escape double-quote" '"say \"hello\""' "$result"

# Backslash
result=$(json_escape_string 'path\to\file')
assert_eq "escape backslash" '"path\\to\\file"' "$result"

# Newline
result=$(json_escape_string $'line1\nline2')
assert_eq "escape newline" '"line1\nline2"' "$result"

# Tab
result=$(json_escape_string $'col1\tcol2')
assert_eq "escape tab" '"col1\tcol2"' "$result"

# Empty string
result=$(json_escape_string "")
assert_eq "escape empty string" '""' "$result"

# Carriage return
result=$(json_escape_string $'foo\rbar')
assert_eq "escape CR" '"foo\rbar"' "$result"

# Unicode passthrough (json_escape_string should not corrupt UTF-8)
if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
    result=$(json_escape_string "caf\xc3\xa9")
    assert_valid_json "escape UTF-8 char" "$result"
fi

# ── Tests: json_null_or_string ────────────────────────────────────────────────

result=$(json_null_or_string "")
assert_eq "null_or_string empty -> null" "null" "$result"

result=$(json_null_or_string "hello")
assert_eq "null_or_string non-empty -> quoted" '"hello"' "$result"

result=$(json_null_or_string 'with "quotes"')
assert_eq "null_or_string with quotes" '"with \"quotes\""' "$result"

# ── Tests: json_bool ──────────────────────────────────────────────────────────

assert_eq "json_bool true"  "true"  "$(json_bool "true")"
assert_eq "json_bool false" "false" "$(json_bool "false")"
assert_eq "json_bool 1"     "true"  "$(json_bool "1")"
assert_eq "json_bool 0"     "false" "$(json_bool "0")"
assert_eq "json_bool yes"   "true"  "$(json_bool "yes")"
assert_eq "json_bool empty" "false" "$(json_bool "")"

# ── Tests: assemble_check_object ─────────────────────────────────────────────

# Basic pass check
CHECK_STATUS="pass"
CHECK_VALUE="enabled"
CHECK_VALUE_JSON=""
CHECK_RAW="FileVault is On."
CHECK_ERROR=""
CHECK_PRIVILEGE="user"
CHECK_DURATION_MS=214
result=$(assemble_check_object "filevault")
assert_valid_json "assemble filevault pass" "$result"
[[ "$result" == *'"status":"pass"'* ]] \
    && assert_eq "filevault status in output" "yes" "yes" \
    || assert_eq "filevault status in output" '"status":"pass" present' "missing"

# Unknown check with error
CHECK_STATUS="unknown"
CHECK_VALUE="null"
CHECK_VALUE_JSON=""
CHECK_RAW=""
CHECK_ERROR="requires root; skipped"
CHECK_PRIVILEGE="root"
CHECK_DURATION_MS=0
result=$(assemble_check_object "firewall_global_state")
assert_valid_json "assemble root check unknown" "$result"

# Integer value (screen_lock_timeout)
CHECK_STATUS="pass"
CHECK_VALUE="300"
CHECK_VALUE_JSON=""
CHECK_RAW="300"
CHECK_ERROR=""
CHECK_PRIVILEGE="user"
CHECK_DURATION_MS=45
result=$(assemble_check_object "screen_lock_timeout")
assert_valid_json "assemble screen_lock_timeout integer" "$result"
[[ "$result" == *'"value":300'* ]] \
    && assert_eq "screen_lock_timeout value is unquoted int" "yes" "yes" \
    || assert_eq "screen_lock_timeout value is unquoted int" '"value":300 present' "missing"

# Boolean value (is_admin)
CHECK_STATUS="warn"
CHECK_VALUE="true"
CHECK_VALUE_JSON=""
CHECK_RAW="yes neo is a member of admin"
CHECK_ERROR=""
CHECK_PRIVILEGE="user"
CHECK_DURATION_MS=441
result=$(assemble_check_object "is_admin")
assert_valid_json "assemble is_admin boolean" "$result"
[[ "$result" == *'"value":true'* ]] \
    && assert_eq "is_admin value is boolean true" "yes" "yes" \
    || assert_eq "is_admin value is boolean true" '"value":true present' "missing"

# Object value (gatekeeper)
CHECK_STATUS="pass"
CHECK_VALUE="enabled"
CHECK_VALUE_JSON='{"state":"enabled","assessments_enabled":true}'
CHECK_RAW="assessments enabled"
CHECK_ERROR=""
CHECK_PRIVILEGE="user"
CHECK_DURATION_MS=88
result=$(assemble_check_object "gatekeeper")
assert_valid_json "assemble gatekeeper object value" "$result"

# Special chars in raw field
CHECK_STATUS="unknown"
CHECK_VALUE="null"
CHECK_VALUE_JSON=""
CHECK_RAW='output with "quotes" and \backslash'
CHECK_ERROR="error with \"special\" chars"
CHECK_PRIVILEGE="user"
CHECK_DURATION_MS=10
result=$(assemble_check_object "sip")
assert_valid_json "assemble check with special chars in raw/error" "$result"

# ── Tests: compute_summary ────────────────────────────────────────────────────

compute_summary 10 2 3 5
assert_eq "summary total"   "20" "$_SUMMARY_TOTAL"
assert_eq "summary pass"    "10" "$_SUMMARY_PASS"
assert_eq "summary fail"    "2"  "$_SUMMARY_FAIL"
assert_eq "summary warn"    "3"  "$_SUMMARY_WARN"
assert_eq "summary unknown" "5"  "$_SUMMARY_UNKNOWN"
# score = (10*100 + 3*50) / (20-5) = (1000+150)/15 = 1150/15 = 76
assert_eq "summary score"   "76" "$_SUMMARY_SCORE"

# Edge: all unknown
compute_summary 0 0 0 5
assert_eq "summary score all unknown" "0" "$_SUMMARY_SCORE"

# Edge: all pass
compute_summary 10 0 0 0
assert_eq "summary score all pass" "100" "$_SUMMARY_SCORE"

# ── Final tally ───────────────────────────────────────────────────────────────

echo ""
printf '  json tests: %d pass, %d fail\n' "$_PASS" "$_FAIL"

if [[ $_FAIL -gt 0 ]]; then
    exit 1
fi
exit 0
