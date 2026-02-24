#!/usr/bin/env bash
# tests/run_tests.sh — macguard-audit test harness
# Runs all test suites and reports results.
# Exit code: 0 = all pass, 1 = any failure
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TESTS_DIR")"

TOTAL_PASS=0
TOTAL_FAIL=0
SUITES_RUN=0
SUITES_FAILED=0

_green() { printf '\033[0;32m%s\033[0m' "$*"; }
_red()   { printf '\033[0;31m%s\033[0m' "$*"; }
_bold()  { printf '\033[1m%s\033[0m' "$*"; }

run_suite() {
    local suite_file="$1"
    local suite_name
    suite_name=$(basename "$suite_file" .sh)
    SUITES_RUN=$(( SUITES_RUN + 1 ))

    echo ""
    _bold "=== Suite: ${suite_name} ==="; echo ""

    # Run suite in subshell to capture pass/fail counts
    local suite_out
    if suite_out=$(bash "$suite_file" 2>&1); then
        echo "$suite_out"
        local p f
        p=$(echo "$suite_out" | grep -c "^  PASS:" || true)
        f=$(echo "$suite_out" | grep -c "^  FAIL:" || true)
        TOTAL_PASS=$(( TOTAL_PASS + p ))
        TOTAL_FAIL=$(( TOTAL_FAIL + f ))
        if [[ $f -gt 0 ]]; then
            SUITES_FAILED=$(( SUITES_FAILED + 1 ))
            _red "SUITE FAIL: ${suite_name} (${f} failures)"; echo ""
        else
            _green "SUITE PASS: ${suite_name} (${p} tests)"; echo ""
        fi
    else
        local exit_code=$?
        echo "$suite_out"
        SUITES_FAILED=$(( SUITES_FAILED + 1 ))
        _red "SUITE CRASH: ${suite_name} (exit ${exit_code})"; echo ""
    fi
}

# Run each suite
for suite in \
    "${TESTS_DIR}/test_json.sh" \
    "${TESTS_DIR}/test_checks.sh"
do
    if [[ -f "$suite" ]]; then
        run_suite "$suite"
    else
        echo "WARNING: suite not found: $suite"
    fi
done

# Transport tests require mock server; skip if not explicitly enabled
if [[ "${RUN_TRANSPORT_TESTS:-false}" == "true" ]]; then
    if [[ -f "${TESTS_DIR}/test_transport.sh" ]]; then
        run_suite "${TESTS_DIR}/test_transport.sh"
    fi
fi

# Summary
echo ""
_bold "══════════════════════════════════════"
printf ' Total: %d tests across %d suites\n' "$((TOTAL_PASS + TOTAL_FAIL))" "$SUITES_RUN"
_green "  PASS: ${TOTAL_PASS}"; echo ""
if [[ $TOTAL_FAIL -gt 0 ]]; then
    _red   "  FAIL: ${TOTAL_FAIL}"; echo ""
fi
_bold "══════════════════════════════════════"; echo ""

if [[ $TOTAL_FAIL -gt 0 ]] || [[ $SUITES_FAILED -gt 0 ]]; then
    exit 1
fi
exit 0
