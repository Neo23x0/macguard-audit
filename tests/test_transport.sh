#!/usr/bin/env bash
# tests/test_transport.sh — Transport integration tests against mock_server.py
#
# Starts tools/mock_server.py on localhost:18765 (HTTP mode),
# exercises ship_splunk_hec and ship_https_post, asserts HTTP responses
# and event body structure via /_events endpoint.
#
# Skipped automatically when Python3 is unavailable.
# Set RUN_TRANSPORT_TESTS=false to skip explicitly.
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

TESTS_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(dirname "$TESTS_DIR")"

_PASS=0
_FAIL=0

assert_eq() {
    local label="$1" expected="$2" actual="$3"
    if [[ "$expected" == "$actual" ]]; then
        _PASS=$(( _PASS + 1 ))
        printf '  PASS: %s\n' "$label"
    else
        _FAIL=$(( _FAIL + 1 ))
        printf '  FAIL: %s\n    expected: %s\n    actual:   %s\n' \
            "$label" "$expected" "$actual"
    fi
}

assert_contains() {
    local label="$1" needle="$2" haystack="$3"
    if [[ "$haystack" == *"$needle"* ]]; then
        _PASS=$(( _PASS + 1 ))
        printf '  PASS: %s\n' "$label"
    else
        _FAIL=$(( _FAIL + 1 ))
        printf '  FAIL: %s\n    expected to contain: %s\n    actual: %s\n' \
            "$label" "$needle" "${haystack:0:200}"
    fi
}

# ── Skip guard ────────────────────────────────────────────────────────────────
if ! /usr/bin/python3 --version >/dev/null 2>&1; then
    printf '  SKIP: transport tests (python3 unavailable)\n'
    exit 0
fi
if [[ "${RUN_TRANSPORT_TESTS:-true}" == "false" ]]; then
    printf '  SKIP: transport tests (RUN_TRANSPORT_TESTS=false)\n'
    exit 0
fi

# ── Bootstrap libs ────────────────────────────────────────────────────────────
PYTHON3_AVAILABLE=true
VERBOSE=false
_LOG_LEVEL=3   # warn
RUN_AS_ROOT=false

source "${REPO_ROOT}/lib/utils.sh"
source "${REPO_ROOT}/lib/json.sh"
source "${REPO_ROOT}/lib/transport.sh"
source "${REPO_ROOT}/lib/keychain.sh"

# ── Start mock server ─────────────────────────────────────────────────────────
MOCK_PORT=18765
MOCK_TOKEN="test-token-12345"
MOCK_LOG=$(mktemp /tmp/macguard_mock.XXXXXX)
MOCK_PID=""

cleanup() {
    if [[ -n "$MOCK_PID" ]]; then
        kill "$MOCK_PID" 2>/dev/null || true
        wait "$MOCK_PID" 2>/dev/null || true
    fi
    rm -f "$MOCK_LOG"
}
trap cleanup EXIT INT TERM

/usr/bin/python3 "${REPO_ROOT}/tools/mock_server.py" \
    --port "$MOCK_PORT" \
    --mode http \
    --token "$MOCK_TOKEN" \
    > "$MOCK_LOG" 2>&1 &
MOCK_PID=$!

# Wait for server to become ready (up to 5 seconds)
_ready=false
for _ in 1 2 3 4 5; do
    if grep -q "READY" "$MOCK_LOG" 2>/dev/null; then
        _ready=true; break
    fi
    sleep 1
done

if [[ "$_ready" != "true" ]]; then
    printf '  FAIL: mock server did not become ready in 5s\n'
    cat "$MOCK_LOG" >&2 || true
    exit 1
fi

BASE_URL="http://127.0.0.1:${MOCK_PORT}"

# ── Helper: reset event log ───────────────────────────────────────────────────
reset_events() {
    curl -s "${BASE_URL}/_reset" >/dev/null 2>&1 || true
}

get_events() {
    curl -s "${BASE_URL}/_events" 2>/dev/null || echo "[]"
}

# ── Minimal sample report ─────────────────────────────────────────────────────
SAMPLE_REPORT='{"schema_version":"1.0","tool":"macguard-audit","collected_at":"2026-02-23T10:00:00Z","posture":{"filevault":{"status":"pass","value":"enabled"}}}'

# ── Test 1: health endpoint ───────────────────────────────────────────────────
health_resp=$(curl -s "${BASE_URL}/_health" 2>/dev/null || echo "{}")
health_status=$(printf '%s' "$health_resp" | /usr/bin/python3 -c \
    "import json,sys; print(json.loads(sys.stdin.read()).get('status',''))" 2>/dev/null || echo "")
assert_eq "mock server health" "ok" "$health_status"

# ── Test 2: Splunk HEC valid token → 200 ─────────────────────────────────────
reset_events

SPLUNK_HEC_URL="${BASE_URL}/services/collector/event"
SPLUNK_HEC_TOKEN="$MOCK_TOKEN"
SPLUNK_HEC_INDEX=""
SPLUNK_HEC_SOURCETYPE="macguard:posture"
SPLUNK_HEC_TLS_VERIFY="false"  # HTTP mode but flag is harmless
SPLUNK_HEC_CONNECT_TIMEOUT="5"
SPLUNK_HEC_MAX_RETRIES="1"
SPLUNK_HEC_RETRY_DELAY="1"

if ship_splunk_hec "$SAMPLE_REPORT" 2>/dev/null; then
    assert_eq "ship_splunk_hec valid token -> success" "0" "0"
else
    assert_eq "ship_splunk_hec valid token -> success" "0" "1"
fi

# ── Test 3: event body recorded by mock ──────────────────────────────────────
events=$(get_events)
event_count=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo "0")
assert_eq "splunk_hec: 1 event recorded" "1" "$event_count"

# ── Test 4: event has sourcetype field ───────────────────────────────────────
sourcetype=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; events=json.loads(sys.stdin.read()); print(events[0].get('sourcetype','') if events else '')" \
    2>/dev/null || echo "")
assert_eq "splunk_hec: event.sourcetype" "macguard:posture" "$sourcetype"

# ── Test 5: event.event contains the original report ─────────────────────────
event_tool=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; events=json.loads(sys.stdin.read()); print(events[0].get('event',{}).get('tool','') if events else '')" \
    2>/dev/null || echo "")
assert_eq "splunk_hec: event.event.tool" "macguard-audit" "$event_tool"

# ── Test 6: Splunk HEC invalid token → ship returns non-zero ─────────────────
reset_events

SPLUNK_HEC_TOKEN="wrong-token"
if ship_splunk_hec "$SAMPLE_REPORT" 2>/dev/null; then
    assert_eq "ship_splunk_hec bad token -> fail" "fail" "no_fail"
else
    assert_eq "ship_splunk_hec bad token -> fail" "fail" "fail"
fi

# ── Test 7: Splunk HEC bad token → no event stored ───────────────────────────
events=$(get_events)
event_count=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo "0")
assert_eq "splunk_hec bad token: 0 events recorded" "0" "$event_count"

# ── Test 8: HTTPS POST valid token → 200 ─────────────────────────────────────
reset_events

HTTPS_POST_URL="${BASE_URL}/api/v1/events"
HTTPS_POST_TOKEN="$MOCK_TOKEN"
HTTPS_POST_AUTH_HEADER="Authorization"
HTTPS_POST_TLS_VERIFY="false"
HTTPS_POST_CONNECT_TIMEOUT="5"
HTTPS_POST_MAX_RETRIES="1"

if ship_https_post "$SAMPLE_REPORT" 2>/dev/null; then
    assert_eq "ship_https_post valid token -> success" "0" "0"
else
    assert_eq "ship_https_post valid token -> success" "0" "1"
fi

# ── Test 9: HTTPS POST event recorded ────────────────────────────────────────
events=$(get_events)
event_count=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo "0")
assert_eq "https_post: 1 event recorded" "1" "$event_count"

# ── Test 10: HTTPS POST invalid token → fail ─────────────────────────────────
reset_events

HTTPS_POST_TOKEN="bad-token"
if ship_https_post "$SAMPLE_REPORT" 2>/dev/null; then
    assert_eq "ship_https_post bad token -> fail" "fail" "no_fail"
else
    assert_eq "ship_https_post bad token -> fail" "fail" "fail"
fi

# ── Test 11: ship() dispatch → splunk_hec ────────────────────────────────────
reset_events

TRANSPORT_ENABLED="true"
TRANSPORT_TYPE="splunk_hec"
SPLUNK_HEC_TOKEN="$MOCK_TOKEN"

if ship "$SAMPLE_REPORT" 2>/dev/null; then
    assert_eq "ship() dispatch splunk_hec" "0" "0"
else
    assert_eq "ship() dispatch splunk_hec" "0" "1"
fi

# ── Test 12: ship() disabled → no events ─────────────────────────────────────
reset_events

TRANSPORT_ENABLED="false"
ship "$SAMPLE_REPORT" 2>/dev/null || true

events=$(get_events)
event_count=$(printf '%s' "$events" | /usr/bin/python3 -c \
    "import json,sys; print(len(json.loads(sys.stdin.read())))" 2>/dev/null || echo "0")
assert_eq "ship() disabled: 0 events" "0" "$event_count"

# ── Test 13: JSON payload validity ───────────────────────────────────────────
reset_events

TRANSPORT_ENABLED="true"
TRANSPORT_TYPE="splunk_hec"
SPLUNK_HEC_TOKEN="$MOCK_TOKEN"

# Build a report with special characters that must be properly escaped
SPECIAL_REPORT='{"tool":"macguard-audit","host":{"hostname":"test\"host"},"posture":{}}'
if ship_splunk_hec "$SPECIAL_REPORT" 2>/dev/null; then
    events=$(get_events)
    valid=$(/usr/bin/python3 -c \
        "import json,sys; events=json.loads(sys.stdin.read()); print('ok' if events else 'empty')" \
        <<< "$events" 2>/dev/null || echo "error")
    assert_eq "splunk_hec: special-char report stored as valid JSON" "ok" "$valid"
else
    assert_eq "splunk_hec: special-char report ship" "ok" "fail"
fi

# ── Final tally ───────────────────────────────────────────────────────────────
echo ""
printf '  transport tests: %d pass, %d fail\n' "$_PASS" "$_FAIL"

if [[ $_FAIL -gt 0 ]]; then
    exit 1
fi
