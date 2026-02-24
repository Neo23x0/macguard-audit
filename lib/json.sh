#!/usr/bin/env bash
# lib/json.sh — JSON assembly helpers and full report construction
# Part of macguard-audit
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Strategy:
#   - json_escape_string: Python3 json.dumps when available; manual sed fallback
#   - assemble_check_object: builds per-check JSON from CHECK_* globals
#   - assemble_full_report: wraps all check objects + host/OS/user metadata
#     Python3 path: passes pre-assembled posture JSON to Python for final wrap + validation
#     Manual path: builds wrapper with printf, no validation (acceptable for known-good output)

# ── Low-level string escaping ─────────────────────────────────────────────────

# json_escape_string VALUE
# Outputs a JSON double-quoted string with all special chars escaped.
# Returns the string WITH surrounding double-quotes (e.g. "foo \"bar\"").
json_escape_string() {
    local input="$1"
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        /usr/bin/python3 -c \
            "import json,sys; print(json.dumps(sys.argv[1]))" \
            "$input" 2>/dev/null \
            || _json_escape_manual "$input"
    else
        _json_escape_manual "$input"
    fi
}

_json_escape_manual() {
    local s="$1"
    # Order matters: backslash first, then the rest
    s="${s//\\/\\\\}"        # \ -> \\
    s="${s//\"/\\\"}"        # " -> \"
    s="${s//$'\t'/\\t}"      # TAB -> \t
    s="${s//$'\r'/\\r}"      # CR -> \r
    s="${s//$'\n'/\\n}"      # LF -> \n
    # Control chars 0x01-0x1f (other than the above) are rare in our outputs;
    # strip them rather than risk invalid JSON
    # shellcheck disable=SC2001
    s=$(echo "$s" | LC_ALL=C sed 's/[\x01-\x08\x0b\x0c\x0e-\x1f]//g' 2>/dev/null || echo "$s")
    printf '"%s"' "$s"
}

# json_null_or_string VALUE
# Returns "null" if VALUE is empty, else a JSON-escaped quoted string.
json_null_or_string() {
    if [[ -z "$1" ]]; then
        echo "null"
    else
        json_escape_string "$1"
    fi
}

# json_bool VALUE
# Converts any truthy value ("true","1","yes") to JSON true/false literal.
json_bool() {
    case "${1,,}" in
        true|1|yes) echo "true" ;;
        *)          echo "false" ;;
    esac
}

# ── Check object assembly ─────────────────────────────────────────────────────
# Reads the CHECK_* globals set by each check_NAME() function.
# Globals expected:
#   CHECK_STATUS        pass|fail|warn|unknown
#   CHECK_VALUE         raw typed value (special handling per check name)
#   CHECK_RAW           raw command output (will be truncated to 512 chars)
#   CHECK_ERROR         error string or ""
#   CHECK_PRIVILEGE     user|root
#   CHECK_DURATION_MS   integer milliseconds
#
# Special CHECK_VALUE handling by check name:
#   screen_lock_timeout  -> integer (no quotes)
#   is_admin             -> boolean literal
#   pending_updates      -> integer (no quotes)
#   browser_versions     -> already-built JSON object string in CHECK_VALUE_JSON
#   firmware_version     -> already-built JSON object string in CHECK_VALUE_JSON
#   gatekeeper           -> already-built JSON object string in CHECK_VALUE_JSON

assemble_check_object() {
    local name="$1"
    local value_field raw_field error_field

    # Determine JSON representation of value
    case "$name" in
        screen_lock_timeout|pending_updates)
            if [[ "${CHECK_VALUE}" =~ ^[0-9]+$ ]]; then
                value_field="${CHECK_VALUE}"
            else
                value_field="null"
            fi
            ;;
        is_admin)
            if [[ "${CHECK_VALUE}" == "true" ]]; then
                value_field="true"
            elif [[ "${CHECK_VALUE}" == "false" ]]; then
                value_field="false"
            else
                value_field="null"
            fi
            ;;
        browser_versions|firmware_version|gatekeeper)
            # CHECK_VALUE_JSON holds a pre-built JSON object or "null"
            value_field="${CHECK_VALUE_JSON:-null}"
            ;;
        *)
            value_field=$(json_null_or_string "${CHECK_VALUE:-}")
            ;;
    esac

    # Truncate raw to 512 chars before escaping
    local raw_trunc
    raw_trunc=$(truncate_str "${CHECK_RAW:-}" 512)
    raw_field=$(json_null_or_string "$raw_trunc")
    error_field=$(json_null_or_string "${CHECK_ERROR:-}")

    printf '{"status":%s,"value":%s,"raw":%s,"privilege":%s,"check_duration_ms":%d,"error":%s}' \
        "$(json_escape_string "${CHECK_STATUS:-unknown}")" \
        "$value_field" \
        "$raw_field" \
        "$(json_escape_string "${CHECK_PRIVILEGE:-user}")" \
        "${CHECK_DURATION_MS:-0}" \
        "$error_field"
}

# ── Full report assembly ──────────────────────────────────────────────────────
# assemble_full_report POSTURE_JSON WARNINGS_JSON COLLECTION_DURATION_MS
# Uses PLATFORM_* and config globals.
# Writes the complete JSON document to stdout.

assemble_full_report() {
    local posture_json="$1"
    local warnings_json="${2:-[]}"
    local collection_duration_ms="${3:-0}"

    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        _assemble_full_report_python \
            "$posture_json" "$warnings_json" "$collection_duration_ms"
    else
        _assemble_full_report_manual \
            "$posture_json" "$warnings_json" "$collection_duration_ms"
    fi
}

_assemble_full_report_python() {
    local posture_json="$1"
    local warnings_json="$2"
    local collection_duration_ms="$3"

    # Pass large data via tempfiles to avoid ARG_MAX issues
    local tmp_posture tmp_warn
    tmp_posture=$(mktemp /tmp/posturectl_posture.XXXXXX)
    tmp_warn=$(mktemp /tmp/posturectl_warn.XXXXXX)
    printf '%s' "$posture_json" > "$tmp_posture"
    printf '%s' "$warnings_json" > "$tmp_warn"

    local pretty_flag="${PRETTY_PRINT:-false}"

    /usr/bin/python3 - \
        "$tmp_posture" "$tmp_warn" \
        "$collection_duration_ms" \
        "$pretty_flag" \
        "${TOOL_VERSION:-1.0.0}" \
        "${PLATFORM_HOSTNAME:-unknown}" \
        "${PLATFORM_HW_UUID:-unknown}" \
        "${_SERIAL_FIELD:-null}" \
        "${PLATFORM_MODEL:-unknown}" \
        "${PLATFORM_ARCH:-unknown}" \
        "${CFG_ORG_ID:-}" \
        "${CFG_ENVIRONMENT:-}" \
        "${CFG_TAGS_JSON:-[]}" \
        "${PLATFORM_MDM_ENROLLED:-false}" \
        "${PLATFORM_MDM_URL:-}" \
        "${PLATFORM_OS_VERSION:-unknown}" \
        "${PLATFORM_OS_BUILD:-unknown}" \
        "${PLATFORM_OS_MAJOR:-0}" \
        "${PLATFORM_OS_MINOR:-0}" \
        "${PLATFORM_KERNEL:-unknown}" \
        "${PLATFORM_UPTIME_SECS:-0}" \
        "${PLATFORM_CURRENT_USER:-unknown}" \
        "${PLATFORM_CONSOLE_USER:-unknown}" \
        "${PLATFORM_UID:-0}" \
        "${RUN_AS_ROOT:-false}" \
        "${_SUMMARY_TOTAL:-0}" \
        "${_SUMMARY_PASS:-0}" \
        "${_SUMMARY_FAIL:-0}" \
        "${_SUMMARY_WARN:-0}" \
        "${_SUMMARY_UNKNOWN:-0}" \
        "${_SUMMARY_SCORE:-0}" \
        <<'PYEOF'
import json, sys

args = sys.argv[1:]
posture_file, warn_file = args[0], args[1]
collection_ms = int(args[2])
pretty = args[3].lower() == "true"
tool_version, hostname, hw_uuid = args[4], args[5], args[6]
serial_field_raw = args[7]  # already "null" or a JSON string
model, arch = args[8], args[9]
org_id, environment, tags_json_str = args[10], args[11], args[12]
mdm_enrolled_str, mdm_url = args[13], args[14]
os_version, os_build = args[15], args[16]
os_major, os_minor = int(args[17]), int(args[18])
kernel, uptime_secs = args[19], int(args[20])
current_user, console_user, uid_str = args[21], args[22], args[23]
run_as_root_str = args[24]
s_total, s_pass, s_fail, s_warn, s_unknown, s_score = (
    int(args[25]), int(args[26]), int(args[27]),
    int(args[28]), int(args[29]), int(args[30])
)

with open(posture_file) as f:
    posture = json.load(f)
with open(warn_file) as f:
    warnings = json.load(f)

import os
os.unlink(posture_file)
os.unlink(warn_file)

import time
collected_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())

try:
    tags = json.loads(tags_json_str)
except Exception:
    tags = []

# serial_hash field: already JSON-encoded ("null" or a quoted string)
# We need to embed it as a raw JSON value
import re
try:
    serial_value = json.loads(serial_field_raw)
except Exception:
    serial_value = None

doc = {
    "schema_version": "1.0",
    "tool": "macguard-audit",
    "tool_version": tool_version,
    "collected_at": collected_at,
    "collection_duration_ms": collection_ms,
    "run_as_root": run_as_root_str.lower() == "true",
    "collection_warnings": warnings,
    "host": {
        "hostname": hostname,
        "hardware_uuid": hw_uuid,
        "serial_hash": serial_value,
        "model": model,
        "arch": arch,
        "org_id": org_id if org_id else None,
        "environment": environment if environment else None,
        "tags": tags,
        "mdm_enrolled": mdm_enrolled_str.lower() == "true",
        "mdm_server_url": mdm_url if mdm_url else None,
    },
    "os": {
        "name": "macOS",
        "version": os_version,
        "build": os_build,
        "major": os_major,
        "minor": os_minor,
        "kernel_version": "Darwin " + kernel,
        "uptime_seconds": uptime_secs,
    },
    "user": {
        "current_user": current_user,
        "console_user": console_user,
        "uid": int(uid_str) if uid_str.isdigit() else 0,
    },
    "posture": posture,
    "summary": {
        "total": s_total,
        "pass": s_pass,
        "fail": s_fail,
        "warn": s_warn,
        "unknown": s_unknown,
        "score_pct": s_score,
    },
}

indent = 2 if pretty else None
print(json.dumps(doc, indent=indent, ensure_ascii=False))
PYEOF
}

_assemble_full_report_manual() {
    local posture_json="$1"
    local warnings_json="$2"
    local collection_duration_ms="$3"

    local collected_at
    collected_at=$(now_rfc3339)
    local run_as_root_val
    run_as_root_val=$(json_bool "${RUN_AS_ROOT:-false}")
    local mdm_enrolled_val
    mdm_enrolled_val=$(json_bool "${PLATFORM_MDM_ENROLLED:-false}")

    # serial_hash: use pre-computed _SERIAL_FIELD or null
    local serial_field="${_SERIAL_FIELD:-null}"

    # For manual path, no pretty-print; single-line output
    printf '{"schema_version":"1.0","tool":"macguard-audit","tool_version":%s,' \
        "$(json_escape_string "${TOOL_VERSION:-1.0.0}")"
    printf '"collected_at":%s,"collection_duration_ms":%d,' \
        "$(json_escape_string "$collected_at")" \
        "$collection_duration_ms"
    printf '"run_as_root":%s,"collection_warnings":%s,' \
        "$run_as_root_val" \
        "$warnings_json"
    printf '"host":{"hostname":%s,"hardware_uuid":%s,"serial_hash":%s,' \
        "$(json_escape_string "${PLATFORM_HOSTNAME:-unknown}")" \
        "$(json_escape_string "${PLATFORM_HW_UUID:-unknown}")" \
        "$serial_field"
    printf '"model":%s,"arch":%s,"org_id":%s,"environment":%s,"tags":%s,' \
        "$(json_escape_string "${PLATFORM_MODEL:-unknown}")" \
        "$(json_escape_string "${PLATFORM_ARCH:-unknown}")" \
        "$(json_null_or_string "${CFG_ORG_ID:-}")" \
        "$(json_null_or_string "${CFG_ENVIRONMENT:-}")" \
        "${CFG_TAGS_JSON:-[]}"
    printf '"mdm_enrolled":%s,"mdm_server_url":%s},' \
        "$mdm_enrolled_val" \
        "$(json_null_or_string "${PLATFORM_MDM_URL:-}")"
    printf '"os":{"name":"macOS","version":%s,"build":%s,' \
        "$(json_escape_string "${PLATFORM_OS_VERSION:-unknown}")" \
        "$(json_escape_string "${PLATFORM_OS_BUILD:-unknown}")"
    printf '"major":%s,"minor":%s,"kernel_version":%s,"uptime_seconds":%d},' \
        "${PLATFORM_OS_MAJOR:-0}" \
        "${PLATFORM_OS_MINOR:-0}" \
        "$(json_escape_string "Darwin ${PLATFORM_KERNEL:-unknown}")" \
        "${PLATFORM_UPTIME_SECS:-0}"
    printf '"user":{"current_user":%s,"console_user":%s,"uid":%s},' \
        "$(json_escape_string "${PLATFORM_CURRENT_USER:-unknown}")" \
        "$(json_escape_string "${PLATFORM_CONSOLE_USER:-unknown}")" \
        "${PLATFORM_UID:-0}"
    printf '"posture":%s,' "$posture_json"
    printf '"summary":{"total":%d,"pass":%d,"fail":%d,"warn":%d,"unknown":%d,"score_pct":%d}}' \
        "${_SUMMARY_TOTAL:-0}" \
        "${_SUMMARY_PASS:-0}" \
        "${_SUMMARY_FAIL:-0}" \
        "${_SUMMARY_WARN:-0}" \
        "${_SUMMARY_UNKNOWN:-0}" \
        "${_SUMMARY_SCORE:-0}"
    printf '\n'
}

# ── Summary computation ───────────────────────────────────────────────────────
# compute_summary PASS FAIL WARN UNKNOWN
# Sets _SUMMARY_* globals
compute_summary() {
    _SUMMARY_PASS="${1:-0}"
    _SUMMARY_FAIL="${2:-0}"
    _SUMMARY_WARN="${3:-0}"
    _SUMMARY_UNKNOWN="${4:-0}"
    _SUMMARY_TOTAL=$(( _SUMMARY_PASS + _SUMMARY_FAIL + _SUMMARY_WARN + _SUMMARY_UNKNOWN ))

    if (( _SUMMARY_TOTAL > 0 )); then
        # Score = (pass + warn*0.5) / (total - unknown) * 100
        # Use integer arithmetic: (pass*100 + warn*50) / (total - unknown)
        local denominator=$(( _SUMMARY_TOTAL - _SUMMARY_UNKNOWN ))
        if (( denominator > 0 )); then
            _SUMMARY_SCORE=$(( (_SUMMARY_PASS * 100 + _SUMMARY_WARN * 50) / denominator ))
        else
            _SUMMARY_SCORE=0
        fi
    else
        _SUMMARY_SCORE=0
    fi
}

# get_summary_json — outputs a JSON object from _SUMMARY_* globals
get_summary_json() {
    printf '{"total":%s,"pass":%s,"fail":%s,"warn":%s,"unknown":%s,"score_pct":%s}' \
        "${_SUMMARY_TOTAL:-0}" \
        "${_SUMMARY_PASS:-0}" \
        "${_SUMMARY_FAIL:-0}" \
        "${_SUMMARY_WARN:-0}" \
        "${_SUMMARY_UNKNOWN:-0}" \
        "${_SUMMARY_SCORE:-0}"
}

# ── Warnings JSON builder ─────────────────────────────────────────────────────
# build_warnings_json
# Reads global COLLECTION_WARNINGS array; outputs a JSON array string.
# Bash 3.2-compatible (no nameref).
build_warnings_json() {
    if [[ ${#COLLECTION_WARNINGS[@]} -eq 0 ]]; then
        echo "[]"
        return
    fi

    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        local tmp
        tmp=$(mktemp /tmp/macguard_warn.XXXXXX)
        printf '%s\0' "${COLLECTION_WARNINGS[@]}" > "$tmp"
        /usr/bin/python3 - "$tmp" <<'PYEOF'
import json, sys, os
with open(sys.argv[1], 'rb') as f:
    raw = f.read()
os.unlink(sys.argv[1])
items = [x.decode('utf-8') for x in raw.split(b'\x00') if x]
print(json.dumps(items))
PYEOF
    else
        local out="["
        local first=true
        local w
        for w in "${COLLECTION_WARNINGS[@]}"; do
            local esc
            esc=$(json_escape_string "$w")
            if [[ "$first" == "true" ]]; then
                out="${out}${esc}"
                first=false
            else
                out="${out},${esc}"
            fi
        done
        echo "${out}]"
    fi
}
