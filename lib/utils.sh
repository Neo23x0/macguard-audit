#!/usr/bin/env bash
# lib/utils.sh — Logging, timeout wrapper, platform detection
# Part of posturectl - macOS Security Posture Reporter
# SPDX-License-Identifier: GPL-3.0-or-later

# ── Logging ──────────────────────────────────────────────────────────────────

# Global log level: debug=0, info=1, warn=2, error=3
_LOG_LEVEL=${_LOG_LEVEL:-1}
_LOG_SYSLOG=${_LOG_SYSLOG:-false}
_LOG_SYSLOG_FACILITY=${_LOG_SYSLOG_FACILITY:-local0}

log_debug() { [[ $_LOG_LEVEL -le 0 ]] && _log "DEBUG" "$*" || true; }
log_info()  { [[ $_LOG_LEVEL -le 1 ]] && _log "INFO"  "$*" || true; }
log_warn()  { [[ $_LOG_LEVEL -le 2 ]] && _log "WARN"  "$*" || true; }
log_error() { [[ $_LOG_LEVEL -le 3 ]] && _log "ERROR" "$*" || true; }

_log() {
    local level="$1"; shift
    local msg="$*"
    local ts
    ts=$(date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "unknown")
    printf '[%s] [%-5s] macguard-audit: %s\n' "$ts" "$level" "$msg" >&2
    if [[ "$_LOG_SYSLOG" == "true" ]]; then
        logger -t macguard-audit -p "${_LOG_SYSLOG_FACILITY}.info" "${level}: ${msg}" 2>/dev/null || true
    fi
}

# ── Timeout wrapper ───────────────────────────────────────────────────────────
# run_with_timeout TIMEOUT_SECS CMD [ARGS...]
# Sets globals:
#   RWT_OUTPUT — combined stdout+stderr of the command
#   RWT_EXIT   — exit code; 124 = timed out
run_with_timeout() {
    local timeout_secs="$1"; shift
    local tmpfile
    tmpfile=$(mktemp /tmp/macguard.XXXXXX 2>/dev/null) || {
        RWT_OUTPUT=""
        RWT_EXIT=1
        return 0  # Always 0; callers inspect RWT_EXIT global
    }

    # Run command in background, capture combined output
    "$@" >"$tmpfile" 2>&1 &
    local pid=$!
    local elapsed_ms=0
    local timeout_ms=$(( timeout_secs * 1000 ))

    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.1
        elapsed_ms=$(( elapsed_ms + 100 ))
        if (( elapsed_ms >= timeout_ms )); then
            kill -TERM "$pid" 2>/dev/null || true
            sleep 0.2
            kill -KILL "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            RWT_OUTPUT=$(cat "$tmpfile" 2>/dev/null || true)
            rm -f "$tmpfile"
            RWT_EXIT=124
            return 0  # Always 0; callers inspect RWT_EXIT global
        fi
    done

    wait "$pid" 2>/dev/null
    RWT_EXIT=$?
    RWT_OUTPUT=$(cat "$tmpfile" 2>/dev/null || true)
    rm -f "$tmpfile"
    return 0  # Always 0; callers inspect RWT_EXIT global
}

# ── Platform detection ────────────────────────────────────────────────────────
# Populates PLATFORM_* globals; safe to call multiple times (idempotent).
detect_environment() {
    PLATFORM_OS_VERSION=$(sw_vers -productVersion 2>/dev/null || echo "unknown")
    PLATFORM_OS_BUILD=$(sw_vers -buildVersion 2>/dev/null || echo "unknown")
    PLATFORM_ARCH=$(uname -m 2>/dev/null || echo "unknown")
    PLATFORM_KERNEL=$(uname -r 2>/dev/null || echo "unknown")
    PLATFORM_MODEL=$(sysctl -n hw.model 2>/dev/null || echo "unknown")

    # Hostname: try scutil (more reliable), fall back to hostname
    PLATFORM_HOSTNAME=$(scutil --get ComputerName 2>/dev/null \
        || hostname -s 2>/dev/null \
        || echo "unknown")

    # Console user: who is logged in at the GUI console
    PLATFORM_CONSOLE_USER=$(stat -f '%Su' /dev/console 2>/dev/null || echo "unknown")

    # Current effective user
    PLATFORM_CURRENT_USER=$(id -un 2>/dev/null || echo "unknown")
    PLATFORM_UID=$(id -u 2>/dev/null || echo "0")

    # Hardware UUID (non-sensitive, stable identifier)
    PLATFORM_HW_UUID=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
        | awk -F'"' '/IOPlatformUUID/{print $4}' \
        || echo "unknown")

    # Serial number — used only for hashing when privacy.hash_serial=true
    PLATFORM_SERIAL=$(ioreg -rd1 -c IOPlatformExpertDevice 2>/dev/null \
        | awk -F'"' '/IOPlatformSerialNumber/{print $4}' \
        || echo "unknown")

    # OS major/minor for version-specific logic
    PLATFORM_OS_MAJOR=$(echo "$PLATFORM_OS_VERSION" | cut -d. -f1 2>/dev/null || echo "0")
    PLATFORM_OS_MINOR=$(echo "$PLATFORM_OS_VERSION" | cut -d. -f2 2>/dev/null || echo "0")

    # Uptime in seconds — parse sysctl kern.boottime
    local boottime_raw
    boottime_raw=$(sysctl -n kern.boottime 2>/dev/null || echo "")
    if [[ "$boottime_raw" =~ sec\ =\ ([0-9]+) ]]; then
        local boot_sec="${BASH_REMATCH[1]}"
        local now_sec
        now_sec=$(date +%s 2>/dev/null || echo "0")
        PLATFORM_UPTIME_SECS=$(( now_sec - boot_sec ))
    else
        PLATFORM_UPTIME_SECS=0
    fi

    # Root detection
    if [[ "$PLATFORM_UID" == "0" ]]; then
        RUN_AS_ROOT=true
    else
        RUN_AS_ROOT=false
    fi

    # MDM enrollment check (non-fatal)
    PLATFORM_MDM_ENROLLED=false
    PLATFORM_MDM_URL=""
    if command -v profiles >/dev/null 2>&1; then
        local mdm_info
        mdm_info=$(profiles status -type enrollment 2>/dev/null || true)
        if echo "$mdm_info" | grep -q "MDM enrollment: Yes" 2>/dev/null; then
            PLATFORM_MDM_ENROLLED=true
            PLATFORM_MDM_URL=$(profiles -e 2>/dev/null \
                | awk -F': ' '/ServerURL/{print $2; exit}' \
                || echo "")
        fi
    fi

    # Python3 availability at Apple's system path
    PYTHON3_AVAILABLE=false
    if /usr/bin/python3 --version >/dev/null 2>&1; then
        PYTHON3_AVAILABLE=true
    fi

    log_debug "Platform: macOS ${PLATFORM_OS_VERSION} (${PLATFORM_OS_BUILD}) arch=${PLATFORM_ARCH} root=${RUN_AS_ROOT} python3=${PYTHON3_AVAILABLE}"
}

# ── Timestamp helpers ─────────────────────────────────────────────────────────

# epoch_ms: milliseconds since Unix epoch
epoch_ms() {
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        /usr/bin/python3 -c "import time; print(int(time.time()*1000))" 2>/dev/null \
            || echo $(( $(date +%s) * 1000 ))
    else
        echo $(( $(date +%s) * 1000 ))
    fi
}

# now_rfc3339: current UTC time in RFC3339 format
now_rfc3339() {
    date -u +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || echo "1970-01-01T00:00:00Z"
}

# ── Privilege helpers ─────────────────────────────────────────────────────────

is_root() { [[ "${RUN_AS_ROOT:-false}" == "true" ]]; }

require_root_or_skip() {
    local check_name="$1"
    if ! is_root; then
        CHECK_STATUS="unknown"
        CHECK_VALUE=""
        CHECK_RAW=""
        CHECK_ERROR="requires root; skipped"
        CHECK_PRIVILEGE="root"
        CHECK_DURATION_MS=0
        return 1
    fi
    return 0
}

# ── String helpers ────────────────────────────────────────────────────────────

# truncate STRING MAX_LEN
# Truncates a string to MAX_LEN chars, appending "..." if truncated
truncate_str() {
    local s="$1"
    local max="${2:-512}"
    if [[ ${#s} -gt $max ]]; then
        echo "${s:0:$max}..."
    else
        echo "$s"
    fi
}

# sha256_hex STRING
# Returns lowercase hex SHA-256 of STRING; requires shasum (always on macOS)
sha256_hex() {
    echo -n "$1" | shasum -a 256 2>/dev/null | awk '{print $1}' || echo ""
}
