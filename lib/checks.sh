#!/usr/bin/env bash
# lib/checks.sh — All 29 security posture check functions
# Part of macguard-audit
# SPDX-License-Identifier: GPL-3.0-or-later
#
# Each check_NAME() function follows this contract:
#   - Sets CHECK_STATUS   : pass | fail | warn | unknown
#   - Sets CHECK_VALUE    : typed value (string/integer/boolean as string/object-json)
#   - Sets CHECK_VALUE_JSON: pre-built JSON for complex value types (or unset)
#   - Sets CHECK_RAW      : raw command output (will be truncated by assembler)
#   - Sets CHECK_ERROR    : error string, or ""
#   - Sets CHECK_PRIVILEGE: "user" or "root"
#   - Sets CHECK_DURATION_MS: wall-clock ms for the check
#   - Never exits non-zero (uses || true guards everywhere)
#   - Calls require_root_or_skip when root is needed
#
# ENABLED_CHECKS array defines run order and must list all check names.

ENABLED_CHECKS=(
    # User-level checks (no root required)
    filevault
    gatekeeper
    sip
    ssh_remote_login
    screen_lock_timeout
    auto_login
    guest_account
    xprotect_version
    xprotect_remediator_version
    xprotect_last_update
    mrt_version
    mrt_last_update
    auto_updates
    pending_updates
    is_admin
    time_sync
    airdrop
    remote_management
    browser_versions
    disk_encryption_apfs
    secure_boot
    tcc_version
    # Root-required checks (silently skipped when not root)
    firewall_global_state
    firewall_stealth_mode
    firewall_logging
    profiles
    system_extensions
    # Slow checks last
    firmware_version
)

# ── Helper: start/end timing ──────────────────────────────────────────────────
_check_start() {
    CHECK_STATUS="unknown"
    CHECK_VALUE=""
    CHECK_VALUE_JSON=""
    CHECK_RAW=""
    CHECK_ERROR=""
    CHECK_PRIVILEGE="user"
    CHECK_DURATION_MS=0
    _CHECK_START_MS=$(epoch_ms)
}

_check_end() {
    CHECK_DURATION_MS=$(( $(epoch_ms) - _CHECK_START_MS ))
}

# ── CHECK 01: filevault ───────────────────────────────────────────────────────
check_filevault() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" fdesetup status
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "FileVault is On"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
    elif echo "$RWT_OUTPUT" | grep -qi "FileVault is Off"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 02: gatekeeper ──────────────────────────────────────────────────────
# NOTE: spctl --status writes to STDERR on macOS 15+; run_with_timeout captures 2>&1
check_gatekeeper() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" spctl --status
    CHECK_RAW="$RWT_OUTPUT"

    local state="unknown"
    local assessments=false

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "assessments enabled"; then
        CHECK_STATUS="pass"; state="enabled"; assessments=true
    elif echo "$RWT_OUTPUT" | grep -qi "assessments disabled"; then
        CHECK_STATUS="fail"; state="disabled"; assessments=false
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    # Build JSON object value
    if [[ "$CHECK_STATUS" != "unknown" ]]; then
        CHECK_VALUE_JSON=$(printf '{"state":%s,"assessments_enabled":%s}' \
            "$(json_escape_string "$state")" \
            "$(json_bool "$assessments")")
        CHECK_VALUE="$state"  # simple scalar fallback
    fi

    _check_end
}

# ── CHECK 03: sip ─────────────────────────────────────────────────────────────
check_sip() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" csrutil status
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "Custom Configuration"; then
        CHECK_STATUS="warn"; CHECK_VALUE="custom_configuration"
    elif echo "$RWT_OUTPUT" | grep -qi "enabled"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
    elif echo "$RWT_OUTPUT" | grep -qi "disabled"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 04: firewall_global_state ──────────────────────────────────────────
check_firewall_global_state() {
    _check_start
    CHECK_PRIVILEGE="root"
    require_root_or_skip "firewall_global_state" || { _check_end; return; }

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        /usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "enabled"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
    elif echo "$RWT_OUTPUT" | grep -qi "disabled"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 05: firewall_stealth_mode ──────────────────────────────────────────
check_firewall_stealth_mode() {
    _check_start
    CHECK_PRIVILEGE="root"
    require_root_or_skip "firewall_stealth_mode" || { _check_end; return; }

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        /usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "Stealth mode enabled"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
    elif echo "$RWT_OUTPUT" | grep -qi "Stealth mode disabled"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 06: firewall_logging ────────────────────────────────────────────────
check_firewall_logging() {
    _check_start
    CHECK_PRIVILEGE="root"
    require_root_or_skip "firewall_logging" || { _check_end; return; }

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        /usr/libexec/ApplicationFirewall/socketfilterfw --getloggingmode
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$RWT_OUTPUT" | grep -qi "Log mode is on\|enabled"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
    elif echo "$RWT_OUTPUT" | grep -qi "Log mode is off\|disabled"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
    else
        CHECK_ERROR="unrecognized output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 07: ssh_remote_login ────────────────────────────────────────────────
check_ssh_remote_login() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Primary: systemsetup (deprecated in macOS 15 but still functional)
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" systemsetup -getremotelogin
    local primary_output="$RWT_OUTPUT"
    local primary_exit=$RWT_EXIT

    if [[ $primary_exit -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$primary_output" | grep -qi "Remote Login: Off"; then
        CHECK_STATUS="pass"; CHECK_VALUE="disabled"
        CHECK_RAW=$(echo "$primary_output" | head -1)
    elif echo "$primary_output" | grep -qi "Remote Login: On"; then
        CHECK_STATUS="fail"; CHECK_VALUE="enabled"
        CHECK_RAW=$(echo "$primary_output" | head -1)
    else
        # Fallback: check via launchctl (works on macOS 15+)
        run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
            launchctl list com.openssh.sshd
        CHECK_RAW="$RWT_OUTPUT"
        if [[ $RWT_EXIT -eq 0 ]] && echo "$RWT_OUTPUT" | grep -q '"PID"'; then
            CHECK_STATUS="fail"; CHECK_VALUE="enabled"
        elif [[ $RWT_EXIT -ne 0 ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="disabled"
        else
            CHECK_STATUS="unknown"
            CHECK_ERROR="could not determine SSH status from systemsetup or launchctl"
        fi
    fi

    _check_end
}

# ── CHECK 08: screen_lock_timeout ─────────────────────────────────────────────
check_screen_lock_timeout() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Read screensaver idleTime from ByHost preferences
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read /Library/Preferences/ByHost/com.apple.screensaver idleTime
    CHECK_RAW="$RWT_OUTPUT"

    local max_secs="${THRESHOLD_SCREEN_LOCK_MAX_SECS:-600}"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]] && [[ "${RWT_OUTPUT}" =~ ^[0-9]+$ ]]; then
        local idle="${RWT_OUTPUT}"
        CHECK_VALUE="$idle"
        if [[ "$idle" -eq 0 ]]; then
            CHECK_STATUS="fail"  # 0 = never lock
        elif [[ "$idle" -le "$max_secs" ]]; then
            CHECK_STATUS="pass"
        else
            CHECK_STATUS="warn"  # locks eventually, but too long
        fi
    elif [[ $RWT_EXIT -ne 0 ]]; then
        # Key may not exist; try user-level domain
        run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
            defaults -currentHost read com.apple.screensaver idleTime
        CHECK_RAW="$RWT_OUTPUT"
        if [[ $RWT_EXIT -eq 0 ]] && [[ "${RWT_OUTPUT}" =~ ^[0-9]+$ ]]; then
            local idle="${RWT_OUTPUT}"
            CHECK_VALUE="$idle"
            if [[ "$idle" -eq 0 ]]; then
                CHECK_STATUS="fail"
            elif [[ "$idle" -le "$max_secs" ]]; then
                CHECK_STATUS="pass"
            else
                CHECK_STATUS="warn"
            fi
        else
            CHECK_ERROR="idleTime key not found in screensaver preferences"
        fi
    else
        CHECK_ERROR="unexpected output: $(truncate_str "$RWT_OUTPUT" 80)"
    fi

    _check_end
}

# ── CHECK 09: auto_login ──────────────────────────────────────────────────────
check_auto_login() {
    _check_start
    CHECK_PRIVILEGE="user"

    # DisableAutoLogin = 1 means auto-login IS disabled (good)
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read /Library/Preferences/com.apple.loginwindow DisableAutoLogin
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]]; then
        local val="${RWT_OUTPUT//[[:space:]]/}"  # strip whitespace
        if [[ "$val" == "1" ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="disabled"
        else
            CHECK_STATUS="fail"; CHECK_VALUE="enabled"
        fi
    else
        # Key missing = auto-login not explicitly disabled
        CHECK_STATUS="fail"; CHECK_VALUE="not_disabled"
        CHECK_RAW="key DisableAutoLogin not found"
    fi

    _check_end
}

# ── CHECK 10: guest_account ───────────────────────────────────────────────────
check_guest_account() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]]; then
        local val="${RWT_OUTPUT//[[:space:]]/}"
        if [[ "$val" == "0" ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="disabled"
        else
            CHECK_STATUS="fail"; CHECK_VALUE="enabled"
        fi
    else
        # Key missing = guest account disabled by default
        CHECK_STATUS="pass"; CHECK_VALUE="disabled"
        CHECK_RAW="key GuestEnabled not found (defaults to disabled)"
    fi

    _check_end
}

# ── CHECK 11: xprotect_version ────────────────────────────────────────────────
check_xprotect_version() {
    _check_start
    CHECK_PRIVILEGE="user"

    local -a xp_paths=(
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle/Contents/Info.plist"
        "/private/var/protected/xprotect/XProtect.bundle/Contents/Info.plist"
    )

    local version=""
    local found_path=""
    local p
    for p in "${xp_paths[@]}"; do
        if [[ -f "$p" ]]; then
            run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
                defaults read "$p" CFBundleShortVersionString
            if [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
                version="${RWT_OUTPUT//[[:space:]]/}"
                found_path="$p"
                break
            fi
        fi
    done

    if [[ -n "$version" ]]; then
        CHECK_STATUS="pass"
        CHECK_VALUE="$version"
        CHECK_RAW="path=${found_path} version=${version}"
    elif [[ -z "$found_path" ]]; then
        CHECK_ERROR="XProtect.bundle not found at expected paths"
    else
        CHECK_ERROR="could not read CFBundleShortVersionString from $found_path"
    fi

    _check_end
}

# ── CHECK 12: xprotect_remediator_version ─────────────────────────────────────
check_xprotect_remediator_version() {
    _check_start
    CHECK_PRIVILEGE="user"

    local xpr_plist="/Library/Apple/System/Library/CoreServices/XProtect.app/Contents/Info.plist"

    if [[ ! -f "$xpr_plist" ]]; then
        CHECK_ERROR="XProtect.app not found (macOS < 12 or path changed)"
        _check_end; return
    fi

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read "$xpr_plist" CFBundleShortVersionString
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
        CHECK_STATUS="pass"
        CHECK_VALUE="${RWT_OUTPUT//[[:space:]]/}"
    else
        CHECK_ERROR="could not read CFBundleShortVersionString from XProtect.app"
    fi

    _check_end
}

# ── CHECK 13: xprotect_last_update ────────────────────────────────────────────
check_xprotect_last_update() {
    _check_start
    CHECK_PRIVILEGE="user"

    local max_age_days="${THRESHOLD_UPDATE_STALENESS_DAYS:-30}"

    local -a xp_dirs=(
        "/Library/Apple/System/Library/CoreServices/XProtect.bundle"
        "/private/var/protected/xprotect/XProtect.bundle"
    )

    local mtime="" found_path=""
    local d
    for d in "${xp_dirs[@]}"; do
        if [[ -d "$d" ]]; then
            mtime=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$d" 2>/dev/null || true)
            if [[ -n "$mtime" ]]; then
                found_path="$d"
                break
            fi
        fi
    done

    if [[ -z "$mtime" ]]; then
        CHECK_ERROR="XProtect bundle directory not found"
        _check_end; return
    fi

    CHECK_RAW="mtime=${mtime} path=${found_path}"
    CHECK_VALUE="$mtime"

    # Compute age in days (requires python3 for date arithmetic; fall back to unknown)
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        local age_days
        age_days=$(/usr/bin/python3 -c "
from datetime import datetime, timezone
import sys
ts = sys.argv[1].rstrip('Z')
try:
    dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    print(int((now - dt).days))
except Exception as e:
    print(-1)
" "$mtime" 2>/dev/null || echo "-1")

        if [[ "$age_days" -lt 0 ]]; then
            CHECK_ERROR="could not compute age from timestamp $mtime"
        elif [[ "$age_days" -le "$max_age_days" ]]; then
            CHECK_STATUS="pass"
        else
            CHECK_STATUS="fail"
            CHECK_ERROR="XProtect last updated ${age_days} days ago (threshold: ${max_age_days} days)"
        fi
    else
        # Without python3, report value but status unknown
        CHECK_STATUS="pass"  # report as informational; can't compute age without python3
    fi

    _check_end
}

# ── CHECK 14: mrt_version ─────────────────────────────────────────────────────
check_mrt_version() {
    _check_start
    CHECK_PRIVILEGE="user"

    local mrt_plist="/Library/Apple/System/Library/CoreServices/MRT.app/Contents/Info.plist"

    if [[ ! -f "$mrt_plist" ]]; then
        CHECK_ERROR="MRT.app not found (may be Cryptex-delivered on macOS 15)"
        _check_end; return
    fi

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read "$mrt_plist" CFBundleShortVersionString
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
        CHECK_STATUS="pass"
        CHECK_VALUE="${RWT_OUTPUT//[[:space:]]/}"
    else
        CHECK_ERROR="could not read MRT version"
    fi

    _check_end
}

# ── CHECK 15: mrt_last_update ─────────────────────────────────────────────────
check_mrt_last_update() {
    _check_start
    CHECK_PRIVILEGE="user"

    local max_age_days="${THRESHOLD_UPDATE_STALENESS_DAYS:-30}"
    local mrt_dir="/Library/Apple/System/Library/CoreServices/MRT.app"

    if [[ ! -d "$mrt_dir" ]]; then
        CHECK_ERROR="MRT.app directory not found"
        _check_end; return
    fi

    local mtime
    mtime=$(stat -f "%Sm" -t "%Y-%m-%dT%H:%M:%SZ" "$mrt_dir" 2>/dev/null || true)

    if [[ -z "$mtime" ]]; then
        CHECK_ERROR="could not stat MRT.app"
        _check_end; return
    fi

    CHECK_RAW="mtime=${mtime}"
    CHECK_VALUE="$mtime"

    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        local age_days
        age_days=$(/usr/bin/python3 -c "
from datetime import datetime, timezone
import sys
ts = sys.argv[1].rstrip('Z')
try:
    dt = datetime.strptime(ts, '%Y-%m-%dT%H:%M:%S').replace(tzinfo=timezone.utc)
    now = datetime.now(timezone.utc)
    print(int((now - dt).days))
except Exception:
    print(-1)
" "$mtime" 2>/dev/null || echo "-1")

        if [[ "$age_days" -lt 0 ]]; then
            CHECK_ERROR="could not compute age from timestamp $mtime"
        elif [[ "$age_days" -le "$max_age_days" ]]; then
            CHECK_STATUS="pass"
        else
            CHECK_STATUS="fail"
            CHECK_ERROR="MRT last updated ${age_days} days ago (threshold: ${max_age_days} days)"
        fi
    else
        CHECK_STATUS="pass"
    fi

    _check_end
}

# ── CHECK 16: auto_updates ────────────────────────────────────────────────────
check_auto_updates() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Primary: plist-based check (fast, offline)
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]]; then
        local val="${RWT_OUTPUT//[[:space:]]/}"
        if [[ "$val" == "1" ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="enabled"
        else
            CHECK_STATUS="fail"; CHECK_VALUE="disabled"
        fi
    else
        # Fallback: softwareupdate --schedule (deprecated but still works)
        run_with_timeout 20 softwareupdate --schedule
        CHECK_RAW="$RWT_OUTPUT"
        if [[ $RWT_EXIT -eq 124 ]]; then
            CHECK_ERROR="timeout"
        elif echo "$RWT_OUTPUT" | grep -qi "Automatic check is on"; then
            CHECK_STATUS="pass"; CHECK_VALUE="enabled"
        elif echo "$RWT_OUTPUT" | grep -qi "Automatic check is off"; then
            CHECK_STATUS="fail"; CHECK_VALUE="disabled"
        else
            CHECK_ERROR="could not determine auto-update status"
        fi
    fi

    _check_end
}

# ── CHECK 17: pending_updates ─────────────────────────────────────────────────
check_pending_updates() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Read cached recommended updates — no network call
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read /Library/Preferences/com.apple.SoftwareUpdate RecommendedUpdates
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
        # Count entries: each update starts with "{"
        local count
        count=$(echo "$RWT_OUTPUT" | grep -c "^    {" 2>/dev/null || echo "0")
        # Fallback count method
        if [[ "$count" -eq 0 ]]; then
            count=$(echo "$RWT_OUTPUT" | grep -c "Identifier" 2>/dev/null || echo "0")
        fi
        CHECK_VALUE="$count"
        if [[ "$count" -gt 0 ]]; then
            CHECK_STATUS="warn"
            # Extract update names for raw field
            local names
            names=$(echo "$RWT_OUTPUT" \
                | awk -F'"' '/Identifier/{print $4}' \
                | head -5 \
                | tr '\n' ',' \
                | sed 's/,$//' \
                || true)
            CHECK_RAW="count=${count} updates=${names}"
        else
            CHECK_STATUS="pass"
            CHECK_RAW="no pending updates (cached)"
        fi
    else
        # Key missing = no pending updates recorded
        CHECK_STATUS="pass"
        CHECK_VALUE="0"
        CHECK_RAW="RecommendedUpdates key not found (no pending updates)"
    fi

    _check_end
}

# ── CHECK 18: is_admin ────────────────────────────────────────────────────────
check_is_admin() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        dseditgroup -o checkmember -m "${PLATFORM_CURRENT_USER:-$(id -un)}" admin
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]]; then
        # Exit code 0 = IS a member of admin
        if [[ "${CFG_IS_ADMIN_IS_FAIL:-false}" == "true" ]]; then
            CHECK_STATUS="fail"
        else
            CHECK_STATUS="warn"
        fi
        CHECK_VALUE="true"
    else
        # Non-zero exit = NOT a member
        CHECK_STATUS="pass"
        CHECK_VALUE="false"
    fi

    _check_end
}

# ── CHECK 19: time_sync ───────────────────────────────────────────────────────
check_time_sync() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Primary: systemsetup (deprecated macOS 15 but functional)
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" systemsetup -getusingnetworktime
    local primary_output="$RWT_OUTPUT"
    local primary_exit=$RWT_EXIT

    if [[ $primary_exit -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif echo "$primary_output" | grep -qi "Network Time: On"; then
        CHECK_STATUS="pass"; CHECK_VALUE="enabled"
        CHECK_RAW=$(echo "$primary_output" | head -1)
    elif echo "$primary_output" | grep -qi "Network Time: Off"; then
        CHECK_STATUS="fail"; CHECK_VALUE="disabled"
        CHECK_RAW=$(echo "$primary_output" | head -1)
    else
        # Fallback: check timed daemon (macOS 13+)
        run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
            launchctl list com.apple.timed
        CHECK_RAW="$RWT_OUTPUT"
        if [[ $RWT_EXIT -eq 0 ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="enabled"
        else
            CHECK_STATUS="unknown"
            CHECK_ERROR="could not determine NTP status from systemsetup or launchctl"
        fi
    fi

    _check_end
}

# ── CHECK 20: airdrop ─────────────────────────────────────────────────────────
check_airdrop() {
    _check_start
    CHECK_PRIVILEGE="user"

    local policy="${THRESHOLD_AIRDROP_POLICY:-contacts_or_off}"

    # Try sharingd preference first
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read com.apple.sharingd DiscoverableMode
    local sharingd_output="$RWT_OUTPUT"
    local sharingd_exit=$RWT_EXIT

    # Also check Finder preference (macOS 13+)
    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read com.apple.finder ShareAirDropWithEveryone
    local finder_output="$RWT_OUTPUT"
    local finder_exit=$RWT_EXIT

    local mode="off"

    if [[ $sharingd_exit -eq 0 ]] && [[ -n "$sharingd_output" ]]; then
        local raw="${sharingd_output//[[:space:]]/}"
        CHECK_RAW="sharingd.DiscoverableMode=${raw}"
        case "$raw" in
            Off|"") mode="off" ;;
            "ContactsOnly") mode="contacts_only" ;;
            Everyone) mode="everyone" ;;
            *) mode="unknown_value" ;;
        esac
    elif [[ $finder_exit -eq 0 ]] && [[ -n "$finder_output" ]]; then
        local raw="${finder_output//[[:space:]]/}"
        CHECK_RAW="finder.ShareAirDropWithEveryone=${raw}"
        if [[ "$raw" == "1" ]]; then mode="everyone"; else mode="off"; fi
    else
        # Key missing = AirDrop default (Off or Contacts Only depending on macOS version)
        mode="off"
        CHECK_RAW="no AirDrop preference key found (defaulting to off)"
    fi

    CHECK_VALUE="$mode"

    case "$mode" in
        off)
            CHECK_STATUS="pass"
            ;;
        contacts_only)
            if [[ "$policy" == "off_only" ]]; then
                CHECK_STATUS="fail"
            else
                CHECK_STATUS="warn"
            fi
            ;;
        everyone)
            CHECK_STATUS="fail"
            ;;
        *)
            CHECK_STATUS="unknown"
            CHECK_ERROR="unrecognized AirDrop mode value: ${mode}"
            ;;
    esac

    _check_end
}

# ── CHECK 21: remote_management ───────────────────────────────────────────────
check_remote_management() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Check Screen Sharing (ARD) and Remote Desktop agent
    local screen_sharing_running=false
    local ard_running=false

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        launchctl list com.apple.screensharing
    if [[ $RWT_EXIT -eq 0 ]] && echo "$RWT_OUTPUT" | grep -q '"PID"'; then
        screen_sharing_running=true
    fi

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        launchctl list com.apple.RemoteDesktop.agent
    if [[ $RWT_EXIT -eq 0 ]] && echo "$RWT_OUTPUT" | grep -q '"PID"'; then
        ard_running=true
    fi

    CHECK_RAW="screensharing=${screen_sharing_running} RemoteDesktop.agent=${ard_running}"

    if [[ "$screen_sharing_running" == "true" ]] || [[ "$ard_running" == "true" ]]; then
        CHECK_STATUS="fail"; CHECK_VALUE="enabled"
    else
        CHECK_STATUS="pass"; CHECK_VALUE="disabled"
    fi

    _check_end
}

# ── CHECK 22: browser_versions ────────────────────────────────────────────────
check_browser_versions() {
    _check_start
    CHECK_PRIVILEGE="user"

    local -A versions=()

    _get_browser_version() {
        local name="$1"; shift
        local paths=("$@")
        local p
        for p in "${paths[@]}"; do
            if [[ -f "$p" ]]; then
                run_with_timeout 5 defaults read "$p" CFBundleShortVersionString
                if [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
                    versions["$name"]="${RWT_OUTPUT//[[:space:]]/}"
                    return
                fi
            fi
        done
        versions["$name"]="not_installed"
    }

    _get_browser_version "safari" \
        "/Applications/Safari.app/Contents/Info.plist"

    _get_browser_version "chrome" \
        "/Applications/Google Chrome.app/Contents/Info.plist" \
        "${HOME}/Applications/Google Chrome.app/Contents/Info.plist"

    _get_browser_version "firefox" \
        "/Applications/Firefox.app/Contents/Info.plist" \
        "${HOME}/Applications/Firefox.app/Contents/Info.plist"

    _get_browser_version "brave" \
        "/Applications/Brave Browser.app/Contents/Info.plist" \
        "${HOME}/Applications/Brave Browser.app/Contents/Info.plist"

    _get_browser_version "edge" \
        "/Applications/Microsoft Edge.app/Contents/Info.plist" \
        "${HOME}/Applications/Microsoft Edge.app/Contents/Info.plist"

    _get_browser_version "arc" \
        "/Applications/Arc.app/Contents/Info.plist" \
        "${HOME}/Applications/Arc.app/Contents/Info.plist"

    # Build JSON object
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        CHECK_VALUE_JSON=$(/usr/bin/python3 -c "
import json, sys
d = {}
pairs = [x.split('=',1) for x in sys.argv[1:] if '=' in x]
for k,v in pairs: d[k] = v
print(json.dumps(d))
" \
            "safari=${versions[safari]}" \
            "chrome=${versions[chrome]}" \
            "firefox=${versions[firefox]}" \
            "brave=${versions[brave]}" \
            "edge=${versions[edge]}" \
            "arc=${versions[arc]}" \
            2>/dev/null || echo "null")
    else
        CHECK_VALUE_JSON=$(printf \
            '{"safari":%s,"chrome":%s,"firefox":%s,"brave":%s,"edge":%s,"arc":%s}' \
            "$(json_escape_string "${versions[safari]}")" \
            "$(json_escape_string "${versions[chrome]}")" \
            "$(json_escape_string "${versions[firefox]}")" \
            "$(json_escape_string "${versions[brave]}")" \
            "$(json_escape_string "${versions[edge]}")" \
            "$(json_escape_string "${versions[arc]}")")
    fi

    CHECK_STATUS="pass"
    CHECK_RAW=""  # no single raw output for compound check

    _check_end
}

# ── CHECK 23: disk_encryption_apfs ────────────────────────────────────────────
check_disk_encryption_apfs() {
    _check_start
    CHECK_PRIVILEGE="user"

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" diskutil apfs list
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -ne 0 ]]; then
        CHECK_ERROR="diskutil apfs list failed (may not be APFS)"
    else
        # Look for FileVault: Yes lines
        local fv_yes
        fv_yes=$(echo "$RWT_OUTPUT" | grep -i "FileVault:.*Yes" | head -3 || true)
        local fv_no
        fv_no=$(echo "$RWT_OUTPUT" | grep -i "FileVault:.*No" | head -3 || true)

        if [[ -n "$fv_yes" ]]; then
            CHECK_STATUS="pass"; CHECK_VALUE="encrypted"
            CHECK_RAW=$(echo "$fv_yes" | head -1 | sed 's/^[[:space:]]*//')
        elif [[ -n "$fv_no" ]]; then
            CHECK_STATUS="fail"; CHECK_VALUE="unencrypted"
            CHECK_RAW=$(echo "$fv_no" | head -1 | sed 's/^[[:space:]]*//')
        else
            CHECK_ERROR="FileVault status not found in diskutil apfs list output"
        fi
    fi

    _check_end
}

# ── CHECK 24: secure_boot ─────────────────────────────────────────────────────
check_secure_boot() {
    _check_start
    CHECK_PRIVILEGE="user"

    if [[ "${PLATFORM_ARCH:-unknown}" == "arm64" ]]; then
        # Apple Silicon: use bputil
        run_with_timeout "${TIMEOUT_PER_CHECK:-15}" bputil -d
        CHECK_RAW="$RWT_OUTPUT"

        if [[ $RWT_EXIT -eq 124 ]]; then
            CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
        elif echo "$RWT_OUTPUT" | grep -qi "Full Security"; then
            CHECK_STATUS="pass"; CHECK_VALUE="full_security"
        elif echo "$RWT_OUTPUT" | grep -qi "Reduced Security"; then
            CHECK_STATUS="warn"; CHECK_VALUE="reduced_security"
        elif echo "$RWT_OUTPUT" | grep -qi "Permissive Security"; then
            CHECK_STATUS="fail"; CHECK_VALUE="permissive_security"
        else
            CHECK_ERROR="bputil did not return recognizable security level"
        fi
    else
        # Intel: nvram-based check
        local guid="94b73556-2197-4702-82a8-3e1337dafbfb"
        run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
            nvram "${guid}:AppleSecureBootPolicy"
        CHECK_RAW="$RWT_OUTPUT"

        if [[ $RWT_EXIT -eq 124 ]]; then
            CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
        elif [[ $RWT_EXIT -ne 0 ]]; then
            # Key not present — likely a VM or very old Intel Mac
            CHECK_ERROR="AppleSecureBootPolicy nvram key not found (VM or legacy Intel Mac)"
        else
            # Value is typically: <guid>:AppleSecureBootPolicy	%03
            local raw_val="${RWT_OUTPUT##*$'\t'}"  # strip up to last tab
            raw_val="${raw_val//[[:space:]]/}"
            case "$raw_val" in
                *03*|*\x03*) CHECK_STATUS="pass";  CHECK_VALUE="full_security" ;;
                *01*|*\x01*) CHECK_STATUS="warn";  CHECK_VALUE="reduced_security" ;;
                *00*|*\x00*) CHECK_STATUS="fail";  CHECK_VALUE="permissive_security" ;;
                *)
                    CHECK_STATUS="unknown"
                    CHECK_ERROR="unrecognized nvram value: ${raw_val}"
                    ;;
            esac
        fi
    fi

    _check_end
}

# ── CHECK 25: tcc_version ─────────────────────────────────────────────────────
check_tcc_version() {
    _check_start
    CHECK_PRIVILEGE="user"

    local tcc_plist="/System/Library/PrivateFrameworks/TCC.framework/Versions/A/Resources/Info.plist"

    if [[ ! -f "$tcc_plist" ]]; then
        CHECK_ERROR="TCC Info.plist not found (may be in dyld cache on macOS 15)"
        _check_end; return
    fi

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" \
        defaults read "$tcc_plist" CFBundleVersion
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -eq 0 ]] && [[ -n "$RWT_OUTPUT" ]]; then
        CHECK_STATUS="pass"
        CHECK_VALUE="${RWT_OUTPUT//[[:space:]]/}"
    else
        CHECK_ERROR="could not read TCC version"
    fi

    _check_end
}

# ── CHECK 26: firewall_global_state (root) — already defined as CHECK 04
# ── CHECK 27: firewall_stealth_mode (root) — already defined as CHECK 05
# ── CHECK 28: firewall_logging (root) — already defined as CHECK 06

# ── CHECK 26: profiles ────────────────────────────────────────────────────────
check_profiles() {
    _check_start
    CHECK_PRIVILEGE="root"
    require_root_or_skip "profiles" || { _check_end; return; }

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" profiles -P
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -ne 0 ]]; then
        CHECK_ERROR="profiles -P failed (TCC FDA may be required)"
    else
        # Count profiles by "There are N configuration profiles installed"
        # or by counting ProfileDisplayName lines
        local count=0
        if echo "$RWT_OUTPUT" | grep -q "There are [0-9]"; then
            count=$(echo "$RWT_OUTPUT" \
                | grep -o "There are [0-9][0-9]*" \
                | grep -o "[0-9][0-9]*" \
                | head -1 || echo "0")
        else
            count=$(echo "$RWT_OUTPUT" \
                | grep -c "ProfileDisplayName\|attribute: name" 2>/dev/null \
                || true)
            count="${count:-0}"
        fi

        CHECK_VALUE="$count"
        CHECK_STATUS="pass"  # presence or absence of profiles is informational

        if [[ "$count" -eq 0 ]]; then
            CHECK_RAW="no configuration profiles installed"
        else
            # Extract profile identifiers (not display names; safer)
            local ids
            ids=$(echo "$RWT_OUTPUT" \
                | awk -F'"' '/ProfileIdentifier/{print $4}' \
                | head -10 \
                | tr '\n' ',' \
                | sed 's/,$//' \
                || true)
            CHECK_RAW="count=${count} identifiers=${ids}"
        fi
    fi

    _check_end
}

# ── CHECK 27: system_extensions ───────────────────────────────────────────────
check_system_extensions() {
    _check_start
    CHECK_PRIVILEGE="root"
    require_root_or_skip "system_extensions" || { _check_end; return; }

    run_with_timeout "${TIMEOUT_PER_CHECK:-15}" systemextensionsctl list
    CHECK_RAW="$RWT_OUTPUT"

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout after ${TIMEOUT_PER_CHECK:-15}s"
    elif [[ $RWT_EXIT -ne 0 ]]; then
        CHECK_ERROR="systemextensionsctl list failed"
    else
        local active_count=0
        active_count=$(echo "$RWT_OUTPUT" \
            | grep -c "\[activated enabled\]" \
            || echo "0")

        CHECK_VALUE="$active_count"
        CHECK_STATUS="pass"  # informational; no policy-based pass/fail in v1
        CHECK_RAW=$(echo "$RWT_OUTPUT" | grep "\[activated enabled\]" | head -10 \
            || echo "no active system extensions")
    fi

    _check_end
}

# ── CHECK 28: firmware_version (SLOW — run last) ──────────────────────────────
check_firmware_version() {
    _check_start
    CHECK_PRIVILEGE="user"

    # Use a longer timeout: system_profiler can take 5-10s
    run_with_timeout 30 system_profiler SPHardwareDataType
    CHECK_RAW=""  # don't store full system_profiler output

    if [[ $RWT_EXIT -eq 124 ]]; then
        CHECK_ERROR="timeout (system_profiler took >30s)"
        _check_end; return
    elif [[ $RWT_EXIT -ne 0 ]]; then
        CHECK_ERROR="system_profiler SPHardwareDataType failed"
        _check_end; return
    fi

    local firmware_type="" firmware_version="" bridge_version=""

    if [[ "${PLATFORM_ARCH:-unknown}" == "arm64" ]]; then
        firmware_type="iboot"
        firmware_version=$(echo "$RWT_OUTPUT" \
            | awk -F': ' '/System Firmware Version:/{gsub(/^[[:space:]]+/,"",$2); print $2}' \
            | head -1 || true)
        # Clean up
        firmware_version="${firmware_version//[[:space:]]/}"
    else
        firmware_type="efi"
        firmware_version=$(echo "$RWT_OUTPUT" \
            | awk -F': ' '/Boot ROM Version:/{gsub(/^[[:space:]]+/,"",$2); print $2}' \
            | head -1 || true)
        firmware_version="${firmware_version//[[:space:]]/}"

        # T2 bridge firmware
        bridge_version=$(echo "$RWT_OUTPUT" \
            | awk -F': ' '/Bridge OS Version:/{gsub(/^[[:space:]]+/,"",$2); print $2}' \
            | head -1 || true)
        bridge_version="${bridge_version//[[:space:]]/}"
    fi

    if [[ -z "$firmware_version" ]]; then
        CHECK_ERROR="firmware version field not found in system_profiler output"
        _check_end; return
    fi

    CHECK_STATUS="pass"
    CHECK_RAW="type=${firmware_type} version=${firmware_version}"

    # Build JSON object value
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        CHECK_VALUE_JSON=$(/usr/bin/python3 -c "
import json, sys
d = {'firmware_type': sys.argv[1], 'firmware_version': sys.argv[2]}
bv = sys.argv[3]
d['bridge_version'] = bv if bv else None
print(json.dumps(d))
" "$firmware_type" "$firmware_version" "${bridge_version:-}" 2>/dev/null \
            || echo "null")
    else
        local bv_field
        if [[ -n "$bridge_version" ]]; then
            bv_field=$(json_escape_string "$bridge_version")
        else
            bv_field="null"
        fi
        CHECK_VALUE_JSON=$(printf \
            '{"firmware_type":%s,"firmware_version":%s,"bridge_version":%s}' \
            "$(json_escape_string "$firmware_type")" \
            "$(json_escape_string "$firmware_version")" \
            "$bv_field")
    fi

    CHECK_VALUE="$firmware_version"

    _check_end
}

# ── Check runner ──────────────────────────────────────────────────────────────
# run_checks
# Accumulates results in _POSTURE_JSON_BODY (global string, no assoc arrays)
# Populates COLLECTION_WARNINGS array
# Updates _SUMMARY_* counters
#
# NOTE: Designed for bash 3.2+ compatibility (no declare -A, no declare -g).
#   Results are accumulated directly into _POSTURE_JSON_BODY string.

# Global accumulators (set here so they're in global scope before run_checks)
_POSTURE_JSON_BODY=""
COLLECTION_WARNINGS=()

run_checks() {
    _POSTURE_JSON_BODY=""
    COLLECTION_WARNINGS=()
    local cnt_pass=0 cnt_fail=0 cnt_warn=0 cnt_unknown=0

    # Determine which checks to run
    local checks_to_run
    checks_to_run=()
    if [[ "${CFG_ENABLED_CHECKS:-all}" == "all" ]]; then
        checks_to_run=("${ENABLED_CHECKS[@]}")
    else
        # CFG_ENABLED_CHECKS is a comma-separated list
        local old_IFS="$IFS"
        IFS=',' read -ra checks_to_run <<< "$CFG_ENABLED_CHECKS"
        IFS="$old_IFS"
    fi

    # Apply disabled_checks filter
    if [[ -n "${CFG_DISABLED_CHECKS:-}" ]]; then
        local filtered=()
        local c
        for c in "${checks_to_run[@]}"; do
            if ! echo ",$CFG_DISABLED_CHECKS," | grep -q ",${c},"; then
                filtered+=("$c")
            fi
        done
        checks_to_run=("${filtered[@]}")
    fi

    # Single check mode (for --check NAME CLI flag)
    if [[ -n "${SINGLE_CHECK:-}" ]]; then
        checks_to_run=("$SINGLE_CHECK")
    fi

    local check_name
    for check_name in "${checks_to_run[@]}"; do
        check_name="${check_name//[[:space:]]/}"  # strip whitespace
        [[ -z "$check_name" ]] && continue

        log_debug "Running check: ${check_name}"

        # Reset globals before each check
        CHECK_STATUS="unknown"
        CHECK_VALUE=""
        CHECK_VALUE_JSON=""
        CHECK_RAW=""
        CHECK_ERROR=""
        CHECK_PRIVILEGE="user"
        CHECK_DURATION_MS=0

        # Call the check function; catch unexpected non-zero exits
        if type "check_${check_name}" >/dev/null 2>&1; then
            "check_${check_name}" 2>/dev/null || {
                CHECK_STATUS="unknown"
                CHECK_ERROR="check function exited unexpectedly"
            }
        else
            CHECK_STATUS="unknown"
            CHECK_ERROR="unknown check name: ${check_name}"
        fi

        # Collect warnings
        if [[ "$CHECK_STATUS" == "unknown" ]] && [[ -n "$CHECK_ERROR" ]]; then
            COLLECTION_WARNINGS+=("${check_name}: ${CHECK_ERROR}")
        fi

        # Tally summary counters
        case "$CHECK_STATUS" in
            pass)    cnt_pass=$(( cnt_pass + 1 )) ;;
            fail)    cnt_fail=$(( cnt_fail + 1 )) ;;
            warn)    cnt_warn=$(( cnt_warn + 1 )) ;;
            *)       cnt_unknown=$(( cnt_unknown + 1 )) ;;
        esac

        # Accumulate posture JSON directly (avoid associative arrays for bash 3.2 compat)
        local obj
        obj=$(assemble_check_object "$check_name")
        if [[ -z "$_POSTURE_JSON_BODY" ]]; then
            _POSTURE_JSON_BODY="\"${check_name}\":${obj}"
        else
            _POSTURE_JSON_BODY="${_POSTURE_JSON_BODY},\"${check_name}\":${obj}"
        fi

        if [[ "${VERBOSE:-false}" == "true" ]]; then
            printf '[%s] status=%-7s value=%s\n' \
                "$check_name" "$CHECK_STATUS" "${CHECK_VALUE:-null}" >&2
        fi
    done

    compute_summary "$cnt_pass" "$cnt_fail" "$cnt_warn" "$cnt_unknown"
}

# ── Posture JSON builder ──────────────────────────────────────────────────────
# build_posture_json
# Returns the complete posture JSON object {"check1":...,"check2":...}
build_posture_json() {
    echo "{${_POSTURE_JSON_BODY}}"
}
