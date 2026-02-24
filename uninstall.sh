#!/usr/bin/env bash
# uninstall.sh — Remove macguard-audit files and launchd services
#
# Must be run as root: sudo bash uninstall.sh
# To also remove logs and config, add --purge.
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

OPT_PURGE=false
OPT_USER_AGENT=false

for arg in "$@"; do
    case "$arg" in
        --purge)        OPT_PURGE=true ;;
        --user-agent)   OPT_USER_AGENT=true ;;
        --help|-h)
            cat <<'EOF'
Usage: sudo bash uninstall.sh [OPTIONS]

Options:
  --purge       Also remove config files and logs
  --user-agent  Uninstall LaunchAgent variant (user context)
  --help        Show this help
EOF
            exit 0
            ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

if [[ "$OPT_USER_AGENT" == "false" && "$(id -u)" -ne 0 ]]; then
    printf 'ERROR: Run as root: sudo bash uninstall.sh\n' >&2
    exit 1
fi

printf '[uninstall] macguard-audit uninstaller\n'

# ── Unload and remove launchd services ───────────────────────────────────────
DAEMON_PLIST="/Library/LaunchDaemons/com.example.macguard-audit.plist"
AGENT_PLIST_SYSTEM="/Library/LaunchAgents/com.example.macguard-audit-user.plist"
AGENT_PLIST_USER="${HOME}/Library/LaunchAgents/com.example.macguard-audit-user.plist"

if [[ "$OPT_USER_AGENT" == "true" ]]; then
    if [[ -f "$AGENT_PLIST_USER" ]]; then
        printf '[uninstall] Unloading LaunchAgent\n'
        launchctl unload -w "$AGENT_PLIST_USER" 2>/dev/null || true
        rm -f "$AGENT_PLIST_USER"
    fi
else
    if [[ -f "$DAEMON_PLIST" ]]; then
        printf '[uninstall] Unloading LaunchDaemon\n'
        launchctl unload -w "$DAEMON_PLIST" 2>/dev/null || true
        rm -f "$DAEMON_PLIST"
    fi
    if [[ -f "$AGENT_PLIST_SYSTEM" ]]; then
        printf '[uninstall] Removing system LaunchAgent\n'
        launchctl unload -w "$AGENT_PLIST_SYSTEM" 2>/dev/null || true
        rm -f "$AGENT_PLIST_SYSTEM"
    fi
fi

# ── Remove binary and libraries ───────────────────────────────────────────────
printf '[uninstall] Removing binary and libraries\n'
rm -f "/usr/local/bin/macguard-audit.sh"
rm -rf "/usr/local/lib/macguard-audit"

# ── Remove config and logs (only with --purge) ────────────────────────────────
if [[ "$OPT_PURGE" == "true" ]]; then
    printf '[uninstall] --purge: removing config and logs\n'
    rm -rf "/etc/macguard-audit"
    rm -rf "/var/log/macguard-audit"
    rm -rf "/Library/Application Support/macguard-audit"
    printf '[uninstall] NOTE: Keychain tokens not removed. Use:\n'
    printf '  security delete-generic-password -s macguard-audit -a splunk_hec_token\n'
    printf '  security delete-generic-password -s macguard-audit -a https_post_token\n'
else
    printf '[uninstall] Config and logs preserved (use --purge to remove)\n'
fi

printf '[uninstall] Done.\n'
