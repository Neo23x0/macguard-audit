#!/usr/bin/env bash
# install.sh — Deploy macguard-audit to /usr/local/bin and configure LaunchDaemon
#
# Must be run as root: sudo bash install.sh [--user-agent]
#
# Options:
#   --user-agent    Install LaunchAgent (user context) instead of LaunchDaemon (root)
#   --no-service    Copy files only; do not install launchd service
#   --help          Show this help
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

INSTALL_BINARY_DIR="/usr/local/bin"
INSTALL_LIB_DIR="/usr/local/lib/macguard-audit"
INSTALL_CONFIG_DIR="/etc/macguard-audit"
INSTALL_LOG_DIR="/var/log/macguard-audit"
INSTALL_APP_SUPPORT_DIR="/Library/Application Support/macguard-audit"

DAEMON_PLIST_SRC="launchd/com.example.macguard-audit.plist"
DAEMON_PLIST_DEST="/Library/LaunchDaemons/com.example.macguard-audit.plist"
AGENT_PLIST_SRC="launchd/com.example.macguard-audit-user.plist"
AGENT_PLIST_DEST="/Library/LaunchAgents/com.example.macguard-audit-user.plist"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

OPT_USER_AGENT=false
OPT_NO_SERVICE=false

for arg in "$@"; do
    case "$arg" in
        --user-agent)   OPT_USER_AGENT=true ;;
        --no-service)   OPT_NO_SERVICE=true ;;
        --help|-h)
            cat <<'EOF'
Usage: sudo bash install.sh [OPTIONS]

Options:
  --user-agent    Install LaunchAgent (runs as current user)
  --no-service    Copy files only; skip launchd service installation
  --help          Show this help
EOF
            exit 0
            ;;
        *) printf 'Unknown option: %s\n' "$arg" >&2; exit 2 ;;
    esac
done

# Root check (not needed for --user-agent, but required for daemon install + file copy)
if [[ "$OPT_USER_AGENT" == "false" && "$(id -u)" -ne 0 ]]; then
    printf 'ERROR: Run as root: sudo bash install.sh\n' >&2
    exit 1
fi

printf '[install] macguard-audit installer\n'

# ── 1. Copy main script ───────────────────────────────────────────────────────
printf '[install] Copying macguard-audit.sh -> %s/macguard-audit.sh\n' "$INSTALL_BINARY_DIR"
install -m 755 -o root -g wheel \
    "${SCRIPT_DIR}/macguard-audit.sh" \
    "${INSTALL_BINARY_DIR}/macguard-audit.sh"

# ── 2. Copy libraries ─────────────────────────────────────────────────────────
printf '[install] Copying lib/ -> %s/\n' "$INSTALL_LIB_DIR"
mkdir -p "$INSTALL_LIB_DIR"
for f in "${SCRIPT_DIR}/lib/"*.sh; do
    install -m 644 -o root -g wheel "$f" "${INSTALL_LIB_DIR}/$(basename "$f")"
done

# ── 3. Create config directory and copy example ───────────────────────────────
if [[ "$OPT_USER_AGENT" == "false" ]]; then
    printf '[install] Creating %s/\n' "$INSTALL_CONFIG_DIR"
    mkdir -p "$INSTALL_CONFIG_DIR"
    chmod 750 "$INSTALL_CONFIG_DIR"
    chown root:wheel "$INSTALL_CONFIG_DIR"

    local_cfg="${INSTALL_CONFIG_DIR}/macguard-audit.json"
    if [[ ! -f "$local_cfg" ]]; then
        printf '[install] Copying example config -> %s\n' "$local_cfg"
        install -m 600 -o root -g wheel \
            "${SCRIPT_DIR}/config/macguard-audit.json.example" \
            "$local_cfg"
        printf '[install] IMPORTANT: Edit %s to configure transport, org_id, etc.\n' "$local_cfg"
    else
        printf '[install] Config already exists at %s (not overwritten)\n' "$local_cfg"
    fi
fi

# ── 4. Create log directory ───────────────────────────────────────────────────
printf '[install] Creating %s/\n' "$INSTALL_LOG_DIR"
mkdir -p "$INSTALL_LOG_DIR"
if [[ "$OPT_USER_AGENT" == "false" ]]; then
    chmod 750 "$INSTALL_LOG_DIR"
    chown root:wheel "$INSTALL_LOG_DIR"
fi

# ── 5. Install launchd service ────────────────────────────────────────────────
if [[ "$OPT_NO_SERVICE" == "false" ]]; then
    if [[ "$OPT_USER_AGENT" == "true" ]]; then
        # LaunchAgent
        agent_dir="${HOME}/Library/LaunchAgents"
        mkdir -p "$agent_dir"
        dest_plist="${agent_dir}/com.example.macguard-audit-user.plist"

        # Create AppSupport config dir
        mkdir -p "$INSTALL_APP_SUPPORT_DIR"
        if [[ ! -f "${INSTALL_APP_SUPPORT_DIR}/macguard-audit.json" ]]; then
            cp "${SCRIPT_DIR}/config/macguard-audit.json.example" \
               "${INSTALL_APP_SUPPORT_DIR}/macguard-audit.json"
            chmod 600 "${INSTALL_APP_SUPPORT_DIR}/macguard-audit.json"
        fi

        printf '[install] Installing LaunchAgent -> %s\n' "$dest_plist"
        cp "${SCRIPT_DIR}/${AGENT_PLIST_SRC}" "$dest_plist"
        chmod 644 "$dest_plist"
        launchctl unload "$dest_plist" 2>/dev/null || true
        launchctl load -w "$dest_plist"
        printf '[install] LaunchAgent loaded: com.example.macguard-audit-user\n'
    else
        # LaunchDaemon
        printf '[install] Installing LaunchDaemon -> %s\n' "$DAEMON_PLIST_DEST"
        install -m 644 -o root -g wheel \
            "${SCRIPT_DIR}/${DAEMON_PLIST_SRC}" \
            "$DAEMON_PLIST_DEST"

        launchctl unload "$DAEMON_PLIST_DEST" 2>/dev/null || true
        launchctl load -w "$DAEMON_PLIST_DEST"
        printf '[install] LaunchDaemon loaded: com.example.macguard-audit\n'
    fi
fi

# ── 6. Token setup reminder ───────────────────────────────────────────────────
printf '\n'
printf '══════════════════════════════════════════════════════════\n'
printf '  Installation complete!\n'
printf '\n'
printf '  Next steps:\n'
printf '  1. Edit the config file and set your transport URL.\n'
if [[ "$OPT_USER_AGENT" == "false" ]]; then
    printf '     Config: %s\n' "$INSTALL_CONFIG_DIR/macguard-audit.json"
else
    printf '     Config: %s\n' "$INSTALL_APP_SUPPORT_DIR/macguard-audit.json"
fi
printf '\n'
printf '  2. Store your Splunk HEC token in the Keychain:\n'
printf '     sudo security add-generic-password \\\n'
printf '       -k /Library/Keychains/System.keychain \\\n'
printf '       -s macguard-audit -a splunk_hec_token \\\n'
printf '       -w "YOUR_HEC_TOKEN" -U\n'
printf '\n'
printf '  3. Test manually:\n'
printf '     macguard-audit.sh --checks-only --pretty\n'
printf '══════════════════════════════════════════════════════════\n'
