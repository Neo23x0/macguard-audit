#!/usr/bin/env bash
# lib/keychain.sh — macOS Keychain token storage/retrieval via `security` CLI
# Sourced by macguard-audit.sh; never executed directly.
# SPDX-License-Identifier: GPL-3.0-or-later

# ── keychain_store SERVICE ACCOUNT TOKEN [KEYCHAIN_PATH] ─────────────────────
# Stores TOKEN in the keychain under SERVICE/ACCOUNT.
# Uses the System keychain (/Library/Keychains/System.keychain) when running
# as root; user keychain otherwise.
# Passes -U to update if the entry already exists.
keychain_store() {
    local service="$1"
    local account="$2"
    local token="$3"
    local keychain="${4:-}"

    if [[ -z "$service" || -z "$account" || -z "$token" ]]; then
        log_error "keychain_store: service, account, and token are required"
        return 1
    fi

    local keychain_arg=()
    if [[ -n "$keychain" ]]; then
        keychain_arg=("-k" "$keychain")
    elif is_root; then
        keychain_arg=("-k" "/Library/Keychains/System.keychain")
    fi

    if /usr/bin/security add-generic-password \
            "${keychain_arg[@]}" \
            -s "$service" \
            -a "$account" \
            -w "$token" \
            -U \
            2>/dev/null; then
        log_info "keychain: stored token for service='$service' account='$account'"
        return 0
    else
        log_error "keychain: failed to store token for service='$service' account='$account'"
        return 1
    fi
}

# ── keychain_retrieve SERVICE ACCOUNT [KEYCHAIN_PATH] → stdout ───────────────
# Prints the password for SERVICE/ACCOUNT to stdout.
# Returns 1 (with empty output) if not found.
keychain_retrieve() {
    local service="$1"
    local account="$2"
    local keychain="${3:-}"

    if [[ -z "$service" || -z "$account" ]]; then
        log_error "keychain_retrieve: service and account are required"
        return 1
    fi

    local keychain_arg=()
    if [[ -n "$keychain" ]]; then
        keychain_arg=("-k" "$keychain")
    elif is_root; then
        keychain_arg=("-k" "/Library/Keychains/System.keychain")
    fi

    local token
    token=$(/usr/bin/security find-generic-password \
        "${keychain_arg[@]}" \
        -s "$service" \
        -a "$account" \
        -w \
        2>/dev/null) || {
        log_warn "keychain: token not found for service='$service' account='$account'"
        return 1
    }

    printf '%s' "$token"
    return 0
}

# ── get_token TRANSPORT_TYPE → sets RESOLVED_TOKEN ───────────────────────────
# Resolves the token for TRANSPORT_TYPE according to the configured token_source.
# Token source precedence (from config):
#   "keychain"    → keychain_retrieve using configured service + account
#   "config"      → read from CONFIG_TOKEN_VALUE (plain text in config file)
#   "env"         → read from the configured env var name
#
# Sets global RESOLVED_TOKEN.  Returns 1 if no token can be found.
get_token() {
    local transport_type="$1"
    RESOLVED_TOKEN=""

    local token_source
    case "$transport_type" in
        splunk_hec)
            token_source="${SPLUNK_TOKEN_SOURCE:-keychain}"
            case "$token_source" in
                keychain)
                    local svc="${SPLUNK_TOKEN_KEYCHAIN_SERVICE:-macguard-audit}"
                    local acct="${SPLUNK_TOKEN_KEYCHAIN_ACCOUNT:-splunk_hec_token}"
                    RESOLVED_TOKEN=$(keychain_retrieve "$svc" "$acct" 2>/dev/null) || true
                    ;;
                config)
                    RESOLVED_TOKEN="${SPLUNK_TOKEN_CONFIG_VALUE:-}"
                    ;;
                env)
                    local env_var="${SPLUNK_TOKEN_ENV_VAR:-MACGUARD_SPLUNK_TOKEN}"
                    RESOLVED_TOKEN="${!env_var:-}"
                    ;;
                *)
                    log_error "get_token: unknown token_source '$token_source' for splunk_hec"
                    return 1
                    ;;
            esac
            ;;
        https_post)
            token_source="${HTTPS_TOKEN_SOURCE:-keychain}"
            case "$token_source" in
                keychain)
                    local svc="${HTTPS_TOKEN_KEYCHAIN_SERVICE:-macguard-audit}"
                    local acct="${HTTPS_TOKEN_KEYCHAIN_ACCOUNT:-https_post_token}"
                    RESOLVED_TOKEN=$(keychain_retrieve "$svc" "$acct" 2>/dev/null) || true
                    ;;
                config)
                    RESOLVED_TOKEN="${HTTPS_TOKEN_CONFIG_VALUE:-}"
                    ;;
                env)
                    local env_var="${HTTPS_TOKEN_ENV_VAR:-MACGUARD_HTTPS_TOKEN}"
                    RESOLVED_TOKEN="${!env_var:-}"
                    ;;
                *)
                    log_error "get_token: unknown token_source '$token_source' for https_post"
                    return 1
                    ;;
            esac
            ;;
        *)
            log_error "get_token: unknown transport type '$transport_type'"
            return 1
            ;;
    esac

    if [[ -z "$RESOLVED_TOKEN" ]]; then
        log_error "get_token: no token resolved for transport_type='$transport_type' source='$token_source'"
        return 1
    fi

    log_debug "get_token: resolved token for '$transport_type' from '$token_source'"
    return 0
}

# ── check_config_token_file_permissions FILE ─────────────────────────────────
# Warns if a config file containing a token has permissions wider than 600.
check_config_token_file_permissions() {
    local config_file="$1"
    if [[ ! -f "$config_file" ]]; then return 0; fi

    local perms
    perms=$(stat -f "%Lp" "$config_file" 2>/dev/null || true)
    if [[ -n "$perms" ]] && [[ "$perms" -gt 600 ]]; then
        log_warn "security: config file '$config_file' has permissions $perms (should be 600); token may be readable by other users"
    fi
}
