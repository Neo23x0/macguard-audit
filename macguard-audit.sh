#!/usr/bin/env bash
# macguard-audit.sh — macOS Security Posture Reporter
#
# Collects ~29 local security configuration signals, outputs structured JSON,
# and optionally ships to Splunk HEC or a generic HTTPS ingest endpoint.
# No MDM required. Runs on macOS 12–15 (Monterey–Sequoia).
#
# Usage: macguard-audit.sh [OPTIONS]
#   -c, --config FILE     Config file path
#   -o, --output FILE     Write output to FILE ("-" for stdout, default: stdout)
#   -n, --dry-run         Collect and write; do not ship
#       --checks-only     Run checks and print to stdout; no config/transport
#       --ship-only FILE  Read FILE and ship; no recollection
#       --check NAME      Run only the named check (debug)
#       --list-checks     List all check names and exit
#   -v, --verbose         Print each check result to stderr as it completes
#   -p, --pretty          Pretty-print JSON (requires python3)
#       --version         Print version and exit
#       --help            Show this message
#
# SPDX-License-Identifier: GPL-3.0-or-later

set -euo pipefail

# ── Version ───────────────────────────────────────────────────────────────────
TOOL_VERSION="1.0.0"
TOOL_NAME="macguard-audit"
SCHEMA_VERSION="1.0"

# ── Resolve script directory ──────────────────────────────────────────────────
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# ── Source libraries ──────────────────────────────────────────────────────────
_source_lib() {
    local lib="$1"
    local path="${SCRIPT_DIR}/lib/${lib}"
    if [[ ! -f "$path" ]]; then
        printf 'ERROR: required library not found: %s\n' "$path" >&2
        exit 1
    fi
    # shellcheck source=/dev/null
    source "$path"
}

_source_lib utils.sh
_source_lib json.sh
_source_lib checks.sh
_source_lib transport.sh
_source_lib keychain.sh

# ── Default config values ─────────────────────────────────────────────────────
CFG_ENABLED_CHECKS="all"
CFG_DISABLED_CHECKS=""
TIMEOUT_PER_CHECK=15
TIMEOUT_TOTAL=120
CFG_RUN_ROOT_CHECKS=false

OUTPUT_FILE="-"
CFG_ROTATE_MAX_LINES=1000
CFG_ATOMIC_WRITE=true

CFG_SCREEN_LOCK_MAX_SECS=600
CFG_AIRDROP_POLICY="contacts_or_off"
CFG_IS_ADMIN_IS_FAIL=false

TRANSPORT_ENABLED=false
TRANSPORT_TYPE=splunk_hec

SPLUNK_HEC_URL=""
SPLUNK_HEC_INDEX=""
SPLUNK_HEC_SOURCETYPE="macguard:posture"
SPLUNK_HEC_TLS_VERIFY=true
SPLUNK_HEC_CONNECT_TIMEOUT=10
SPLUNK_HEC_MAX_RETRIES=3
SPLUNK_HEC_RETRY_DELAY=5
SPLUNK_TOKEN_SOURCE="keychain"
SPLUNK_TOKEN_KEYCHAIN_SERVICE="macguard-audit"
SPLUNK_TOKEN_KEYCHAIN_ACCOUNT="splunk_hec_token"
SPLUNK_TOKEN_CONFIG_VALUE=""
SPLUNK_TOKEN_ENV_VAR="MACGUARD_SPLUNK_TOKEN"

HTTPS_POST_URL=""
HTTPS_POST_AUTH_HEADER="Authorization"
HTTPS_POST_TLS_VERIFY=true
HTTPS_POST_CONNECT_TIMEOUT=10
HTTPS_POST_MAX_RETRIES=3
HTTPS_TOKEN_SOURCE="keychain"
HTTPS_TOKEN_KEYCHAIN_SERVICE="macguard-audit"
HTTPS_TOKEN_KEYCHAIN_ACCOUNT="https_post_token"
HTTPS_TOKEN_CONFIG_VALUE=""
HTTPS_TOKEN_ENV_VAR="MACGUARD_HTTPS_TOKEN"

CFG_HASH_SERIAL=true
CFG_HASH_SALT=""
CFG_ORG_ID=""
CFG_ENVIRONMENT=""
CFG_TAGS=""

_LOG_LEVEL=2   # info
VERBOSE=false

# ── Argument defaults ─────────────────────────────────────────────────────────
ARG_CONFIG=""
ARG_OUTPUT=""
ARG_DRY_RUN=false
ARG_CHECKS_ONLY=false
ARG_SHIP_ONLY=""
ARG_CHECK_NAME=""
ARG_LIST_CHECKS=false
ARG_PRETTY=false

# ── Usage ─────────────────────────────────────────────────────────────────────
usage() {
    cat <<'EOF'
macguard-audit — macOS Security Posture Reporter

Usage: macguard-audit.sh [OPTIONS]

Options:
  -c, --config FILE     Config JSON file
                        (default: /etc/macguard-audit/macguard-audit.json,
                         then ~/.config/macguard-audit/macguard-audit.json)
  -o, --output FILE     Write JSON to FILE ("-" = stdout; default: stdout)
  -n, --dry-run         Collect and write; do not ship to remote endpoint
      --checks-only     Run all checks and print JSON to stdout; skip config/transport
      --ship-only FILE  Read last report from FILE and ship; skip recollection
      --check NAME      Run only the named check and print result to stdout
      --list-checks     Print all available check names and exit
  -v, --verbose         Print each check result to stderr as it completes
  -p, --pretty          Pretty-print JSON output (requires python3)
      --version         Print version string and exit
      --help            Show this help message and exit

Examples:
  # Quick scan to stdout
  macguard-audit.sh --checks-only

  # Write to file, ship to Splunk HEC
  macguard-audit.sh --config /etc/macguard-audit/macguard-audit.json

  # Debug a single check
  macguard-audit.sh --check filevault --verbose

  # Store Splunk HEC token in Keychain
  security add-generic-password -s macguard-audit -a splunk_hec_token \
    -w "YOUR_TOKEN" -U
EOF
}

# ── Argument parsing ──────────────────────────────────────────────────────────
parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -c|--config)
                ARG_CONFIG="${2:-}"
                [[ -z "$ARG_CONFIG" ]] && { printf 'ERROR: --config requires a FILE argument\n' >&2; exit 2; }
                shift 2
                ;;
            -o|--output)
                ARG_OUTPUT="${2:-}"
                [[ -z "$ARG_OUTPUT" ]] && { printf 'ERROR: --output requires a FILE argument\n' >&2; exit 2; }
                shift 2
                ;;
            -n|--dry-run)
                ARG_DRY_RUN=true; shift ;;
            --checks-only)
                ARG_CHECKS_ONLY=true; shift ;;
            --ship-only)
                ARG_SHIP_ONLY="${2:-}"
                [[ -z "$ARG_SHIP_ONLY" ]] && { printf 'ERROR: --ship-only requires a FILE argument\n' >&2; exit 2; }
                shift 2
                ;;
            --check)
                ARG_CHECK_NAME="${2:-}"
                [[ -z "$ARG_CHECK_NAME" ]] && { printf 'ERROR: --check requires a NAME argument\n' >&2; exit 2; }
                shift 2
                ;;
            --list-checks)
                ARG_LIST_CHECKS=true; shift ;;
            -v|--verbose)
                VERBOSE=true; _LOG_LEVEL=1; shift ;;
            -p|--pretty)
                ARG_PRETTY=true; shift ;;
            --version)
                printf '%s %s\n' "$TOOL_NAME" "$TOOL_VERSION"; exit 0 ;;
            --help|-h)
                usage; exit 0 ;;
            *)
                printf 'ERROR: unknown option: %s\n' "$1" >&2
                usage >&2; exit 2
                ;;
        esac
    done
}

# ── Config loading (Python3 JSON parse) ──────────────────────────────────────
load_config() {
    local config_file="$1"

    if [[ ! -f "$config_file" ]]; then
        log_debug "config: no config file at '$config_file'; using defaults"
        return 0
    fi

    log_info "config: loading $config_file"
    check_config_token_file_permissions "$config_file"

    if [[ "$PYTHON3_AVAILABLE" != "true" ]]; then
        log_warn "config: python3 unavailable; cannot parse JSON config; using defaults"
        return 0
    fi

    # Parse all known config keys with Python3; emit as KEY=VALUE lines
    local cfg_vars
    cfg_vars=$(/usr/bin/python3 - "$config_file" <<'PYEOF'
import json, sys, os

try:
    with open(sys.argv[1]) as f:
        c = json.load(f)
except Exception as e:
    print(f"ERROR: {e}", file=sys.stderr)
    sys.exit(1)

def p(key, val):
    """Emit KEY=VALUE, escaping for bash eval."""
    val = str(val) if not isinstance(val, bool) else ("true" if val else "false")
    # Single-quote the value; escape embedded single-quotes
    val = val.replace("'", "'\\''")
    print(f"{key}='{val}'")

coll = c.get("collection", {})
p("CFG_ENABLED_CHECKS",    ",".join(coll["enabled_checks"]) if isinstance(coll.get("enabled_checks"), list) else coll.get("enabled_checks","all"))
p("CFG_DISABLED_CHECKS",   ",".join(coll.get("disabled_checks",[])))
p("TIMEOUT_PER_CHECK",     coll.get("timeout_per_check_secs", 15))
p("TIMEOUT_TOTAL",         coll.get("timeout_total_secs", 120))
p("CFG_RUN_ROOT_CHECKS",   coll.get("run_root_checks", False))

out = c.get("output", {})
p("OUTPUT_FILE",           out.get("file", "-"))
p("CFG_ROTATE_MAX_LINES",  out.get("rotate_max_lines", 1000))
p("CFG_ATOMIC_WRITE",      out.get("atomic_write", True))

thr = c.get("thresholds", {})
p("CFG_SCREEN_LOCK_MAX_SECS", thr.get("screen_lock_timeout_max_secs", 600))
p("CFG_AIRDROP_POLICY",       thr.get("airdrop_policy", "contacts_or_off"))
p("CFG_IS_ADMIN_IS_FAIL",     thr.get("is_admin_is_fail", False))

tr = c.get("transport", {})
p("TRANSPORT_ENABLED",     tr.get("enabled", False))
p("TRANSPORT_TYPE",        tr.get("type", "splunk_hec"))

shec = tr.get("splunk_hec", {})
p("SPLUNK_HEC_URL",                  shec.get("url",""))
p("SPLUNK_HEC_INDEX",                shec.get("index",""))
p("SPLUNK_HEC_SOURCETYPE",           shec.get("sourcetype","macguard:posture"))
p("SPLUNK_HEC_TLS_VERIFY",           shec.get("tls_verify", True))
p("SPLUNK_HEC_CONNECT_TIMEOUT",      shec.get("connect_timeout_secs", 10))
p("SPLUNK_HEC_MAX_RETRIES",          shec.get("max_retries", 3))
p("SPLUNK_HEC_RETRY_DELAY",          shec.get("retry_delay_secs", 5))
p("SPLUNK_TOKEN_SOURCE",             shec.get("token_source","keychain"))
p("SPLUNK_TOKEN_KEYCHAIN_SERVICE",   shec.get("token_keychain_service","macguard-audit"))
p("SPLUNK_TOKEN_KEYCHAIN_ACCOUNT",   shec.get("token_keychain_account","splunk_hec_token"))
p("SPLUNK_TOKEN_CONFIG_VALUE",       shec.get("token_config_value",""))
p("SPLUNK_TOKEN_ENV_VAR",            shec.get("token_env_var","MACGUARD_SPLUNK_TOKEN"))

hp = tr.get("https_post", {})
p("HTTPS_POST_URL",                  hp.get("url",""))
p("HTTPS_POST_AUTH_HEADER",          hp.get("auth_header","Authorization"))
p("HTTPS_POST_TLS_VERIFY",           hp.get("tls_verify", True))
p("HTTPS_POST_CONNECT_TIMEOUT",      hp.get("connect_timeout_secs", 10))
p("HTTPS_POST_MAX_RETRIES",          hp.get("max_retries", 3))
p("HTTPS_TOKEN_SOURCE",              hp.get("token_source","keychain"))
p("HTTPS_TOKEN_KEYCHAIN_SERVICE",    hp.get("token_keychain_service","macguard-audit"))
p("HTTPS_TOKEN_KEYCHAIN_ACCOUNT",    hp.get("token_keychain_account","https_post_token"))
p("HTTPS_TOKEN_CONFIG_VALUE",        hp.get("token_config_value",""))
p("HTTPS_TOKEN_ENV_VAR",             hp.get("token_env_var","MACGUARD_HTTPS_TOKEN"))

priv = c.get("privacy", {})
p("CFG_HASH_SERIAL",   priv.get("hash_serial", True))
p("CFG_HASH_SALT",     priv.get("hash_salt", ""))

p("CFG_ORG_ID",        c.get("org_id",""))
p("CFG_ENVIRONMENT",   c.get("environment",""))
p("CFG_TAGS",          ",".join(c.get("tags",[])))

log_cfg = c.get("logging", {})
level_map = {"debug":1,"info":2,"warn":3,"error":4}
p("_LOG_LEVEL", level_map.get(log_cfg.get("level","info"), 2))
PYEOF
) || {
        log_error "config: failed to parse '$config_file'"
        return 1
    }

    # Evaluate the parsed variables into current shell
    eval "$cfg_vars"
    log_debug "config: loaded successfully"
}

# ── Find config file ──────────────────────────────────────────────────────────
find_config() {
    # Explicit -c/--config wins
    if [[ -n "$ARG_CONFIG" ]]; then
        echo "$ARG_CONFIG"
        return 0
    fi
    # System-wide
    if [[ -f "/etc/macguard-audit/macguard-audit.json" ]]; then
        echo "/etc/macguard-audit/macguard-audit.json"
        return 0
    fi
    # User
    local user_cfg="${HOME}/.config/macguard-audit/macguard-audit.json"
    if [[ -f "$user_cfg" ]]; then
        echo "$user_cfg"
        return 0
    fi
    echo ""
}

# ── Atomic write ──────────────────────────────────────────────────────────────
write_report() {
    local content="$1"
    local dest="$2"

    if [[ "$dest" == "-" ]]; then
        printf '%s\n' "$content"
        return 0
    fi

    local dir
    dir=$(dirname "$dest")
    if [[ ! -d "$dir" ]]; then
        mkdir -p "$dir" || {
            log_error "output: cannot create directory '$dir'"
            return 1
        }
    fi

    if [[ "$CFG_ATOMIC_WRITE" == "true" ]]; then
        local tmp="${dir}/.macguard_tmp_$(date +%s)_$$"
        printf '%s\n' "$content" > "$tmp" && mv "$tmp" "$dest" || {
            rm -f "$tmp" 2>/dev/null || true
            log_error "output: atomic write failed to '$dest'"
            return 1
        }
    else
        printf '%s\n' "$content" > "$dest" || {
            log_error "output: write failed to '$dest'"
            return 1
        }
    fi

    log_info "output: wrote report to '$dest'"
}

# ── Rotate JSONL output file ──────────────────────────────────────────────────
rotate_if_needed() {
    local file="$1"
    [[ "$file" == "-" ]] && return 0
    [[ ! -f "$file" ]] && return 0

    local line_count
    line_count=$(wc -l < "$file" 2>/dev/null || echo "0")
    line_count="${line_count// /}"

    if [[ "$line_count" -ge "$CFG_ROTATE_MAX_LINES" ]]; then
        log_info "output: rotating '$file' (${line_count} lines >= ${CFG_ROTATE_MAX_LINES})"
        local half=$(( CFG_ROTATE_MAX_LINES / 2 ))
        local tmp="${file}.rotate_$$"
        tail -n "$half" "$file" > "$tmp" && mv "$tmp" "$file" || rm -f "$tmp"
    fi
}

# ── Pretty-print JSON ─────────────────────────────────────────────────────────
pretty_print() {
    local json="$1"
    if [[ "$PYTHON3_AVAILABLE" == "true" ]]; then
        printf '%s' "$json" | /usr/bin/python3 -c \
            "import json,sys; print(json.dumps(json.loads(sys.stdin.read()), indent=2))" \
            2>/dev/null || printf '%s\n' "$json"
    else
        printf '%s\n' "$json"
    fi
}

# ── --list-checks ─────────────────────────────────────────────────────────────
do_list_checks() {
    printf 'Available checks:\n'
    local i=1
    for chk in "${ENABLED_CHECKS[@]}"; do
        printf '  %02d. %s\n' "$i" "$chk"
        i=$(( i + 1 ))
    done
}

# ── --check NAME ──────────────────────────────────────────────────────────────
do_single_check() {
    local check_name="$1"
    local fn="check_${check_name}"

    if ! type "$fn" >/dev/null 2>&1; then
        printf 'ERROR: unknown check: %s\n' "$check_name" >&2
        do_list_checks >&2
        exit 2
    fi

    detect_environment
    "$fn"

    local obj
    obj=$(assemble_check_object "$check_name")
    if [[ "$ARG_PRETTY" == "true" ]]; then
        pretty_print "$obj"
    else
        printf '%s\n' "$obj"
    fi
}

# ── Assemble host/os/user metadata ───────────────────────────────────────────
assemble_metadata() {
    local serial_hash="null"
    if [[ "$CFG_HASH_SERIAL" == "true" ]] && [[ -n "$CFG_HASH_SALT" ]]; then
        local raw_serial
        raw_serial=$(system_profiler SPHardwareDataType 2>/dev/null \
            | awk -F': ' '/Serial Number/{print $2}' | tr -d '[:space:]' || true)
        if [[ -n "$raw_serial" ]]; then
            serial_hash=$(json_escape_string "$(sha256_hex "${raw_serial}${CFG_HASH_SALT}")")
        fi
    fi

    local mdm_enrolled="false"
    local mdm_url="null"
    if [[ -n "${PLATFORM_MDM_ENROLLED:-}" ]]; then
        mdm_enrolled=$(json_bool "$PLATFORM_MDM_ENROLLED")
    fi
    if [[ -n "${PLATFORM_MDM_URL:-}" ]]; then
        mdm_url=$(json_escape_string "$PLATFORM_MDM_URL")
    fi

    local tags_json="[]"
    if [[ -n "$CFG_TAGS" ]]; then
        tags_json=$(/usr/bin/python3 -c \
            "import json,sys; tags=[t.strip() for t in sys.argv[1].split(',') if t.strip()]; print(json.dumps(tags))" \
            "$CFG_TAGS" 2>/dev/null || echo "[]")
    fi

    # host block
    local host_json
    host_json=$(printf '{"hostname":%s,"hardware_uuid":%s,"serial_hash":%s,"model":%s,"arch":%s,"org_id":%s,"environment":%s,"tags":%s,"mdm_enrolled":%s,"mdm_server_url":%s}' \
        "$(json_escape_string "${PLATFORM_HOSTNAME:-}")" \
        "$(json_escape_string "${PLATFORM_HW_UUID:-}")" \
        "$serial_hash" \
        "$(json_escape_string "${PLATFORM_MODEL:-}")" \
        "$(json_escape_string "${PLATFORM_ARCH:-}")" \
        "$(json_null_or_string "$CFG_ORG_ID")" \
        "$(json_null_or_string "$CFG_ENVIRONMENT")" \
        "$tags_json" \
        "$mdm_enrolled" \
        "$mdm_url")

    # os block
    local os_json
    os_json=$(printf '{"name":"macOS","version":%s,"build":%s,"major":%s,"minor":%s,"kernel_version":%s,"uptime_seconds":%s}' \
        "$(json_escape_string "${PLATFORM_OS_VERSION:-}")" \
        "$(json_escape_string "${PLATFORM_OS_BUILD:-}")" \
        "${PLATFORM_OS_MAJOR:-0}" \
        "${PLATFORM_OS_MINOR:-0}" \
        "$(json_escape_string "${PLATFORM_KERNEL_VERSION:-}")" \
        "${PLATFORM_UPTIME_SECS:-0}")

    # user block
    local user_json
    user_json=$(printf '{"current_user":%s,"console_user":%s,"uid":%s}' \
        "$(json_escape_string "${PLATFORM_CURRENT_USER:-}")" \
        "$(json_escape_string "${PLATFORM_CONSOLE_USER:-}")" \
        "${PLATFORM_UID:-0}")

    printf '%s\t%s\t%s' "$host_json" "$os_json" "$user_json"
}

# ── Main ──────────────────────────────────────────────────────────────────────
main() {
    parse_args "$@"

    # -- --list-checks
    if [[ "$ARG_LIST_CHECKS" == "true" ]]; then
        do_list_checks
        exit 0
    fi

    # -- --check NAME (debug single check)
    if [[ -n "$ARG_CHECK_NAME" ]]; then
        detect_environment
        do_single_check "$ARG_CHECK_NAME"
        exit 0
    fi

    # Load config (unless --checks-only)
    if [[ "$ARG_CHECKS_ONLY" != "true" ]]; then
        local config_file
        config_file=$(find_config)
        if [[ -n "$config_file" ]]; then
            load_config "$config_file"
        fi
    fi

    # CLI overrides for output file
    if [[ -n "$ARG_OUTPUT" ]]; then
        OUTPUT_FILE="$ARG_OUTPUT"
    fi

    # -- --ship-only FILE
    if [[ -n "$ARG_SHIP_ONLY" ]]; then
        if [[ ! -f "$ARG_SHIP_ONLY" ]]; then
            log_error "--ship-only: file not found: $ARG_SHIP_ONLY"
            exit 1
        fi
        local existing_report
        existing_report=$(cat "$ARG_SHIP_ONLY")

        if [[ "$TRANSPORT_ENABLED" != "true" ]]; then
            log_warn "--ship-only: transport is disabled; nothing to ship"
            exit 0
        fi

        if get_token "$TRANSPORT_TYPE" 2>/dev/null; then
            case "$TRANSPORT_TYPE" in
                splunk_hec) SPLUNK_HEC_TOKEN="$RESOLVED_TOKEN" ;;
                https_post) HTTPS_POST_TOKEN="$RESOLVED_TOKEN" ;;
            esac
        fi

        ship "$existing_report"
        exit $?
    fi

    # ── Normal collection flow ────────────────────────────────────────────────

    detect_environment

    local t_start
    t_start=$(epoch_ms)

    # Run all checks (or just --checks-only subset)
    run_checks

    local t_end
    t_end=$(epoch_ms)
    local collection_duration_ms=$(( t_end - t_start ))

    # Assemble metadata
    local meta
    meta=$(assemble_metadata)
    local host_json os_json user_json
    host_json=$(printf '%s' "$meta" | cut -f1)
    os_json=$(printf '%s' "$meta" | cut -f2)
    user_json=$(printf '%s' "$meta" | cut -f3)

    # Build posture section
    local posture_json
    posture_json=$(build_posture_json)

    # Summary globals already set by run_checks → compute_summary
    local summary_json
    summary_json=$(get_summary_json)

    # Build warnings array
    local warnings_json
    warnings_json=$(build_warnings_json)

    # Assemble full report
    local run_as_root_bool
    run_as_root_bool=$(json_bool "$RUN_AS_ROOT")

    local report_json
    report_json=$(printf '{"schema_version":%s,"tool":%s,"tool_version":%s,"collected_at":%s,"collection_duration_ms":%s,"run_as_root":%s,"collection_warnings":%s,"host":%s,"os":%s,"user":%s,"posture":%s,"summary":%s}' \
        "$(json_escape_string "$SCHEMA_VERSION")" \
        "$(json_escape_string "$TOOL_NAME")" \
        "$(json_escape_string "$TOOL_VERSION")" \
        "$(json_escape_string "$(now_rfc3339)")" \
        "$collection_duration_ms" \
        "$run_as_root_bool" \
        "$warnings_json" \
        "$host_json" \
        "$os_json" \
        "$user_json" \
        "$posture_json" \
        "$summary_json")

    # Pretty-print if requested
    if [[ "$ARG_PRETTY" == "true" ]]; then
        report_json=$(pretty_print "$report_json")
    fi

    # Verbose: dump summary to stderr
    if [[ "$VERBOSE" == "true" ]]; then
        printf '[macguard-audit] collection complete in %dms\n' \
            "$collection_duration_ms" >&2
        printf '[macguard-audit] summary: %s\n' "$summary_json" >&2
    fi

    # Write output
    rotate_if_needed "$OUTPUT_FILE"
    write_report "$report_json" "$OUTPUT_FILE"

    # Ship (unless dry-run or checks-only)
    if [[ "$ARG_DRY_RUN" == "true" ]] || [[ "$ARG_CHECKS_ONLY" == "true" ]]; then
        log_debug "transport: skipping (dry-run/checks-only)"
        return 0
    fi

    if [[ "$TRANSPORT_ENABLED" == "true" ]]; then
        if get_token "$TRANSPORT_TYPE" 2>/dev/null; then
            case "$TRANSPORT_TYPE" in
                splunk_hec) SPLUNK_HEC_TOKEN="$RESOLVED_TOKEN" ;;
                https_post) HTTPS_POST_TOKEN="$RESOLVED_TOKEN" ;;
            esac
        else
            log_warn "transport: could not resolve token; skipping shipment"
            return 0
        fi
        ship "$report_json" || log_warn "transport: shipment failed (non-fatal)"
    fi
}

main "$@"
