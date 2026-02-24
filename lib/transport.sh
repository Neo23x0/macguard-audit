#!/usr/bin/env bash
# lib/transport.sh — Splunk HEC and generic HTTPS POST transport
# Sourced by macguard-audit.sh; never executed directly.
# SPDX-License-Identifier: GPL-3.0-or-later

# ── Defaults (can be overridden by config) ────────────────────────────────────
: "${TRANSPORT_ENABLED:=false}"
: "${TRANSPORT_TYPE:=splunk_hec}"        # splunk_hec | https_post

# Splunk HEC
: "${SPLUNK_HEC_URL:=}"
: "${SPLUNK_HEC_TOKEN:=}"
: "${SPLUNK_HEC_INDEX:=}"
: "${SPLUNK_HEC_SOURCETYPE:=macguard:posture}"
: "${SPLUNK_HEC_TLS_VERIFY:=true}"
: "${SPLUNK_HEC_CONNECT_TIMEOUT:=10}"
: "${SPLUNK_HEC_MAX_RETRIES:=3}"
: "${SPLUNK_HEC_RETRY_DELAY:=5}"

# Generic HTTPS POST
: "${HTTPS_POST_URL:=}"
: "${HTTPS_POST_TOKEN:=}"
: "${HTTPS_POST_AUTH_HEADER:=Authorization}"
: "${HTTPS_POST_TLS_VERIFY:=true}"
: "${HTTPS_POST_CONNECT_TIMEOUT:=10}"
: "${HTTPS_POST_MAX_RETRIES:=3}"

# ── Internal: shared curl invocation ─────────────────────────────────────────
# _curl_post URL AUTH_HEADER AUTH_VALUE BODY TLS_VERIFY TIMEOUT
# Sets TRANSPORT_HTTP_CODE and TRANSPORT_RESPONSE; returns 0 on success.
_curl_post() {
    local url="$1"
    local auth_header="$2"
    local auth_value="$3"
    local body="$4"
    local tls_verify="${5:-true}"
    local connect_timeout="${6:-10}"

    local tls_flag=""
    if [[ "$tls_verify" != "true" ]]; then
        tls_flag="--insecure"
        log_warn "transport: TLS verification disabled for $url"
    fi

    local tmp_out tmp_hdr
    tmp_out=$(mktemp /tmp/macguard_curl_out.XXXXXX 2>/dev/null) || {
        log_error "transport: mktemp failed"
        TRANSPORT_HTTP_CODE=0
        TRANSPORT_RESPONSE=""
        return 1
    }
    tmp_hdr=$(mktemp /tmp/macguard_curl_hdr.XXXXXX 2>/dev/null) || {
        rm -f "$tmp_out"
        log_error "transport: mktemp failed"
        TRANSPORT_HTTP_CODE=0
        TRANSPORT_RESPONSE=""
        return 1
    }

    # We write body to a temp file to avoid shell quoting issues with large payloads
    local tmp_body
    tmp_body=$(mktemp /tmp/macguard_curl_body.XXXXXX 2>/dev/null) || {
        rm -f "$tmp_out" "$tmp_hdr"
        TRANSPORT_HTTP_CODE=0; TRANSPORT_RESPONSE=""
        return 1
    }
    printf '%s' "$body" > "$tmp_body"

    local http_code
    http_code=$(curl \
        --silent \
        --show-error \
        --write-out '%{http_code}' \
        --output "$tmp_out" \
        --dump-header "$tmp_hdr" \
        --connect-timeout "$connect_timeout" \
        --max-time $(( connect_timeout * 3 )) \
        --header "Content-Type: application/json" \
        --header "${auth_header}: ${auth_value}" \
        --data-binary "@${tmp_body}" \
        $tls_flag \
        "$url" 2>&1 || echo "000")

    TRANSPORT_HTTP_CODE="${http_code##*$'\n'}"   # last line = status code
    TRANSPORT_RESPONSE=$(cat "$tmp_out" 2>/dev/null || true)

    rm -f "$tmp_out" "$tmp_hdr" "$tmp_body"

    log_debug "transport: HTTP $TRANSPORT_HTTP_CODE from $url"
    [[ "$TRANSPORT_HTTP_CODE" =~ ^2 ]] && return 0 || return 1
}

# ── ship_splunk_hec REPORT_JSON ───────────────────────────────────────────────
# Wraps REPORT_JSON in a Splunk HEC event envelope and POSTs it.
ship_splunk_hec() {
    local report_json="$1"

    if [[ -z "$SPLUNK_HEC_URL" ]]; then
        log_error "transport: SPLUNK_HEC_URL is not set"
        return 1
    fi
    if [[ -z "$SPLUNK_HEC_TOKEN" ]]; then
        log_error "transport: SPLUNK_HEC_TOKEN is not set"
        return 1
    fi

    # Build HEC envelope
    # Extract collected_at from report to use as 'time' (epoch float)
    local collected_at
    collected_at=$(printf '%s' "$report_json" \
        | /usr/bin/python3 -c \
          'import json,sys,time,datetime
d=json.loads(sys.stdin.read())
t=d.get("collected_at","")
try:
    epoch=datetime.datetime.strptime(t,"%Y-%m-%dT%H:%M:%SZ")
    print("%.3f" % epoch.timestamp())
except Exception:
    print("%.3f" % time.time())
' 2>/dev/null || date +%s)

    # json_escape_string returns a value already wrapped in double-quotes
    local index_field=""
    if [[ -n "$SPLUNK_HEC_INDEX" ]]; then
        index_field="\"index\":$(json_escape_string "$SPLUNK_HEC_INDEX"),"
    fi

    # Minimal HEC envelope: {time, sourcetype, [index,] event: <full_report>}
    local envelope
    envelope="{\"time\":${collected_at},${index_field}\"sourcetype\":$(json_escape_string "$SPLUNK_HEC_SOURCETYPE"),\"event\":${report_json}}"

    local attempt=1
    while [[ $attempt -le $SPLUNK_HEC_MAX_RETRIES ]]; do
        log_info "transport: Splunk HEC attempt $attempt/$SPLUNK_HEC_MAX_RETRIES -> $SPLUNK_HEC_URL"

        if _curl_post \
               "$SPLUNK_HEC_URL" \
               "Authorization" "Splunk ${SPLUNK_HEC_TOKEN}" \
               "$envelope" \
               "$SPLUNK_HEC_TLS_VERIFY" \
               "$SPLUNK_HEC_CONNECT_TIMEOUT"; then
            log_info "transport: Splunk HEC success (HTTP $TRANSPORT_HTTP_CODE)"
            return 0
        fi

        # Retry on transient codes only
        if [[ "$TRANSPORT_HTTP_CODE" =~ ^(429|503|0)$ ]]; then
            log_warn "transport: Splunk HEC HTTP $TRANSPORT_HTTP_CODE, retrying in ${SPLUNK_HEC_RETRY_DELAY}s"
            sleep "$SPLUNK_HEC_RETRY_DELAY" || true
        else
            log_error "transport: Splunk HEC non-retryable HTTP $TRANSPORT_HTTP_CODE; response: ${TRANSPORT_RESPONSE:0:200}"
            return 1
        fi
        attempt=$(( attempt + 1 ))
    done

    log_error "transport: Splunk HEC failed after $SPLUNK_HEC_MAX_RETRIES attempts"
    return 1
}

# ── ship_https_post REPORT_JSON ───────────────────────────────────────────────
# POSTs REPORT_JSON directly to a generic HTTPS ingest endpoint.
ship_https_post() {
    local report_json="$1"

    if [[ -z "$HTTPS_POST_URL" ]]; then
        log_error "transport: HTTPS_POST_URL is not set"
        return 1
    fi
    if [[ -z "$HTTPS_POST_TOKEN" ]]; then
        log_error "transport: HTTPS_POST_TOKEN is not set"
        return 1
    fi

    local attempt=1
    while [[ $attempt -le $HTTPS_POST_MAX_RETRIES ]]; do
        log_info "transport: HTTPS POST attempt $attempt/$HTTPS_POST_MAX_RETRIES -> $HTTPS_POST_URL"

        if _curl_post \
               "$HTTPS_POST_URL" \
               "$HTTPS_POST_AUTH_HEADER" "Bearer ${HTTPS_POST_TOKEN}" \
               "$report_json" \
               "$HTTPS_POST_TLS_VERIFY" \
               "$HTTPS_POST_CONNECT_TIMEOUT"; then
            log_info "transport: HTTPS POST success (HTTP $TRANSPORT_HTTP_CODE)"
            return 0
        fi

        if [[ "$TRANSPORT_HTTP_CODE" =~ ^(429|503|0)$ ]]; then
            log_warn "transport: HTTPS POST HTTP $TRANSPORT_HTTP_CODE, retrying in 5s"
            sleep 5 || true
        else
            log_error "transport: HTTPS POST non-retryable HTTP $TRANSPORT_HTTP_CODE; response: ${TRANSPORT_RESPONSE:0:200}"
            return 1
        fi
        attempt=$(( attempt + 1 ))
    done

    log_error "transport: HTTPS POST failed after $HTTPS_POST_MAX_RETRIES attempts"
    return 1
}

# ── ship REPORT_JSON ──────────────────────────────────────────────────────────
# Dispatch to the correct transport based on TRANSPORT_TYPE.
ship() {
    local report_json="$1"

    if [[ "$TRANSPORT_ENABLED" != "true" ]]; then
        log_debug "transport: disabled; skipping shipment"
        return 0
    fi

    case "$TRANSPORT_TYPE" in
        splunk_hec)
            ship_splunk_hec "$report_json"
            ;;
        https_post)
            ship_https_post "$report_json"
            ;;
        *)
            log_error "transport: unknown TRANSPORT_TYPE '${TRANSPORT_TYPE}'"
            return 1
            ;;
    esac
}
