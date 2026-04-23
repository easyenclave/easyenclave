#!/bin/sh
# Shared helpers for vendor stages. Sourced, not executed.
#
# Provides:
#   ee_log <msg>           — prefixed diagnostic to stderr
#   ee_ifup <iface>        — link-up, apply EE_IP/EE_GATEWAY/EE_DNS
#                             overrides from $ENV_FILE, or DHCP via
#                             udhcpc if no static IP is configured
#   ee_append_config <body> — flatten body into KEY=VALUE lines in
#                             $ENV_FILE. Accepts both KEY=VALUE-per-line
#                             and flat JSON `{"K":"V", ...}` (the legacy
#                             ee-config contract). Rejects nested JSON
#                             with a loud error.
#
# Callers must export $ENV_FILE before using ee_ifup/ee_append_config.

ee_log() {
    printf 'vendor:%s: %s\n' "${VENDOR_NAME:-?}" "$*" >&2
}

# Extract KEY= from the env file (most recent occurrence wins).
ee_env_get() {
    [ -f "$ENV_FILE" ] || return 1
    grep "^$1=" "$ENV_FILE" 2>/dev/null | tail -n 1 | cut -d= -f2-
}

ee_ifup() {
    iface="$1"
    [ -n "$iface" ] || { ee_log "ee_ifup: no iface"; return 1; }

    ip link set "$iface" up 2>/dev/null || :

    static_ip=$(ee_env_get EE_IP || true)
    if [ -n "$static_ip" ]; then
        ee_log "static ip=$static_ip on $iface"
        ip addr add "$static_ip" dev "$iface" 2>/dev/null || :
        gw=$(ee_env_get EE_GATEWAY || true)
        if [ -n "$gw" ]; then
            ee_log "default route via $gw"
            ip route add default via "$gw" dev "$iface" 2>/dev/null || :
        fi
    else
        ee_log "udhcpc on $iface"
        udhcpc -i "$iface" -q -n -t 10 \
            -s /usr/share/udhcpc/default.script \
            -O staticroutes 2>&1 | tail -n 3 || :
    fi

    dns=$(ee_env_get EE_DNS || true)
    if [ -n "$dns" ]; then
        ee_log "static dns=$dns"
        mkdir -p "$NEWROOT/run"
        printf 'nameserver %s\n' "$dns" > "$NEWROOT/run/resolv.conf" 2>/dev/null || :
    fi
}

# Write a JSON flat-object body to $ENV_FILE as KEY=VALUE lines.
# Honors \" escapes in string values. Any non-string value or nested
# structure returns non-zero — we don't support nested metadata.
_ee_json_to_env() {
    awk '
    { buf = buf $0 "\n" }
    END {
        s = buf
        n = length(s)
        i = 1
        while (i <= n && substr(s, i, 1) ~ /[[:space:]]/) i++
        if (i > n || substr(s, i, 1) != "{") { exit 1 }
        i++
        while (i <= n) {
            while (i <= n && substr(s, i, 1) ~ /[[:space:],]/) i++
            if (i > n) break
            c = substr(s, i, 1)
            if (c == "}") break
            if (c != "\"") { exit 2 }
            i++
            key = ""
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "\\") { key = key substr(s, i+1, 1); i += 2; continue }
                if (c == "\"") { i++; break }
                key = key c; i++
            }
            while (i <= n && substr(s, i, 1) ~ /[[:space:]]/) i++
            if (substr(s, i, 1) != ":") { exit 3 }
            i++
            while (i <= n && substr(s, i, 1) ~ /[[:space:]]/) i++
            if (substr(s, i, 1) != "\"") { exit 4 }
            i++
            val = ""
            while (i <= n) {
                c = substr(s, i, 1)
                if (c == "\\") { val = val substr(s, i+1, 1); i += 2; continue }
                if (c == "\"") { i++; break }
                val = val c; i++
            }
            print key "=" val
        }
    }
    '
}

ee_append_config() {
    body="$1"
    [ -n "$body" ] || return 0
    # Leading `{` (after whitespace) = JSON. Anything else = KEY=VALUE.
    trimmed=$(printf '%s' "$body" | sed 's/^[[:space:]]*//')
    case "$trimmed" in
        "{"*)
            ee_log "config body looks like JSON — flattening to KEY=VALUE"
            if out=$(printf '%s' "$body" | _ee_json_to_env); then
                printf '%s\n' "$out" >> "$ENV_FILE"
                ee_log "merged JSON config into $ENV_FILE"
            else
                ee_log "JSON flatten FAILED (expected flat {string:string} — migrate to KEY=VALUE)"
                return 1
            fi
            ;;
        *)
            # Filter comments + blanks on the way in.
            printf '%s' "$body" | grep -vE '^[[:space:]]*(#|$)' >> "$ENV_FILE"
            ee_log "merged KEY=VALUE config into $ENV_FILE"
            ;;
    esac
}
