#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# soar-ar-common.sh — shared library for the SOAR Active-Response scripts.
#
# Sourced by soar-block / soar-unblock / soar-isolate / soar-unisolate. Provides
# the Wazuh-4.x STDIN parsing, the SAFETY allowlist/denylist, the firewall
# backend abstraction (nftables → ipset+iptables → iptables), and logging.
#
# SAFETY MODEL (do not relax without review):
#   • These four scripts are the ONLY things the Wazuh manager can trigger on the
#     endpoint. They take NO arbitrary command from the wire — only a validated
#     IP argument. The action is fixed by which script ran.
#   • A target IP is acted on ONLY if it is a valid, GLOBAL (public) address.
#     Private/loopback/link-local/multicast/reserved IPs and the manager host are
#     REFUSED (we never block our own infra, the gateway, or loopback).
#   • Every invocation is logged to active-responses.log with its command id.
# ─────────────────────────────────────────────────────────────────────────────
set -uo pipefail

# ── Configuration ─────────────────────────────────────────────────────────────
# Written by the installer; sourced here so MANAGER_HOST etc. are available to
# the AR scripts (which run from /var/ossec/active-response/bin via execd).
SOAR_AR_ENV="${SOAR_AR_ENV:-/var/ossec/active-response/soar-ar.env}"
[ -f "$SOAR_AR_ENV" ] && . "$SOAR_AR_ENV"

MANAGER_HOST="${MANAGER_HOST:-}"                 # never blocked / kept alive on isolate
MANAGER_PORTS="${MANAGER_PORTS:-1514 1515 1516 55000}"  # enrollment/comms/API
SOAR_BLOCK_TTL="${SOAR_BLOCK_TTL:-3600}"         # seconds; block auto-expires
SOAR_FW_BACKEND="${SOAR_FW_BACKEND:-auto}"       # auto|nft|ipset|iptables
SOAR_LOG="${SOAR_LOG:-/var/ossec/logs/active-responses.log}"
# Interfaces kept alive during ISOLATE so an endpoint that is ALSO a container
# host (e.g. the detection stack runs here) stays internally functional. Docker
# bridges by default. Set empty for a strict, total isolate. Trade-off: traffic
# on these interfaces (incl. container egress) is not cut.
SOAR_KEEP_IFACES="${SOAR_KEEP_IFACES:-docker0 docker_gwbridge br+}"

AR_PROGRAM="$(basename "$0")"
AR_NFT_TABLE="soar"
AR_SET_NAME="soar_block"
AR_ISO_CHAIN="SOAR_ISOLATE"

# ── Logging ───────────────────────────────────────────────────────────────────
ar_log() {
    # ar_log <status> <message>
    local ts status msg
    ts="$(date '+%Y/%m/%d %H:%M:%S')"
    status="$1"; shift; msg="$*"
    # Append to the Wazuh AR log (best-effort) and stderr.
    printf '%s soar-ar: program=%s id=%s status=%s %s\n' \
        "$ts" "$AR_PROGRAM" "${AR_ID:--}" "$status" "$msg" >>"$SOAR_LOG" 2>/dev/null
    printf '[soar-ar] %s: %s\n' "$status" "$msg" >&2
}

# ── STDIN parse + validation (centralised in python3 for robustness) ──────────
# Sets: AR_STATUS (ok|denied|invalid_ip|bad_command|parse_error|no_python),
#       AR_CMD ("add"|"delete"), AR_TARGET (validated IP or ""), AR_ID (cmd id).
ar_parse_stdin() {
    local raw out
    # Wazuh's execd writes ONE JSON line to the script's stdin and KEEPS THE PIPE
    # OPEN (stateful AR sends a later "delete" on the same fd). Reading to EOF with
    # `cat` therefore HANGS forever — and a single-threaded execd then blocks on
    # the stuck child, so NO subsequent AR command is ever processed. Read exactly
    # one line, with a timeout as a safety net.
    IFS= read -r -t 5 raw || true

    if ! command -v python3 >/dev/null 2>&1; then
        AR_STATUS="no_python"; AR_CMD=""; AR_TARGET=""; AR_ID="-"
        return 0
    fi

    # NOTE: the program is fed to `python3 -` via the heredoc (stdin), so the
    # alert JSON CANNOT also come through stdin — it is passed in AR_RAW instead.
    out="$(AR_RAW="$raw" MANAGER_HOST="$MANAGER_HOST" python3 - <<'PY'
import sys, os, json, ipaddress
def emit(status, cmd="", ip="", cid="-"):
    print(f"{status}|{cmd}|{ip}|{cid}"); sys.exit(0)
try:
    d = json.loads(os.environ.get("AR_RAW", ""))
except Exception:
    emit("parse_error")
cmd    = str(d.get("command", "")).strip().lower()
params = d.get("parameters") or {}
args   = params.get("extra_args") or []
ip     = str(args[0]).strip() if args else ""
# command id for the audit log (best-effort from the embedded alert)
alert  = params.get("alert") or {}
cid    = str(alert.get("id") or d.get("id") or "-")
# Wazuh stateful commands are add/delete; on-demand API maps to these too.
if cmd not in ("add", "delete"):
    emit("bad_command", cmd, ip, cid)
# IP is required for block/unblock, optional (empty) for isolate/unisolate.
if ip:
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        emit("invalid_ip", cmd, ip, cid)
    mh = os.environ.get("MANAGER_HOST", "").strip()
    denied = (addr.is_private or addr.is_loopback or addr.is_link_local
              or addr.is_multicast or addr.is_reserved or addr.is_unspecified
              or (mh and ip == mh))
    if denied:
        emit("denied", cmd, ip, cid)
emit("ok", cmd, ip, cid)
PY
)"
    AR_STATUS="${out%%|*}"; out="${out#*|}"
    AR_CMD="${out%%|*}";    out="${out#*|}"
    AR_TARGET="${out%%|*}"; out="${out#*|}"
    AR_ID="${out%%|*}"
    [ -z "${AR_ID:-}" ] && AR_ID="-"
}

# ── Firewall backend selection ────────────────────────────────────────────────
ar_backend() {
    if [ "$SOAR_FW_BACKEND" != "auto" ]; then echo "$SOAR_FW_BACKEND"; return; fi
    if command -v nft >/dev/null 2>&1; then echo nft
    elif command -v ipset >/dev/null 2>&1 && command -v iptables >/dev/null 2>&1; then echo ipset
    elif command -v iptables >/dev/null 2>&1; then echo iptables
    else echo none; fi
}

# ── Block (egress DROP to a public IP, with TTL/expiry) ───────────────────────
ar_block_add() {
    local ip="$1" be; be="$(ar_backend)"
    case "$be" in
      nft)
        nft list table inet "$AR_NFT_TABLE" >/dev/null 2>&1 || {
            nft add table inet "$AR_NFT_TABLE"
            nft add set inet "$AR_NFT_TABLE" "$AR_SET_NAME" \
                '{ type ipv4_addr; flags timeout; }'
            nft add chain inet "$AR_NFT_TABLE" out \
                '{ type filter hook output priority 0; }'
            nft add rule  inet "$AR_NFT_TABLE" out \
                ip daddr @"$AR_SET_NAME" drop
        }
        nft add element inet "$AR_NFT_TABLE" "$AR_SET_NAME" \
            "{ $ip timeout ${SOAR_BLOCK_TTL}s }" ;;
      ipset)
        ipset create "$AR_SET_NAME" hash:ip timeout 0 -exist
        iptables -C OUTPUT -m set --match-set "$AR_SET_NAME" dst -j DROP 2>/dev/null \
            || iptables -I OUTPUT -m set --match-set "$AR_SET_NAME" dst -j DROP
        iptables -C FORWARD -m set --match-set "$AR_SET_NAME" dst -j DROP 2>/dev/null \
            || iptables -I FORWARD -m set --match-set "$AR_SET_NAME" dst -j DROP
        ipset add "$AR_SET_NAME" "$ip" timeout "$SOAR_BLOCK_TTL" -exist ;;
      iptables)
        iptables -C OUTPUT -d "$ip" -j DROP 2>/dev/null \
            || iptables -I OUTPUT -d "$ip" -j DROP
        # No native TTL — schedule a detached expiry.
        setsid bash -c "sleep $SOAR_BLOCK_TTL; iptables -D OUTPUT -d $ip -j DROP 2>/dev/null" \
            </dev/null >/dev/null 2>&1 & ;;
      *) return 3 ;;
    esac
}

ar_block_del() {
    local ip="$1" be; be="$(ar_backend)"
    case "$be" in
      nft)      nft delete element inet "$AR_NFT_TABLE" "$AR_SET_NAME" "{ $ip }" 2>/dev/null ;;
      ipset)    ipset del "$AR_SET_NAME" "$ip" 2>/dev/null ;;
      iptables) while iptables -D OUTPUT -d "$ip" -j DROP 2>/dev/null; do :; done ;;
      *) return 3 ;;
    esac
    return 0
}

# ── Isolate (drop ALL traffic except the agent↔manager channel + loopback) ────
# Implemented with iptables (most portable; isolate is a heavy, rare action).
ar_isolate_on() {
    command -v iptables >/dev/null 2>&1 || return 3
    [ -n "$MANAGER_HOST" ] || { ar_log error "isolate refused: MANAGER_HOST unset (would orphan the host)"; return 4; }
    iptables -N "$AR_ISO_CHAIN" 2>/dev/null
    iptables -F "$AR_ISO_CHAIN"
    iptables -A "$AR_ISO_CHAIN" -i lo -j ACCEPT
    iptables -A "$AR_ISO_CHAIN" -o lo -j ACCEPT
    # Keep Docker bridge networking alive so a container-host's own stack
    # (kafka/postgres/inference/translator/dashboard) survives isolation.
    for ifc in $SOAR_KEEP_IFACES; do
        iptables -A "$AR_ISO_CHAIN" -i "$ifc" -j ACCEPT
        iptables -A "$AR_ISO_CHAIN" -o "$ifc" -j ACCEPT
    done
    iptables -A "$AR_ISO_CHAIN" -m state --state ESTABLISHED,RELATED -d "$MANAGER_HOST" -j ACCEPT
    iptables -A "$AR_ISO_CHAIN" -m state --state ESTABLISHED,RELATED -s "$MANAGER_HOST" -j ACCEPT
    for p in $MANAGER_PORTS; do
        iptables -A "$AR_ISO_CHAIN" -p tcp -d "$MANAGER_HOST" --dport "$p" -j ACCEPT
        iptables -A "$AR_ISO_CHAIN" -p udp -d "$MANAGER_HOST" --dport "$p" -j ACCEPT
    done
    iptables -A "$AR_ISO_CHAIN" -j DROP
    for ch in INPUT OUTPUT FORWARD; do
        iptables -C "$ch" -j "$AR_ISO_CHAIN" 2>/dev/null || iptables -I "$ch" 1 -j "$AR_ISO_CHAIN"
    done
}

ar_isolate_off() {
    command -v iptables >/dev/null 2>&1 || return 3
    for ch in INPUT OUTPUT FORWARD; do
        while iptables -D "$ch" -j "$AR_ISO_CHAIN" 2>/dev/null; do :; done
    done
    iptables -F "$AR_ISO_CHAIN" 2>/dev/null
    iptables -X "$AR_ISO_CHAIN" 2>/dev/null
    return 0
}
