#!/usr/bin/env bash
# Discover a Linux sensor host, then optionally install and verify the shipper.
# Secrets are accepted only through environment variables and never displayed.
set -euo pipefail

SERVICE_USER="suricata-shipper"
INSTALL_DIR="/opt/suricata-shipper"
CONFIG_FILE="/etc/suricata-shipper.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODE="check"
FAILURES=0
WARNINGS=0

usage() {
    cat <<'EOF'
Usage:
  onboard.sh [--check | --install] [--help]

Default --check: read-only host discovery and pipeline preflight.
--install: install the shipper, write its config, test configured SOC sinks,
           then enable and start the systemd service.

For --install, provide these through the environment (never command-line args):
  EVE_SHIPPER_FLOW_URL          ThreatPulse network-monitor batch endpoint
  EVE_SHIPPER_FLOW_API_KEY      flow-ingest credential
  EVE_SHIPPER_ALERT_URL         optional SIEM webhook endpoint
  EVE_SHIPPER_ALERT_API_KEY     optional SIEM API-key credential
  EVE_SHIPPER_ALERT_WEBHOOK_SECRET optional SIEM HMAC secret
  EVE_SHIPPER_SOURCE            optional sensor label; defaults to hostname
  EVE_SHIPPER_EVE_PATH          optional EVE path; defaults to Suricata's path

Example:
  sudo ./deploy/onboard.sh --install
  # For automation, export values from a secret manager, then preserve only
  # these variable names through sudo (never pass credentials as CLI arguments).
  sudo --preserve-env=EVE_SHIPPER_FLOW_URL,EVE_SHIPPER_FLOW_API_KEY \
    ./deploy/onboard.sh --install
EOF
}

for arg in "$@"; do
    case "$arg" in
        --check) MODE="check" ;;
        --install) MODE="install" ;;
        --help|-h) usage; exit 0 ;;
        *) printf '[onboard] ERROR: unknown argument: %s\n' "$arg" >&2; usage >&2; exit 2 ;;
    esac
done
if [[ "$MODE" == "install" && $EUID -ne 0 ]]; then
    printf '[onboard] ERROR: --install must run as root\n' >&2
    exit 1
fi

pass() { printf '  [PASS] %s\n' "$*"; }
warn() { printf '  [WARN] %s\n' "$*"; WARNINGS=$((WARNINGS + 1)); }
fail() { printf '  [FAIL] %s\n' "$*"; FAILURES=$((FAILURES + 1)); }
info() { printf '  [INFO] %s\n' "$*"; }

HOSTNAME_SHORT="$(hostname -s 2>/dev/null || hostname)"
SOURCE_LABEL="${EVE_SHIPPER_SOURCE:-$HOSTNAME_SHORT}"
EVE_PATH="${EVE_SHIPPER_EVE_PATH:-/var/log/suricata/eve.json}"
FLOW_URL="${EVE_SHIPPER_FLOW_URL:-}"
FLOW_KEY="${EVE_SHIPPER_FLOW_API_KEY:-}"
ALERT_URL="${EVE_SHIPPER_ALERT_URL:-}"
ALERT_KEY="${EVE_SHIPPER_ALERT_API_KEY:-}"
ALERT_SECRET="${EVE_SHIPPER_ALERT_WEBHOOK_SECRET:-}"
TLS_VERIFY="${EVE_SHIPPER_TLS_VERIFY:-true}"

printf 'Sur1W1r3 host discovery (%s)\n' "$MODE"
printf 'Host: %s | OS: ' "$HOSTNAME_SHORT"
if [[ -r /etc/os-release ]]; then
    . /etc/os-release
    printf '%s %s\n' "${PRETTY_NAME:-Linux}" "${VERSION_ID:-}"
else
    printf '%s\n' "$(uname -s) $(uname -r)"
fi
printf 'Kernel: %s | Architecture: %s\n' "$(uname -r)" "$(uname -m)"
CPU_COUNT="$(getconf _NPROCESSORS_ONLN 2>/dev/null || printf '?')"
MEMORY_KIB="$(awk '/MemTotal:/ {print $2; exit}' /proc/meminfo 2>/dev/null || printf '?')"
if [[ "$MEMORY_KIB" =~ ^[0-9]+$ ]]; then MEMORY_MIB="$((MEMORY_KIB / 1024))"; else MEMORY_MIB="unknown"; fi
DISK_AVAILABLE="$(df -hP /var/lib 2>/dev/null | awk 'NR == 2 {print $4}')"
printf 'Resources: %s CPU(s) | %s MiB RAM | %s available on /var/lib\n' \
    "$CPU_COUNT" "$MEMORY_MIB" "${DISK_AVAILABLE:-unknown}"

PYTHON_BIN=""
for candidate in python3.11 python3; do
    if command -v "$candidate" >/dev/null 2>&1 && "$candidate" -c 'import sys; raise SystemExit(sys.version_info < (3,11))' 2>/dev/null; then
        PYTHON_BIN="$candidate"
        break
    fi
done
if [[ -n "$PYTHON_BIN" ]]; then pass "Python 3.11+ available: $($PYTHON_BIN --version 2>&1)"; else fail "Python 3.11+ is required"; fi

DEFAULT_IFACE=""
if command -v ip >/dev/null 2>&1; then
    DEFAULT_IFACE="$(ip -o route show default 2>/dev/null | awk 'NR == 1 { for (i=1; i<=NF; i++) if ($i == "dev") print $(i+1) }')"
fi
CAPTURE_IFACE="${SURICATA_INTERFACE:-$DEFAULT_IFACE}"
if [[ -n "$CAPTURE_IFACE" ]]; then
    if command -v ip >/dev/null 2>&1 && ip link show dev "$CAPTURE_IFACE" >/dev/null 2>&1; then
        pass "default/capture interface: $CAPTURE_IFACE"
    else
        fail "capture interface $CAPTURE_IFACE does not exist"
    fi
else
    warn "could not detect a capture interface; set SURICATA_INTERFACE before install"
fi

LOCAL_ADDRESSES='[]'
if [[ -n "${EVE_SHIPPER_LOCAL_ADDRESSES:-}" ]]; then
    LOCAL_ADDRESSES="$EVE_SHIPPER_LOCAL_ADDRESSES"
    pass "using configured local addresses for flow direction"
elif [[ -n "$CAPTURE_IFACE" && -n "$PYTHON_BIN" ]] && command -v ip >/dev/null 2>&1; then
    ADDR_LIST="$(ip -o addr show dev "$CAPTURE_IFACE" scope global 2>/dev/null | awk '{print $4}' | cut -d/ -f1 || true)"
    LOCAL_ADDRESSES="$(printf '%s\n' "$ADDR_LIST" | "$PYTHON_BIN" -c 'import json,sys; print(json.dumps([x.strip() for x in sys.stdin if x.strip()]))')"
    pass "addresses on $CAPTURE_IFACE used for flow direction: $LOCAL_ADDRESSES"
else
    warn "cannot enumerate addresses for the capture interface; shipper will auto-detect egress addresses"
fi

if command -v suricata >/dev/null 2>&1; then
    pass "Suricata installed: $(suricata --build-info 2>/dev/null | awk '/Suricata version/ {print $NF; exit}' || suricata -V 2>&1 | head -1)"
else
    fail "Suricata is not installed; install/configure it before onboarding the shipper"
fi

if [[ -f "$EVE_PATH" ]]; then
    pass "EVE file exists: $EVE_PATH ($(stat -c '%s bytes' "$EVE_PATH" 2>/dev/null || wc -c < "$EVE_PATH") )"
    if [[ -r "$EVE_PATH" ]]; then pass "EVE file is readable by the current user"; else fail "EVE file is not readable"; fi
    if [[ -r /etc/suricata/suricata.yaml ]]; then
        if grep -q 'eve-log' /etc/suricata/suricata.yaml && grep -q 'flow' /etc/suricata/suricata.yaml && grep -q 'alert' /etc/suricata/suricata.yaml; then
            pass "Suricata config appears to enable EVE flow and alert events"
        else
            warn "Suricata config may not enable both EVE flow and alert events; inspect deploy/suricata-eve.yaml.example"
        fi
    fi
else
    fail "EVE file not found at $EVE_PATH; configure Suricata EVE output first"
fi

if [[ -n "$PYTHON_BIN" ]] && ! "$PYTHON_BIN" - "$LOCAL_ADDRESSES" <<'PY'
import ipaddress, json, sys
addresses = json.loads(sys.argv[1])
if not isinstance(addresses, list) or any(not isinstance(a, str) for a in addresses):
    raise SystemExit(1)
for address in addresses:
    ipaddress.ip_address(address)
PY
then
    fail "local-address setting must be a JSON list of IP addresses"
fi

if command -v systemctl >/dev/null 2>&1 && [[ -d /run/systemd/system ]]; then
    pass "systemd available"
else
    fail "an active systemd installation is required for the managed service"
fi
if id -u "$SERVICE_USER" >/dev/null 2>&1; then pass "service user exists"; else info "service user will be created during installation"; fi
if command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet suricata.service; then
    pass "Suricata service is running"
else
    warn "Suricata service is not active; it must be started for live capture"
fi

if [[ "$MODE" == "install" && $FAILURES -gt 0 ]]; then
    printf '\nResolve the failed host requirements before entering credentials or installing.\n' >&2
    exit 1
fi

if [[ "$MODE" == "install" && -r /dev/tty && -w /dev/tty ]]; then
    exec 3<>/dev/tty
    [[ -n "$FLOW_URL" ]] || read -r -p "ThreatPulse flow ingest URL: " FLOW_URL <&3
    if [[ -z "$FLOW_KEY" ]]; then
        read -r -s -p "Flow API key (input hidden): " FLOW_KEY <&3
        printf '\n' >&3
    fi
    if [[ -z "$ALERT_URL" && -z "$ALERT_KEY" && -z "$ALERT_SECRET" ]]; then
        read -r -p "Configure the SIEM alert sink now? [y/N] " ENABLE_ALERTS <&3
        [[ "$ENABLE_ALERTS" =~ ^[Yy]$ ]] && read -r -p "ThreatPulse SIEM webhook URL: " ALERT_URL <&3
    fi
    if [[ -n "$ALERT_URL" && -z "$ALERT_KEY" && -z "$ALERT_SECRET" ]]; then
        read -r -p "Alert auth [hmac/api-key] (default hmac): " ALERT_AUTH <&3
        if [[ "${ALERT_AUTH,,}" == "api-key" ]]; then
            read -r -s -p "Alert API key (input hidden): " ALERT_KEY <&3
        else
            read -r -s -p "Webhook HMAC secret (input hidden): " ALERT_SECRET <&3
        fi
        printf '\n' >&3
    fi
fi

if [[ -n "$FLOW_URL" ]]; then pass "flow endpoint configured (value hidden)"; else warn "flow endpoint is not configured"; fi
if [[ -n "$FLOW_KEY" ]]; then pass "flow credential configured (value hidden)"; else warn "flow credential is not configured"; fi
if [[ -n "$ALERT_URL" && ( -n "$ALERT_KEY" || -n "$ALERT_SECRET" ) ]]; then
    pass "alert endpoint and credential configured (values hidden)"
elif [[ -n "$ALERT_URL" || -n "$ALERT_KEY" || -n "$ALERT_SECRET" ]]; then
    warn "alert sink is incomplete; provide URL plus API key or webhook secret"
else
    info "alert sink not configured; flow-only operation is supported"
fi

check_endpoint() {
    local name="$1" url="$2"
    [[ -n "$url" ]] || return 0
    if [[ -n "$PYTHON_BIN" ]] && "$PYTHON_BIN" - "$url" <<'PY'
import socket, sys
from urllib.parse import urlsplit
u = urlsplit(sys.argv[1])
if u.scheme not in ("https", "http") or not u.hostname:
    raise SystemExit(1)
try:
    with socket.create_connection((u.hostname, u.port or (443 if u.scheme == "https" else 80)), timeout=3):
        pass
except OSError:
    raise SystemExit(1)
PY
    then
        pass "$name endpoint DNS/TCP reachable (HTTP auth not tested in --check mode)"
    else
        warn "$name endpoint host could not be resolved/reached from this sensor"
    fi
}
check_endpoint flow "$FLOW_URL"
check_endpoint alert "$ALERT_URL"

printf '\nSummary: %d failure(s), %d warning(s)\n' "$FAILURES" "$WARNINGS"
if [[ "$MODE" == "check" ]]; then
    [[ $FAILURES -eq 0 ]] || exit 1
    printf 'Read-only check complete. Run with --install after providing sink URL(s) and credentials.\n'
    exit 0
fi

[[ $FAILURES -eq 0 ]] || { printf '[onboard] ERROR: resolve failed checks before installing\n' >&2; exit 1; }
[[ -n "$FLOW_URL" && -n "$FLOW_KEY" ]] || { printf '[onboard] ERROR: --install requires EVE_SHIPPER_FLOW_URL and EVE_SHIPPER_FLOW_API_KEY\n' >&2; exit 1; }
[[ "$FLOW_URL" == https://* ]] || { printf '[onboard] ERROR: flow URL must use HTTPS\n' >&2; exit 1; }
[[ "$TLS_VERIFY" == "true" ]] || { printf '[onboard] ERROR: TLS verification must remain enabled for installation\n' >&2; exit 1; }
if [[ -n "$ALERT_URL" && -z "$ALERT_KEY" && -z "$ALERT_SECRET" ]]; then
    printf '[onboard] ERROR: alert URL requires ALERT_API_KEY or ALERT_WEBHOOK_SECRET\n' >&2
    exit 1
fi
if [[ -z "$ALERT_URL" && ( -n "$ALERT_KEY" || -n "$ALERT_SECRET" ) ]]; then
    printf '[onboard] ERROR: alert credentials were provided without ALERT_URL\n' >&2
    exit 1
fi
if [[ -n "$ALERT_URL" && "$ALERT_URL" != https://* ]]; then
    printf '[onboard] ERROR: alert URL must use HTTPS\n' >&2
    exit 1
fi

case "$SOURCE_LABEL" in *[!A-Za-z0-9_.-]*|'') printf '[onboard] ERROR: source label must use letters, digits, dot, underscore, or hyphen\n' >&2; exit 1 ;; esac
for value in "$FLOW_URL" "$FLOW_KEY" "$ALERT_URL" "$ALERT_KEY" "$ALERT_SECRET"; do
    [[ "$value" != *$'\n'* ]] || { printf '[onboard] ERROR: config values must not contain newlines\n' >&2; exit 1; }
done

"$SCRIPT_DIR/install.sh"
CONFIG_TMP="$(mktemp "${CONFIG_FILE}.XXXXXX")"
trap 'rm -f "$CONFIG_TMP"' EXIT
export EVE_SHIPPER_SOURCE="$SOURCE_LABEL"
export EVE_SHIPPER_FLOW_URL="$FLOW_URL"
export EVE_SHIPPER_FLOW_API_KEY="$FLOW_KEY"
export EVE_SHIPPER_ALERT_URL="$ALERT_URL"
export EVE_SHIPPER_ALERT_API_KEY="$ALERT_KEY"
export EVE_SHIPPER_ALERT_WEBHOOK_SECRET="$ALERT_SECRET"
export EVE_SHIPPER_EVE_PATH="$EVE_PATH"
export EVE_SHIPPER_LOCAL_ADDRESSES="$LOCAL_ADDRESSES"
export EVE_SHIPPER_AUTO_DETECT_ADDRESSES=true
export EVE_SHIPPER_TLS_VERIFY="$TLS_VERIFY"
export EVE_SHIPPER_LOG_LEVEL=INFO
"$INSTALL_DIR/.venv/bin/python" - "$CONFIG_TMP" <<'PY'
import os
import sys
from dotenv import set_key

path = sys.argv[1]
for name in (
    "EVE_SHIPPER_SOURCE",
    "EVE_SHIPPER_FLOW_URL",
    "EVE_SHIPPER_FLOW_API_KEY",
    "EVE_SHIPPER_ALERT_URL",
    "EVE_SHIPPER_ALERT_API_KEY",
    "EVE_SHIPPER_ALERT_WEBHOOK_SECRET",
    "EVE_SHIPPER_EVE_PATH",
    "EVE_SHIPPER_LOCAL_ADDRESSES",
    "EVE_SHIPPER_AUTO_DETECT_ADDRESSES",
    "EVE_SHIPPER_TLS_VERIFY",
    "EVE_SHIPPER_LOG_LEVEL",
):
    set_key(path, name, os.environ[name], quote_mode="always")
PY
chown root:"$SERVICE_USER" "$CONFIG_TMP"
chmod 0640 "$CONFIG_TMP"
mv "$CONFIG_TMP" "$CONFIG_FILE"
trap - EXIT

printf '\nTesting configured SOC sinks before service start...\n'
runuser -u "$SERVICE_USER" -- "$INSTALL_DIR/.venv/bin/sur1w1r3" test --config "$CONFIG_FILE"
systemctl enable --now suricata-shipper.service
printf '\n[Sur1W1r3] Pipeline active. Follow logs with: journalctl -u suricata-shipper -f\n'
