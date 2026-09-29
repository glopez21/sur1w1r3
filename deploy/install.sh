#!/usr/bin/env bash
# Install Sur1W1r3 on a SOC-monitored host.
#
# Idempotent: safe to re-run. Does NOT install Suricata itself — see README.md
# for the sensor setup, which is intentionally a separate decision.
#
# Usage:  sudo ./install.sh
#
# Afterwards, edit /etc/suricata-shipper.env and verify with:
#   sudo -u suricata-shipper /opt/suricata-shipper/.venv/bin/sur1w1r3 test

set -euo pipefail

SERVICE_USER="suricata-shipper"
INSTALL_DIR="/opt/suricata-shipper"
STATE_DIR="/var/lib/suricata-shipper"
CONFIG_FILE="/etc/suricata-shipper.env"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="$(dirname "$SCRIPT_DIR")"
VENV_PYTHON="${PYTHON_BIN:-python3.11}"

log() { printf '[install] %s\n' "$*"; }
die() { printf '[install] ERROR: %s\n' "$*" >&2; exit 1; }

[[ $EUID -eq 0 ]] || die "must run as root (use sudo)"

command -v "$VENV_PYTHON" >/dev/null 2>&1 \
    || die "$VENV_PYTHON not found; set PYTHON_BIN to a Python >= 3.11 interpreter"
command -v systemctl >/dev/null 2>&1 || die "systemd not available on this host"

# --- Suricata present? -------------------------------------------------------
if ! command -v suricata >/dev/null 2>&1; then
    log "WARNING: suricata is not installed."
    log "         The shipper will run but have nothing to read."
    log "         Install/configure the sensor first; see the Sur1W1r3 README"
fi

EVE_PATH="/var/log/suricata/eve.json"
if [[ ! -f "$EVE_PATH" ]]; then
    log "WARNING: $EVE_PATH not found. Ensure Suricata writes EVE JSON there."
fi

# --- Service user ------------------------------------------------------------
if ! id -u "$SERVICE_USER" >/dev/null 2>&1; then
    log "Creating system user $SERVICE_USER"
    useradd --system --no-create-home --shell /usr/sbin/nologin "$SERVICE_USER"
fi

# --- Application directory ---------------------------------------------------
mkdir -p "$INSTALL_DIR"
log "Installing shipper into $INSTALL_DIR"

# Use the interpreter that was version-checked at the top, not whatever
# "python3" resolves to, so the venv matches the 3.11+ requirement.
"$VENV_PYTHON" -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --quiet --upgrade pip

# Install this project and its declared dependencies. The sensor host does not
# need a ThreatPulse source checkout or any SOC package.
# Remove the previous distribution name if upgrading an existing install; the
# new package still installs the legacy `suricata-shipper` executable alias.
"$INSTALL_DIR/.venv/bin/pip" uninstall --quiet --yes suricata-shipper >/dev/null 2>&1 || true
"$INSTALL_DIR/.venv/bin/pip" install --quiet "$AGENT_DIR"

# --- State and config directories -------------------------------------------
mkdir -p "$STATE_DIR"
chown "$SERVICE_USER:$SERVICE_USER" "$STATE_DIR"
chmod 0750 "$STATE_DIR"

if [[ ! -f "$CONFIG_FILE" ]]; then
    install -m 0600 -o root -g "$SERVICE_USER" \
        "$SCRIPT_DIR/suricata-shipper.env.example" "$CONFIG_FILE"
    log "Wrote $CONFIG_FILE — EDIT IT NOW with endpoints and keys"
else
    log "$CONFIG_FILE already exists, leaving it untouched"
    chmod 0640 "$CONFIG_FILE"
    chown root:"$SERVICE_USER" "$CONFIG_FILE"
fi

# --- Read access to EVE ------------------------------------------------------
if [[ -f "$EVE_PATH" ]]; then
    if ! sudo -u "$SERVICE_USER" test -r "$EVE_PATH"; then
        log "Granting $SERVICE_USER read access to Suricata logs"
        usermod -aG suricata "$SERVICE_USER" 2>/dev/null \
            || log "  note: could not add to 'suricata' group; adjust ACLs manually"
    fi
fi

# --- systemd -----------------------------------------------------------------
install -m 0644 "$SCRIPT_DIR/suricata-shipper.service" /etc/systemd/system/
if [[ -f "$SCRIPT_DIR/suricata-logrotate.conf" && ! -f /etc/logrotate.d/suricata-shipper ]]; then
    install -m 0644 "$SCRIPT_DIR/suricata-logrotate.conf" /etc/logrotate.d/suricata-shipper
    log "Installed logrotate fragment"
fi

systemctl daemon-reload

if [[ "${1:-}" == "--start" ]]; then
    log "Starting Sur1W1r3"
    systemctl enable --now suricata-shipper.service
    sleep 2
    systemctl --no-pager --lines=20 status suricata-shipper.service || true
else
    log "Installed unit only (not enabled or started)"
fi

cat <<EOF

[install] Done. Next steps:
  1. Edit $CONFIG_FILE — endpoints, EVE_SHIPPER_SOURCE, and the API key.
  2. On the ThreatPulse host, add a matching "label:secret" entry to
     NETWORK_MONITOR_INGEST_KEYS and restart network-monitor.
  3. Verify connectivity:
        sudo -u $SERVICE_USER $INSTALL_DIR/.venv/bin/sur1w1r3 test
  4. Enable and start the service:
        systemctl enable --now suricata-shipper
  5. Watch it:
       journalctl -u suricata-shipper -f
EOF
