# Suricata Shipper

Ships Suricata EVE telemetry from a monitored host to **ThreatPulse**, the Tier-1
platform. Alerts that clear ThreatPulse's correlation and triage thresholds are
escalated to Augur by the alerting service, so this agent **never talks to
Augur directly**.

One sensor, two streams:

| EVE `event_type` | Destination | Auth | What it gives you |
|---|---|---|---|
| `flow` | `network-monitor` `/api/v1/traffic/ingest/batch` | `X-API-Key` | 5-tuple flows with byte/packet counters for analytics, top-talkers, and anomaly baselines |
| `alert` | `siem-app` `/api/v1/webhooks` | HMAC `X-Webhook-Signature` | Signature-based IDS alerts for correlation and alerting |

Other EVE types (`dns`, `tls`, `http`, `fileinfo`, `stats`, …) are counted and
dropped, so the stream stays cheap to send.

---

## Design decisions worth knowing

**Batching is not optional.** Suricata can emit thousands of flow records per
second. One HTTP request per flow saturates both ends, so flows are batched up
to `flow_batch_size` (250 default) against a server-side cap of
`MAX_FLOWS_PER_REQUEST` (500). Keep the client at or below the server value.

**Byte direction is the subtle part.** Suricata counts `bytes_toserver` and
`bytes_toclient` from the *flow originator's* perspective, but ThreatPulse's
`bytes_in`/`bytes_out` are host-relative. The shipper determines which end is
local (from `EVE_SHIPPER_LOCAL_ADDRESSES`, or auto-detected) and maps
accordingly. Get this wrong and every flow in your SIEM is silently inverted.

**Two sinks, two queues.** Flows and alerts are claimed independently, so a
stalled SIEM webhook cannot block flow delivery. A single shared FIFO would let
one degraded sink back up the other.

**Auth failures are terminal.** A 401/403 is never retried — retrying a bad key
just fills the queue with entries that can never succeed. 429 and 5xx are
retried with exponential backoff.

**Rotation is handled by inode, not truncate.** The provided logrotate fragment
uses rename-then-create and signals Suricata with `HUP`, so Suricata reopens the
log and the new file has a new inode. The shipper follows the inode change and
reads the new file from the start. Do not add `copytruncate`: an in-place
truncation keeps the inode, so the shipper only notices while the file is still
shorter than its last read position, and records written before it regrows past
that point are silently skipped.

**Partial lines are never skipped.** The read offset only advances past
newline-terminated records, so a record Suricata is still writing is re-read
next cycle and a crash cannot cause a skipped record.

---

## Install

### 1. The sensor

Install Suricata on Debian/Ubuntu and configure capture for the actual sensor
interface. This project does not guess the interface or replace the distro's
full Suricata configuration:

```bash
sudo apt-get install -y suricata
```

Merge [`deploy/suricata-eve.yaml.example`](deploy/suricata-eve.yaml.example)
under `outputs:` in `/etc/suricata/suricata.yaml`. Tune `af-packet` for the
interface and set `HOME_NET`/rules for your network.

Verify Suricata before proceeding:

```bash
sudo suricata -T -c /etc/suricata/suricata.yaml    # config test
sudo systemctl restart suricata
tail -f /var/log/suricata/eve.json
```

### 2. Discover and onboard the host

From a checkout of this standalone project, run a read-only inventory first:

```bash
sudo ./deploy/onboard.sh --check
```

It reports the OS, default interface, local addresses, Suricata/EVE state,
Python/systemd availability, and optional SOC endpoint reachability. It never
prints credentials or changes the host in check mode.
The detected interface is used to identify host IPs for flow byte direction;
it does not modify Suricata capture settings. If needed, override detection with
`SURICATA_INTERFACE` and configure `af-packet` in Suricata separately.

After this project is published, a remote host can run the same check without a
ThreatPulse checkout:

```bash
curl -fsSL https://raw.githubusercontent.com/glopez21/suricata-shipper/main/deploy/bootstrap.sh \
  | sudo bash -s -- --check
```

For an interactive install, run this one command. The script prompts for the
flow URL and reads the flow key without echoing it; alert ingestion is optional.
It then installs the shipper, generates `/etc/suricata-shipper.env`, tests each
configured sink, and starts the service only if tests pass:

```bash
curl -fsSL https://raw.githubusercontent.com/glopez21/suricata-shipper/main/deploy/bootstrap.sh \
  | sudo bash -s -- --install
```

For unattended rollout, provide the `EVE_SHIPPER_*` variables via a secret
manager and preserve only those variables through `sudo`. Pin a release archive
with `SURICATA_SHIPPER_REF=<tag>` and `SURICATA_SHIPPER_REF_KIND=tags` rather
than tracking `main` in production.

The shipper is standalone: the sensor host needs this project, Suricata, and
Python 3.11+, not a ThreatPulse source checkout. For an alert API key instead of
HMAC, set `EVE_SHIPPER_ALERT_API_KEY` and omit the webhook secret.

### 3. ThreatPulse side

On the ThreatPulse host, generate a key and add it to `.env`:

```bash
openssl rand -base64 32
```

```env
# Label must match EVE_SHIPPER_SOURCE on the monitored host.
NETWORK_MONITOR_INGEST_KEYS=akamai-web-01:<the-generated-secret>
MAX_FLOWS_PER_REQUEST=500

# Alerts: choose HMAC or API key authentication.
WEBHOOK_SECRET=<separate-generated-secret>
# alternatively:
SIEM_INGEST_API_KEYS=akamai-web-01:<another-generated-secret>
```

Then restart the service:

```bash
docker compose up -d --force-recreate --no-deps network-monitor siem-app
```

Ingest is **closed by default**: with no keys configured, the endpoint returns
503 rather than accepting writes from anyone.

### 4. Manual shipper setup

`onboard.sh --install` is the recommended path. For manual setup, run
`install.sh`, edit `/etc/suricata-shipper.env`, test, and then start the unit.

Verify connectivity and auth **before** starting the daemon:

```bash
sudo -u suricata-shipper /opt/suricata-shipper/.venv/bin/suricata-shipper test \
  --config /etc/suricata-shipper.env
```

```text
     PASS flow   handled=1
     PASS alert  sent=1

All checks passed.
```

Then start it:

```bash
sudo systemctl enable --now suricata-shipper
journalctl -u suricata-shipper -f
```

---

## Configuration

All settings live in `/etc/suricata-shipper.env` (mode 0640, group-readable by
the service user). Env prefix is `EVE_SHIPPER_`.

| Variable | Default | Notes |
|---|---|---|
| `EVE_SHIPPER_SOURCE` | hostname | Must match the label in `NETWORK_MONITOR_INGEST_KEYS` |
| `EVE_SHIPPER_FLOW_URL` | `http://.../api/network/api/v1/traffic/ingest/batch` | Via nginx |
| `EVE_SHIPPER_ALERT_URL` | `http://.../api/siem/api/v1/webhooks` | Via Traefik |
| `EVE_SHIPPER_FLOW_API_KEY` | — | Required for the flow sink |
| `EVE_SHIPPER_ALERT_API_KEY` | — | siem-app `SIEM_INGEST_API_KEYS`, for `X-API-Key` |
| `EVE_SHIPPER_LOCAL_ADDRESSES` | `[]` | Explicit list, e.g. `["10.0.0.5"]` |
| `EVE_SHIPPER_AUTO_DETECT_ADDRESSES` | `true` | Adds the host's outbound addresses |
| `EVE_SHIPPER_INTERVAL` | `10` | Seconds between cycles |
| `EVE_SHIPPER_FLOW_BATCH_SIZE` | `250` | Keep ≤ server `MAX_FLOWS_PER_REQUEST` |
| `EVE_SHIPPER_TLS_VERIFY` | `true` | Do not disable outside a lab |

Setting **only** `EVE_SHIPPER_FLOW_API_KEY` ships flows and no alerts — useful
for a first rollout. For alerts, either `EVE_SHIPPER_ALERT_WEBHOOK_SECRET` (HMAC)
or `EVE_SHIPPER_ALERT_API_KEY` is required; HMAC is preferred.

---

## Operations

```bash
suricata-shipper status     # queue depth per sink, dead letters, read offset
suricata-shipper version
```

If the queue grows without bound, ThreatPulse is unreachable. `status` shows
the depth split by sink, which tells you which side to fix. A `503` from the
ingest endpoint means `INGEST_API_KEYS` is unset **server-side** — the key on
this host is fine, the server is closed.

### Key rotation

1. Add the new `label:secret` to `NETWORK_MONITOR_INGEST_KEYS` (both keys valid).
2. Restart network-monitor.
3. Update `EVE_SHIPPER_FLOW_API_KEY` on the collector, `systemctl restart`.
4. Remove the old key, restart network-monitor.

### Uninstall

```bash
sudo systemctl disable --now suricata-shipper
sudo rm -f /etc/systemd/system/suricata-shipper.service /etc/suricata-shipper.env
sudo rm -rf /opt/suricata-shipper /var/lib/suricata-shipper
sudo userdel suricata-shipper
sudo systemctl daemon-reload
```

---

## Development

```bash
pip install -e '.[dev]'
pytest -q
ruff check src tests
```

The SQLite queue is self-contained and migrates databases created by the
monorepo-hosted shipper in place, preserving queued telemetry during upgrades.

### Testing

`test` sends one synthetic flow and one synthetic alert, so it verifies DNS,
TLS, routing, and auth in one shot. A `FAIL` line names the sink, which is the
first thing to check.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `503` from ingest | `INGEST_API_KEYS` unset on the ThreatPulse host |
| `401` in `test` | Key mismatch, or the label/source pairing is wrong |
| Flows present, byte counts look inverted | Wrong `LOCAL_ADDRESSES`, or auto-detect picked the wrong address |
| Queue depth climbing | ThreatPulse unreachable — check `status` for which sink |
| `No local addresses detected` | Auto-detect failed; set the list explicitly |
| Nothing after Suricata restart | Shipper needs a restart too if the inode changed while it was down — it re-detects on next cycle, but `status` confirms the offset moved |
