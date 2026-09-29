"""Configuration for suricata-shipper.

Uses pydantic-settings with an ``EVE_SHIPPER_`` env prefix, ``.env`` file
support, and hostname-derived defaults so a minimal deploy needs little config.
"""

from pathlib import Path
from typing import Literal

from pydantic_settings import BaseSettings, SettingsConfigDict


class ShipperConfig(BaseSettings):
    model_config = SettingsConfigDict(
        env_prefix="EVE_SHIPPER_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- ThreatPulse endpoints -------------------------------------------------
    # network-monitor serves flow ingest; siem-app serves alert ingest. Both are
    # typically reached through Traefik under /api/network and /api/siem.
    flow_url: str = "http://threatpulse.local/api/network/api/v1/traffic/ingest/batch"
    alert_url: str = "http://threatpulse.local/api/siem/api/v1/webhooks"

    # API key matching a "label:secret" entry in the server's INGEST_API_KEYS.
    # Sent as X-API-Key. Rotate by adding a new key server-side, redeploying the
    # collector, then removing the old key.
    flow_api_key: str = ""
    alert_api_key: str = ""
    alert_webhook_secret: str = ""

    # --- Local collection ------------------------------------------------------
    eve_path: str = "/var/log/suricata/eve.json"
    # Offset persisted so a restart does not re-ship the whole file.
    state_path: str = "/var/lib/suricata-shipper/state.json"
    source: str = ""

    # Addresses treated as local when orienting flow byte counters. Left empty,
    # the shipper auto-detects the host's outbound addresses.
    local_addresses: list[str] = []
    auto_detect_addresses: bool = True

    # --- Ship loop -------------------------------------------------------------
    interval: float = 10.0
    flow_batch_size: int = 250
    alert_batch_size: int = 100
    max_batches_per_cycle: int = 20
    read_poll_seconds: float = 0.25
    max_line_bytes: int = 1_000_000

    # --- Delivery --------------------------------------------------------------
    tls_verify: bool = True
    timeout: float = 30.0
    max_retries: int = 5
    queue_max_depth: int = 500_000
    # Set true only to see every record the shipper drops.
    debug_events: bool = False

    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = "INFO"

    def model_post_init(self, __context) -> None:
        if not self.source:
            import socket

            self.source = socket.gethostname()
        self.eve_path = str(Path(self.eve_path).resolve())
        self.state_path = str(Path(self.state_path).resolve())

    @property
    def enabled_targets(self) -> tuple[str, ...]:
        """Which sinks are configured, so unconfigured ones are skipped cleanly."""
        targets = []
        if self.flow_url and self.flow_api_key:
            targets.append("flow")
        if self.alert_url and (self.alert_api_key or self.alert_webhook_secret):
            targets.append("alert")
        return tuple(targets)
