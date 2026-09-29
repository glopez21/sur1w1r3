"""The shipper main loop: read EVE, buffer, deliver, persist position.

Each cycle is independent and idempotent, so a crash at any point loses at most
the current batch:

1. Read new EVE records, convert them, enqueue flows and alerts separately.
2. Persist the read offset — only after the payloads are durably queued, so a
   crash re-reads rather than skips.
3. Drain the queue, claiming one kind at a time so a failing sink cannot block
   the other.
4. Advance the offset again once delivery has settled.
"""

from __future__ import annotations

import asyncio
import logging
import signal
from pathlib import Path

from suricata_shipper.client import AlertClient, FlowClient
from suricata_shipper.collector import EveCollector, EveReader, EveStats
from suricata_shipper.config import ShipperConfig
from suricata_shipper.queue import PositionStore, ShipQueue

logger = logging.getLogger(__name__)


def _format_delta(delta: dict[str, int]) -> str:
    """Render a per-cycle counter delta, omitting counters that did not move."""
    return ", ".join(f"{k}={v}" for k, v in delta.items() if v)


class SuricataShipper:
    def __init__(self, config: ShipperConfig, skip_existing: bool = False):
        self.config = config
        self.stats = EveStats()
        self.reader = EveReader(config)
        self.collector = EveCollector(config, self.stats)
        self.queue = ShipQueue(Path(config.state_path).with_suffix(".queue.db"), config.max_retries)
        self.position = PositionStore(config.state_path)
        self._running = False

        offset, inode = self.position.load()
        if skip_existing:
            self.reader.seek_to_end()
        else:
            self.reader.load_position(offset, inode)
            if offset:
                logger.info("Resuming EVE read at offset %d (inode %s)", offset, inode)

    # --- lifecycle ------------------------------------------------------------

    def stop(self) -> None:
        self._running = False

    async def run_forever(self) -> None:
        targets = self.config.enabled_targets
        if not targets:
            raise SystemExit(
                "No sink configured. Set EVE_SHIPPER_FLOW_API_KEY (and/or "
                "EVE_SHIPPER_ALERT_API_KEY / EVE_SHIPPER_ALERT_WEBHOOK_SECRET)."
            )

        flow_client = (
            FlowClient(
                self.config.flow_url,
                self.config.flow_api_key,
                self.config.source,
                self.config.tls_verify,
                self.config.timeout,
            )
            if "flow" in targets
            else None
        )
        alert_client = (
            AlertClient(
                self.config.alert_url,
                self.config.alert_api_key,
                self.config.alert_webhook_secret,
                self.config.tls_verify,
                self.config.timeout,
            )
            if "alert" in targets
            else None
        )

        self._running = True
        logger.info(
            "Sur1W1r3 started: source=%s targets=%s eve=%s",
            self.config.source,
            ",".join(targets),
            self.config.eve_path,
        )

        try:
            while self._running:
                await self.cycle(flow_client, alert_client)
                if self._running:
                    await asyncio.sleep(self.config.interval)
        finally:
            self._persist_position()
            self.queue.checkpoint()
            self.queue.close()
            if flow_client:
                await flow_client.close()
            if alert_client:
                await alert_client.close()
            logger.info("Sur1W1r3 stopped")

    # --- one cycle ------------------------------------------------------------

    async def cycle(self, flow_client: FlowClient | None, alert_client: AlertClient | None) -> None:
        await self.ingest_new_records()
        if flow_client:
            await self.drain_flows(flow_client)
        if alert_client:
            await self.drain_alerts(alert_client)
        self.queue.sweep(stale_seconds=300.0, max_depth=self.config.queue_max_depth)
        # Persist per cycle rather than only on shutdown, so a kill -9 costs at
        # most the current cycle and the offset never lags the queue.
        self._persist_position()

    async def ingest_new_records(self) -> None:
        flows: list[dict] = []
        alerts: list[dict] = []
        before = self.stats.as_dict()

        for record in self.reader.read_new_records():
            new_flows, new_alerts = self.collector.convert(record)
            flows.extend(new_flows)
            alerts.extend(new_alerts)

            # Enqueue in slices so a burst does not build one oversized batch.
            if len(flows) >= self.config.flow_batch_size:
                self.queue.put_flows(flows)
                flows = []
            if len(alerts) >= self.config.alert_batch_size:
                self.queue.put_alerts(alerts)
                alerts = []

        if flows:
            self.queue.put_flows(flows)
        if alerts:
            self.queue.put_alerts(alerts)

        # Log the delta for this cycle. EveStats is cumulative by design so a
        # long-running shipper still has lifetime totals, which means logging it
        # directly would re-report every earlier cycle's numbers each time.
        delta = {k: v - before[k] for k, v in self.stats.as_dict().items()}
        self.stats.bytes_consumed = self.reader.bytes_consumed
        if delta["read"] or delta["bytes_consumed"]:
            logger.info("Read %d EVE records (%s)", delta["read"], _format_delta(delta))

    def totals(self) -> dict[str, int]:
        """Lifetime counters, for status output and shutdown logging."""
        self.stats.bytes_consumed = self.reader.bytes_consumed
        return self.stats.as_dict()

    async def drain_flows(self, client: FlowClient) -> None:
        for _ in range(self.config.max_batches_per_cycle):
            batch = self.queue.claim("flow", self.config.flow_batch_size)
            if not batch:
                return

            handled, error = await client.send([b["payload"]["data"] for b in batch])
            if not handled:
                # send is all-or-nothing, so a falsy count means nothing landed.
                self.queue.fail([(b["id"], error) for b in batch])
                logger.warning("Flow batch stalled: %d undelivered (%s)", len(batch), error)
                return

            if handled != len(batch):
                # Guard against silently acking a wrong subset if the client's
                # contract ever regresses to a partial count.
                self.queue.fail([(b["id"], error) for b in batch])
                logger.error(
                    "Flow client reported %d of %d handled; requeueing whole batch",
                    handled,
                    len(batch),
                )
                return

            self.queue.ack([b["id"] for b in batch])

    async def drain_alerts(self, client: AlertClient) -> None:
        for _ in range(self.config.max_batches_per_cycle):
            batch = self.queue.claim("alert", self.config.alert_batch_size)
            if not batch:
                return

            sent, error = await client.send([b["payload"]["data"] for b in batch])
            if sent:
                self.queue.ack([b["id"] for b in batch[:sent]])
            if sent < len(batch):
                self.queue.fail([(b["id"], error) for b in batch[sent:]])
                logger.warning("Alert batch stalled: %d undelivered (%s)", len(batch) - sent, error)
                return

    def _persist_position(self) -> None:
        offset, inode = self.reader.position()
        self.position.save(offset, inode)


def setup_signal_handlers(shipper: SuricataShipper) -> None:
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, shipper.stop)
