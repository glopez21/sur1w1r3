"""Tests for queue routing, the ship loop, and HTTP client behaviour.

These use fake clients and real SQLite queue files, so they exercise the
retry/ack accounting that decides whether telemetry is delivered exactly once
without needing ThreatPulse running.
"""

from __future__ import annotations

import json
import sqlite3

import pytest

from suricata_shipper.config import ShipperConfig
from suricata_shipper.queue import ShipQueue
from suricata_shipper.shipper import SuricataShipper


@pytest.fixture
def config(tmp_path) -> ShipperConfig:
    return ShipperConfig(
        eve_path=str(tmp_path / "eve.json"),
        state_path=str(tmp_path / "state.json"),
        auto_detect_addresses=False,
        local_addresses=["10.0.0.5"],
        flow_api_key="test-flow-key",
        alert_api_key="test-alert-key",
        max_batches_per_cycle=3,
    )


def _shipper(config, skip_existing=False) -> SuricataShipper:
    return SuricataShipper(config, skip_existing=skip_existing)


def _write_eve(path, records):
    with open(path, "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _flow_record(**overrides):
    flow = {
        "event_type": "flow",
        "flow": {
            "src_ip": "10.0.0.5",
            "src_port": 51514,
            "dest_ip": "93.184.216.34",
            "dest_port": 443,
            "proto": "tcp",
            "state": "established",
            "start": "2026-09-29T10:00:00+00:00",
            "bytes_toserver": 100,
            "bytes_toclient": 200,
        },
    }
    flow.update(overrides)
    return flow


def _alert_record():
    return {
        "event_type": "alert",
        "alert": {
            "signature": "test signature",
            "signature_id": 1,
            "category": "test",
            "severity": 2,
            "src_ip": "203.0.113.5",
            "dest_ip": "10.0.0.5",
            "dest_port": 22,
            "timestamp": "2026-09-29T10:00:00+00:00",
        },
    }


class _FakeClient:
    """Records what it was asked to send and returns a scripted result."""

    def __init__(self, result=(1, "")):
        self.result = result
        self.batches: list[list] = []

    async def send(self, items):
        self.batches.append(list(items))
        accepted = min(self.result[0], len(items))
        return accepted, self.result[1]


# --- queue routing -----------------------------------------------------------


def test_queue_keeps_flows_and_alerts_separate(tmp_path):
    queue = ShipQueue(tmp_path / "q.db")
    try:
        queue.put_flows([{"source_ip": "10.0.0.5"}])
        queue.put_alerts([{"message": "alert"}])

        depths = queue.depth_by_kind()

        assert depths == {"flow": 1, "alert": 1}
    finally:
        queue.close()


def test_claim_only_returns_the_requested_kind(tmp_path):
    queue = ShipQueue(tmp_path / "q.db")
    try:
        queue.put_flows([{"n": 1}, {"n": 2}])
        queue.put_alerts([{"n": 3}])

        claimed = queue.claim("flow", batch_size=10)

        assert len(claimed) == 2
        assert all(e["payload"]["kind"] == "flow" for e in claimed)
    finally:
        queue.close()


def test_unclaimed_entries_are_released_and_still_deliverable(tmp_path):
    """A non-matching kind must be restorable, not burned as a retry."""
    queue = ShipQueue(tmp_path / "q.db")
    try:
        queue.put_flows([{"n": 1}])
        queue.put_alerts([{"n": 2}])

        assert len(queue.claim("flow", batch_size=10)) == 1

        # The alert was claimed and returned in the same pass; it must survive.
        assert len(queue.claim("alert", batch_size=10)) == 1
    finally:
        queue.close()


def test_ack_removes_entries_and_fail_retains_them(tmp_path):
    queue = ShipQueue(tmp_path / "q.db")
    try:
        queue.put_flows([{"n": 1}, {"n": 2}])
        claimed = queue.claim("flow", batch_size=10)

        queue.ack([claimed[0]["id"]])
        queue.fail([(claimed[1]["id"], "network down")])

        remaining = queue.claim("flow", batch_size=10)
        assert len(remaining) == 1
        assert remaining[0]["payload"]["data"] == {"n": 2}
    finally:
        queue.close()


def test_entries_survive_reopening_the_queue_file(tmp_path):
    path = tmp_path / "q.db"
    queue = ShipQueue(path)
    queue.put_flows([{"n": 1}])
    queue.close()

    reopened = ShipQueue(path)
    try:
        assert reopened.depth() == 1
    finally:
        reopened.close()


def test_queue_files_are_private_to_the_service_user(tmp_path):
    path = tmp_path / "private.db"
    queue = ShipQueue(path)
    try:
        assert path.stat().st_mode & 0o777 == 0o600
    finally:
        queue.close()


def test_migrates_existing_threatpulse_agent_queue_in_place(tmp_path):
    """Standalone upgrades preserve entries created by the monorepo version."""
    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript(
        """CREATE TABLE entries (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            payload TEXT NOT NULL,
            created_at REAL NOT NULL,
            retries INTEGER DEFAULT 0,
            last_error TEXT,
            locked_at REAL,
            locked_by TEXT
        );"""
    )
    conn.execute(
        "INSERT INTO entries (payload, created_at) VALUES (?, ?)",
        (json.dumps({"kind": "flow", "data": {"source_ip": "10.0.0.5"}}), 1.0),
    )
    conn.commit()
    conn.close()

    queue = ShipQueue(path)
    try:
        assert queue.depth_by_kind() == {"flow": 1}
        claimed = queue.claim("flow", batch_size=10)
        assert len(claimed) == 1
        assert claimed[0]["payload"]["data"] == {"source_ip": "10.0.0.5"}
    finally:
        queue.close()


def test_failed_entries_become_dead_letters_after_retry_limit(tmp_path):
    queue = ShipQueue(tmp_path / "q.db", max_retries=2)
    try:
        queue.put_flows([{"n": 1}])
        first = queue.claim("flow", batch_size=1)
        queue.fail([(first[0]["id"], "first failure")])
        assert queue.depth() == 1

        second = queue.claim("flow", batch_size=1)
        queue.fail([(second[0]["id"], "second failure")])

        assert queue.depth() == 0
        assert queue.dead_letters() == 1
        assert queue.claim("flow", batch_size=1) == []
    finally:
        queue.close()


# --- ship loop ---------------------------------------------------------------


async def test_cycle_ships_new_records_to_both_sinks(config):
    _write_eve(config.eve_path, [_flow_record(), _alert_record()])
    shipper = _shipper(config)
    flow_client = _FakeClient((1, ""))
    alert_client = _FakeClient((1, ""))

    try:
        await shipper.cycle(flow_client, alert_client)
    finally:
        shipper.queue.close()

    assert len(flow_client.batches) == 1
    assert len(alert_client.batches) == 1
    assert flow_client.batches[0][0]["destination_ip"] == "93.184.216.34"
    assert alert_client.batches[0][0]["level"] == "high"


async def test_queued_records_are_delivered_on_a_later_cycle(config):
    """A record read while ThreatPulse was down is not lost."""
    _write_eve(config.eve_path, [_flow_record()])
    shipper = _shipper(config)
    failing = _FakeClient((0, "connection error"))

    try:
        await shipper.cycle(failing, None)
        assert shipper.queue.depth() > 0

        recovered = _FakeClient((1, ""))
        await shipper.cycle(recovered, None)

        assert len(recovered.batches) == 1
        assert shipper.queue.depth() == 0
    finally:
        shipper.queue.close()


async def test_a_failing_alert_sink_does_not_block_flow_delivery(config):
    _write_eve(config.eve_path, [_flow_record(), _alert_record()])
    shipper = _shipper(config)
    flow_client = _FakeClient((1, ""))
    alert_client = _FakeClient((0, "siem webhook down"))

    try:
        await shipper.cycle(flow_client, alert_client)

        assert len(flow_client.batches) == 1
        assert shipper.queue.depth_by_kind()["alert"] == 1
    finally:
        shipper.queue.close()


async def test_records_are_not_reshipped_after_successful_delivery(config):
    _write_eve(config.eve_path, [_flow_record()])
    shipper = _shipper(config)
    flow_client = _FakeClient((1, ""))

    try:
        await shipper.cycle(flow_client, None)
        batches_after_first = len(flow_client.batches)

        await shipper.cycle(flow_client, None)
    finally:
        shipper.queue.close()

    assert len(flow_client.batches) == batches_after_first


async def test_position_persists_after_a_cycle(config):
    _write_eve(config.eve_path, [_flow_record(), _flow_record()])
    shipper = _shipper(config)

    try:
        await shipper.cycle(_FakeClient((1, "")), None)
    finally:
        shipper.queue.close()

    assert _read_position(config)[0] > 0


def _read_position(config) -> tuple[int, int | None]:
    from suricata_shipper.queue import PositionStore

    return PositionStore(config.state_path).load()


async def test_no_sink_configured_raises(config):
    bare = ShipperConfig(
        eve_path=config.eve_path,
        state_path=config.state_path,
        auto_detect_addresses=False,
        flow_api_key="",
        alert_api_key="",
        alert_webhook_secret="",
    )
    shipper = _shipper(bare)
    try:
        with pytest.raises(SystemExit):
            await shipper.run_forever()
    finally:
        shipper.queue.close()


# --- config ------------------------------------------------------------------


def test_enabled_targets_requires_a_credential(tmp_path):
    config = ShipperConfig(
        eve_path=str(tmp_path / "eve.json"),
        state_path=str(tmp_path / "state.json"),
        flow_url="http://example/flow",
        flow_api_key="",
        alert_url="http://example/alert",
        alert_api_key="",
        alert_webhook_secret="",
    )

    assert config.enabled_targets == ()


def test_enabled_targets_lists_configured_sinks(tmp_path):
    config = ShipperConfig(
        eve_path=str(tmp_path / "eve.json"),
        state_path=str(tmp_path / "state.json"),
        flow_api_key="k",
        alert_api_key="k",
    )

    assert set(config.enabled_targets) == {"flow", "alert"}


def test_alert_target_accepts_a_webhook_secret_without_an_api_key(tmp_path):
    config = ShipperConfig(
        eve_path=str(tmp_path / "eve.json"),
        state_path=str(tmp_path / "state.json"),
        flow_api_key="",
        alert_api_key="",
        alert_webhook_secret="s",
    )

    assert config.enabled_targets == ("alert",)


def test_source_defaults_to_hostname(tmp_path):
    import socket

    config = ShipperConfig(
        eve_path=str(tmp_path / "eve.json"), state_path=str(tmp_path / "state.json")
    )

    assert config.source == socket.gethostname()
