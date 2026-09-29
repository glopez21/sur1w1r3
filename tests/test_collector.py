"""Tests for the EVE reader's rotation and offset handling.

Losing telemetry to a botched restart or a Suricata logrotate cycle is the
failure mode that matters here, so rotation detection, partial-line buffering,
and position persistence are all pinned by tests.
"""

from __future__ import annotations

import json
import os

from suricata_shipper.collector import EveCollector, EveReader, EveStats
from suricata_shipper.config import ShipperConfig
from suricata_shipper.queue import PositionStore


def _config(tmp_path, **overrides) -> ShipperConfig:
    base = {
        "eve_path": str(tmp_path / "eve.json"),
        "state_path": str(tmp_path / "state.json"),
        "auto_detect_addresses": False,
        "local_addresses": ["10.0.0.5"],
    }
    base.update(overrides)
    return ShipperConfig(**base)


def _write_eve(path, records):
    with open(path, "a", encoding="utf-8") as handle:
        for record in records:
            handle.write(json.dumps(record) + "\n")


def _flow_record(**overrides):
    """A real Suricata EVE flow event.

    Suricata keeps 5-tuple addressing at the top level and puts only the
    counters and lifecycle metadata in the nested ``flow`` object. Fixtures that
    nest the addresses hide wiring bugs, so this mirrors ``eve.json`` exactly.
    """
    record = {
        "timestamp": "2026-09-29T10:00:30+00:00",
        "flow_id": 1234567890,
        "event_type": "flow",
        "src_ip": "10.0.0.5",
        "src_port": 51514,
        "dest_ip": "93.184.216.34",
        "dest_port": 443,
        "proto": "TCP",
        "flow": {
            "pkts_toserver": 10,
            "pkts_toclient": 20,
            "bytes_toserver": 100,
            "bytes_toclient": 200,
            "start": "2026-09-29T10:00:00+00:00",
            "end": "2026-09-29T10:00:30+00:00",
            "state": "established",
            "reason": "established",
        },
    }
    record.update(overrides)
    return record


def _alert_record(**overrides):
    """A real Suricata EVE alert event: addressing top level, details nested."""
    record = {
        "timestamp": "2026-09-29T10:00:00+00:00",
        "flow_id": 1234567890,
        "event_type": "alert",
        "src_ip": "203.0.113.5",
        "src_port": 41000,
        "dest_ip": "10.0.0.5",
        "dest_port": 22,
        "proto": "TCP",
        "alert": {
            "action": "allowed",
            "gid": 1,
            "signature_id": 1,
            "rev": 3,
            "signature": "test signature",
            "category": "test",
            "severity": 2,
            "metadata": {"affected_product": {"product": "generic"}},
        },
    }
    record.update(overrides)
    return record


# --- incremental reading -----------------------------------------------------


def test_reads_records_from_a_fresh_file(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record(), _alert_record()])
    reader = EveReader(config)

    records = list(reader.read_new_records())

    assert len(records) == 2
    assert [r["event_type"] for r in records] == ["flow", "alert"]


def test_second_read_does_not_reprocess_the_same_records(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record()])
    reader = EveReader(config)

    assert len(list(reader.read_new_records())) == 1
    assert list(reader.read_new_records()) == []


def test_appended_records_are_read_next_cycle(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record()])
    reader = EveReader(config)
    list(reader.read_new_records())

    _write_eve(config.eve_path, [_flow_record(), _flow_record()])
    records = list(reader.read_new_records())

    assert len(records) == 2


def test_partial_line_is_held_until_complete(tmp_path):
    config = _config(tmp_path)
    record = json.dumps(_flow_record())
    with open(config.eve_path, "w", encoding="utf-8") as handle:
        handle.write(record[: len(record) // 2])
    reader = EveReader(config)

    assert list(reader.read_new_records()) == []

    with open(config.eve_path, "a", encoding="utf-8") as handle:
        handle.write(record[len(record) // 2 :] + "\n")

    assert len(list(reader.read_new_records())) == 1


# --- rotation ----------------------------------------------------------------


def test_truncation_restarts_from_the_beginning(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record()])
    reader = EveReader(config)
    list(reader.read_new_records())

    # logrotate: same inode, file truncated and rewritten.
    with open(config.eve_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(_alert_record()) + "\n")

    records = list(reader.read_new_records())

    assert len(records) == 1
    assert records[0]["event_type"] == "alert"


def test_inode_change_restarts_from_the_beginning(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record()])
    reader = EveReader(config)
    list(reader.read_new_records())

    # logrotate with rename+create: a new file, so a new inode, offset 0.
    rotated = config.eve_path + ".1"
    os.rename(config.eve_path, rotated)
    _write_eve(config.eve_path, [_alert_record()])

    records = list(reader.read_new_records())

    assert len(records) == 1
    assert records[0]["event_type"] == "alert"


def test_missing_file_does_not_raise(tmp_path):
    config = _config(tmp_path)
    reader = EveReader(config)

    assert list(reader.read_new_records()) == []


def test_file_appearing_later_is_picked_up(tmp_path):
    config = _config(tmp_path)
    reader = EveReader(config)
    list(reader.read_new_records())

    _write_eve(config.eve_path, [_flow_record()])

    assert len(list(reader.read_new_records())) == 1


def test_oversized_unterminated_line_is_skipped_not_re_read_forever(tmp_path):
    """A corrupt line with no newline must be dropped, not retried each cycle."""
    config = _config(tmp_path, max_line_bytes=1000)
    with open(config.eve_path, "w", encoding="utf-8") as handle:
        handle.write("x" * 5000)
    reader = EveReader(config)

    assert list(reader.read_new_records()) == []
    assert list(reader.read_new_records()) == []


def test_oversized_line_terminated_by_newline_is_parsed_normally(tmp_path):
    """The cap targets unterminated junk, not merely long records."""
    config = _config(tmp_path, max_line_bytes=1000)
    record = _flow_record()
    record["flow"]["padding"] = "x" * 5000
    with open(config.eve_path, "w", encoding="utf-8") as handle:
        handle.write(json.dumps(record) + "\n")
    reader = EveReader(config)

    records = list(reader.read_new_records())

    assert len(records) == 1
    assert records[0]["event_type"] == "flow"


def test_a_partial_line_is_not_lost_across_a_restart(tmp_path):
    """The offset must not advance past a record Suricata has not finished writing."""
    config = _config(tmp_path)
    record = json.dumps(_flow_record())
    with open(config.eve_path, "w", encoding="utf-8") as handle:
        handle.write(record[: len(record) // 2])
    reader = EveReader(config)

    assert list(reader.read_new_records()) == []
    saved_offset, saved_inode = reader.position()

    # Simulate a restart from the persisted position.
    resumed = EveReader(config)
    resumed.load_position(saved_offset, saved_inode)

    with open(config.eve_path, "a", encoding="utf-8") as handle:
        handle.write(record[len(record) // 2 :] + "\n")

    records = list(resumed.read_new_records())

    assert len(records) == 1
    assert records[0]["event_type"] == "flow"


# --- position persistence ----------------------------------------------------


def test_position_round_trips(tmp_path):
    store = PositionStore(tmp_path / "state.json")
    store.save(4096, 12345)

    offset, inode = PositionStore(tmp_path / "state.json").load()

    assert offset == 4096
    assert inode == 12345


def test_missing_position_file_starts_at_zero(tmp_path):
    assert PositionStore(tmp_path / "absent.json").load() == (0, None)


def test_corrupt_position_file_starts_at_zero(tmp_path):
    path = tmp_path / "state.json"
    path.write_text("not json")

    assert PositionStore(path).load() == (0, None)


def test_resuming_from_a_saved_position(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record(), _alert_record()])

    store = PositionStore(config.state_path)
    reader = EveReader(config)
    list(reader.read_new_records())
    offset, inode = reader.position()
    store.save(offset, inode)

    _write_eve(config.eve_path, [_flow_record()])
    resumed = EveReader(config)
    resumed.load_position(*store.load())

    records = list(resumed.read_new_records())

    assert len(records) == 1


def test_position_save_is_atomic(tmp_path):
    path = tmp_path / "state.json"
    PositionStore(path).save(10, 1)
    # No leftover temp file from the write-then-rename.
    assert not (tmp_path / "state.tmp").exists()
    assert json.loads(path.read_text())["offset"] == 10


def test_skip_existing_starts_at_end_of_file(tmp_path):
    config = _config(tmp_path)
    _write_eve(config.eve_path, [_flow_record(), _flow_record()])
    reader = EveReader(config)

    reader.seek_to_end()

    assert list(reader.read_new_records()) == []


# --- collector ---------------------------------------------------------------


def test_collector_routes_flows_and_alerts_separately(tmp_path):
    config = _config(tmp_path)
    collector = EveCollector(config, EveStats())

    flows, alerts = collector.convert(_flow_record())
    assert len(flows) == 1 and not alerts

    flows, alerts = collector.convert(_alert_record())
    assert not flows and len(alerts) == 1


def test_collector_drops_unsupported_event_types(tmp_path):
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    flows, alerts = collector.convert({"event_type": "dns", "dns": {}})

    assert not flows and not alerts
    assert stats.skipped_type == 1


def test_collector_drops_noise_flows(tmp_path):
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    flows, _ = collector.convert(_flow_record(flow={"reason": "internal", "proto": "tcp"}))

    assert not flows
    assert stats.noise_flows == 1


def test_collector_counts_malformed_records(tmp_path):
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    # No 5-tuple at all, which is what a malformed flow event looks like.
    incomplete = _flow_record()
    del incomplete["src_ip"]
    del incomplete["dest_ip"]
    flows, _ = collector.convert(incomplete)

    assert not flows
    assert stats.malformed == 1


def test_collector_merges_top_level_addressing_with_nested_counters(tmp_path):
    """Regression: Suricata splits one event across two levels.

    Addressing lives at the top level while the counters live in the nested
    ``flow`` object. Passing only the nested object silently dropped every real
    flow event as malformed, so both halves must be merged.
    """
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    flows, _ = collector.convert(_flow_record())

    assert stats.malformed == 0
    assert len(flows) == 1
    flow = flows[0]
    assert flow["source_ip"] == "10.0.0.5"
    assert flow["destination_ip"] == "93.184.216.34"
    assert flow["source_port"] == 51514
    assert flow["destination_port"] == 443
    assert flow["protocol"] == "tcp"
    # Counters come from the nested half, start_time from the nested half too.
    assert flow["bytes_out"] == 100
    assert flow["bytes_in"] == 200
    assert flow["packets_out"] == 10
    assert flow["packets_in"] == 20
    assert flow["start_time"] == "2026-09-29T10:00:00+00:00"
    assert flow["end_time"] == "2026-09-29T10:00:30+00:00"


def test_collector_attributes_alert_to_top_level_attacker_ip(tmp_path):
    """Regression: alert addressing is top level, not inside the alert object.

    Reading ``src_ip`` from the nested object yielded ``unknown`` and lost the
    attacker address that siem-app uses to correlate the alert with flows.
    """
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    _, alerts = collector.convert(_alert_record())

    assert len(alerts) == 1
    assert alerts[0]["ip_address"] == "203.0.113.5"
    assert alerts[0]["level"] == "high"
    assert alerts[0]["source"] == config.source


def test_collector_accepts_nested_addressing_for_forward_compatibility(tmp_path):
    """A build that nests the 5-tuple should still convert rather than drop."""
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    record = {"event_type": "flow", "flow": {"src_ip": "10.0.0.5", "dest_ip": "8.8.8.8"}}
    flows, _ = collector.convert(record)

    assert stats.malformed == 0
    assert flows[0]["source_ip"] == "10.0.0.5"
    assert flows[0]["destination_ip"] == "8.8.8.8"


def test_collector_uses_configured_local_addresses(tmp_path):
    config = _config(tmp_path)
    stats = EveStats()
    collector = EveCollector(config, stats)

    flows, _ = collector.convert(_flow_record())

    assert flows[0]["bytes_out"] == 100
    assert flows[0]["bytes_in"] == 200


def test_stats_render_all_counters(tmp_path):
    stats = EveStats()
    stats.read = 5
    stats.flows = 3
    stats.alerts = 2

    rendered = str(stats)

    assert "read=5" in rendered
    assert "flows=3" in rendered
    assert "alerts=2" in rendered
