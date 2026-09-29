"""Tests for EVE record conversion.

The byte/packet direction logic is the part most likely to be silently wrong:
Suricata reports counters from the flow originator's perspective, and getting
them backwards would invert every flow's ingress and egress in the SIEM without
raising an error. These tests pin the mapping.
"""

from __future__ import annotations

from datetime import UTC, datetime

from suricata_shipper.parsers import (
    alert_to_log_entry,
    flow_to_flow_ingest,
    is_noise_flow,
    local_address_set,
    local_is_origin,
    parse_eve_line,
)

HOST = "10.0.0.5"
REMOTE = "93.184.216.34"


def _flow(**overrides):
    flow = {
        "src_ip": HOST,
        "src_port": 51514,
        "dest_ip": REMOTE,
        "dest_port": 443,
        "proto": "tcp",
        "state": "established",
        "start": "2026-09-29T10:00:00+00:00",
        "end": "2026-09-29T10:00:30+00:00",
        "bytes_toserver": 1000,
        "bytes_toclient": 2000,
        "pkts_toserver": 10,
        "pkts_toclient": 20,
    }
    flow.update(overrides)
    return flow


# --- flow direction ----------------------------------------------------------


def test_host_as_origin_maps_toserver_to_bytes_out():
    payload = flow_to_flow_ingest(_flow(), local_address_set([HOST]))

    assert payload["bytes_out"] == 1000
    assert payload["bytes_in"] == 2000
    assert payload["packets_out"] == 10
    assert payload["packets_in"] == 20


def test_host_as_responder_maps_toserver_to_bytes_in():
    """An inbound connection has the remote as originator, so toserver is ingress."""
    flow = _flow(src_ip=REMOTE, dest_ip=HOST)

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["bytes_in"] == 1000
    assert payload["bytes_out"] == 2000
    assert payload["packets_in"] == 10
    assert payload["packets_out"] == 20


def test_flow_between_two_remote_hosts_is_reported_from_remote_perspective():
    flow = _flow(src_ip=REMOTE, dest_ip="1.1.1.1")

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    # Neither end is local, so toserver is treated as inbound by convention.
    assert payload["bytes_in"] == 1000
    assert payload["bytes_out"] == 2000


def test_no_local_addresses_does_not_raise():
    payload = flow_to_flow_ingest(_flow(), local_address_set([]))

    assert payload is not None
    assert payload["source_ip"] == HOST


def test_local_is_origin_is_exact_match_only():
    addresses = local_address_set(["10.0.0.5"])

    assert local_is_origin("10.0.0.5", addresses) is True
    assert local_is_origin("10.0.0.50", addresses) is False
    assert local_is_origin("10.0.0.5", frozenset()) is False


# --- field mapping -----------------------------------------------------------


def test_endpoints_ports_and_protocol_are_preserved():
    payload = flow_to_flow_ingest(_flow(), local_address_set([HOST]))

    assert payload["source_ip"] == HOST
    assert payload["source_port"] == 51514
    assert payload["destination_ip"] == REMOTE
    assert payload["destination_port"] == 443
    assert payload["protocol"] == "tcp"
    assert payload["flags"] == "established"


def test_duration_is_derivable_from_timestamps():
    payload = flow_to_flow_ingest(_flow(), local_address_set([HOST]))

    start = datetime.fromisoformat(payload["start_time"])
    end = datetime.fromisoformat(payload["end_time"])
    assert int((end - start).total_seconds()) == 30


def test_missing_end_time_yields_none():
    flow = _flow()
    del flow["end"]

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["end_time"] is None


def test_timestamps_are_always_timezone_aware():
    flow = _flow(start="2026-09-29T10:00:00Z", end="2026-09-29T10:00:30Z")

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert datetime.fromisoformat(payload["start_time"]).tzinfo is not None
    assert payload["start_time"].endswith("+00:00")


def test_naive_timestamp_is_assumed_utc():
    flow = _flow(start="2026-09-29T10:00:00", end="2026-09-29T10:00:30")

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["start_time"].endswith("+00:00")


def test_unparseable_timestamp_falls_back_to_now():
    flow = _flow(start="not-a-timestamp", end="also-not-a-timestamp")

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert datetime.fromisoformat(payload["start_time"]).tzinfo == UTC


def test_flow_without_addresses_is_rejected():
    assert flow_to_flow_ingest(_flow(src_ip="", dest_ip=""), local_address_set([HOST])) is None
    assert flow_to_flow_ingest({}, local_address_set([HOST])) is None


def test_missing_counters_default_to_zero():
    flow = _flow()
    for key in ("bytes_toserver", "bytes_toclient", "pkts_toserver", "pkts_toclient"):
        del flow[key]

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["bytes_in"] == 0
    assert payload["bytes_out"] == 0
    assert payload["packets_in"] == 0
    assert payload["packets_out"] == 0


def test_non_numeric_counters_are_coerced_not_crashed():
    flow = _flow(bytes_toserver="n/a", bytes_toclient=None, pkts_toserver=5.9)

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["bytes_out"] == 0
    assert payload["bytes_in"] == 0
    assert payload["packets_out"] == 5


def test_invalid_ports_become_none():
    payload = flow_to_flow_ingest(
        _flow(src_port=0, dest_port=99999), local_address_set([HOST])
    )

    assert payload["source_port"] is None
    assert payload["destination_port"] is None


def test_missing_protocol_falls_back_to_unknown():
    flow = _flow()
    del flow["proto"]

    payload = flow_to_flow_ingest(flow, local_address_set([HOST]))

    assert payload["protocol"] == "unknown"


def test_protocol_is_lowercased_and_truncated():
    payload = flow_to_flow_ingest(
        _flow(proto="A" * 40), local_address_set([HOST])
    )

    assert payload["protocol"] == "a" * 20


# --- noise filtering ---------------------------------------------------------


def test_bookkeeping_flows_are_treated_as_noise():
    assert is_noise_flow({"reason": "internal"}) is True
    assert is_noise_flow({"reason": "timeout"}) is True
    assert is_noise_flow({"reason": "forced"}) is True
    assert is_noise_flow({"reason": "timeout,still active"}) is True
    assert is_noise_flow({"reason": "  TIMEOUT  "}) is True


def test_real_traffic_reasons_are_not_noise():
    assert is_noise_flow({"reason": "new"}) is False
    assert is_noise_flow({"reason": "established"}) is False
    assert is_noise_flow({"reason": "accept"}) is False
    assert is_noise_flow({"reason": "still-active"}) is False
    assert is_noise_flow({}) is False
    assert is_noise_flow({"reason": ""}) is False


def test_noise_is_detected_from_the_first_token_of_a_multi_reason_flow():
    """Suricata appends reasons with commas; the first is the dominant cause."""
    assert is_noise_flow({"reason": "shutdown,timeout"}) is True
    assert is_noise_flow({"reason": "forced,shutdown"}) is True


# --- alerts ------------------------------------------------------------------


def _alert(**overrides):
    alert = {
        "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
        "signature_id": 2032245,
        "category": "Attempted Administrator Privilege Gain",
        "severity": 1,
        "src_ip": "203.0.113.9",
        "src_port": 41000,
        "dest_ip": HOST,
        "dest_port": 22,
        "proto": "TCP",
        "timestamp": "2026-09-29T11:22:33.123456+0000",
    }
    alert.update(overrides)
    return alert


def test_alert_becomes_a_siem_log_entry():
    entry = alert_to_log_entry(_alert(), source="akamai-web-01")

    assert entry["source"] == "akamai-web-01"
    assert entry["level"] == "critical"
    assert entry["ip_address"] == "203.0.113.9"
    assert entry["category"] == "network"
    assert "Nmap" in entry["message"]
    assert "203.0.113.9" in entry["message"]


def test_alert_preserves_the_full_eve_record():
    alert = _alert()

    entry = alert_to_log_entry(alert, source="akamai-web-01")

    assert entry["raw_data"] == alert


def test_severity_codes_map_to_threatpulse_levels():
    levels = {
        code: alert_to_log_entry(_alert(severity=code), "src")["level"]
        for code in (1, 2, 3, 4)
    }

    assert levels == {1: "critical", 2: "high", 3: "medium", 4: "low"}


def test_out_of_range_severity_falls_back_to_low():
    assert alert_to_log_entry(_alert(severity=9), "src")["level"] == "low"
    assert alert_to_log_entry(_alert(severity=None), "src")["level"] == "low"


def test_alert_message_is_truncated_to_the_siem_limit():
    entry = alert_to_log_entry(_alert(signature="X" * 5000), "src", max_message_len=2000)

    assert len(entry["message"]) <= 2000


def test_alert_without_signature_or_id_is_rejected():
    assert alert_to_log_entry({"severity": 1}, "src") is None
    assert alert_to_log_entry({}, "src") is None


def test_alert_timestamp_is_normalised():
    entry = alert_to_log_entry(_alert(), "src")

    parsed = datetime.fromisoformat(entry["timestamp"])
    assert parsed.tzinfo is not None
    assert parsed.year == 2026


# --- line parsing ------------------------------------------------------------


def test_valid_eve_line_parses():
    record = parse_eve_line('{"event_type":"flow","flow":{"src_ip":"10.0.0.1"}}')

    assert record["event_type"] == "flow"


def test_blank_comment_and_malformed_lines_are_ignored():
    assert parse_eve_line("") is None
    assert parse_eve_line("   ") is None
    assert parse_eve_line("# comment") is None
    assert parse_eve_line("{not json") is None
    assert parse_eve_line("[1,2,3]") is None
