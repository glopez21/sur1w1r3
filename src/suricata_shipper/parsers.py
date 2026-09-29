"""Parse Suricata EVE JSON records into ThreatPulse ingest payloads.

Suricata's ``eve.json`` is newline-delimited JSON where every line is an event
whose ``event_type`` selects the schema. ThreatPulse needs two different
shapes from the same stream:

* ``flow``  -> ``FlowIngest`` (network-monitor ``/api/v1/traffic/ingest/batch``)
* ``alert`` -> ``LogEntryCreate`` (siem-app ``/api/v1/webhooks``)

Suricata reports byte and packet counters from the *initiator's* point of view:
``bytes_toserver`` is traffic the client sent, ``bytes_toclient`` is what came
back. ThreatPulse's ``bytes_in``/``bytes_out`` are host-relative, so the mapping
depends on which end is local. :func:`local_is_origin` decides that by checking
the source address against the collector's own addresses.
"""

from __future__ import annotations

import ipaddress
import json
import re
from datetime import UTC, datetime
from typing import Any

# Suricata EVE event types this shipper understands. Anything else (stats,
# dns, tls, fileinfo, http, ...) is counted and dropped.
SUPPORTED_EVENT_TYPES = ("flow", "alert")

# Suricata alert.severity is 1 (highest) to 4. ThreatPulse uses named levels.
SEVERITY_BY_CODE = {
    1: "critical",
    2: "high",
    3: "medium",
    4: "low",
}

# Flow reasons that are pure protocol bookkeeping, not real traffic. Suricata
# emits these constantly and they would otherwise dominate the flow table.
_NOISE_FLOW_REASONS = {
    "internal",
    "timeout",
    "shutdown",
    "forced",
    "emergency",
    "bypassed",
    "local",
    "invalid",
}


def _parse_timestamp(value: Any) -> datetime:
    """Parse a Suricata timestamp, always returning an aware UTC datetime.

    FlowIngest's ``start_time`` is non-nullable and the column is timezone-aware,
    so a naive timestamp would be rejected by the database rather than by
    validation. Suricata emits RFC 3339 with a ``Z`` suffix, which
    ``fromisoformat`` only handles on Python 3.11+, so ``Z`` is normalised.
    """
    if isinstance(value, datetime):
        parsed = value
    elif isinstance(value, (int, float)):
        parsed = datetime.fromtimestamp(value, tz=UTC)
    elif isinstance(value, str) and value:
        text = value.replace("Z", "+00:00")
        try:
            parsed = datetime.fromisoformat(text)
        except ValueError:
            return datetime.now(UTC)
    else:
        return datetime.now(UTC)

    if parsed.tzinfo is None:
        return parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _to_int(value: Any) -> int:
    """Coerce an EVE numeric field, defaulting to 0 when absent or non-numeric."""
    if isinstance(value, bool):
        return 0
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        return int(value)
    if isinstance(value, str):
        try:
            return int(value)
        except ValueError:
            return 0
    return 0


def _to_port(value: Any) -> int | None:
    port = _to_int(value)
    return port if 0 < port <= 65535 else None


def _to_ip(value: Any) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    try:
        return str(ipaddress.ip_address(value))
    except ValueError:
        # Suricata can emit IPv4-mapped IPv6 or decorated addresses; keep the
        # raw value rather than dropping an otherwise usable record.
        return value


def local_is_origin(source_ip: str, local_addresses: frozenset[str]) -> bool:
    """True when ``source_ip`` is this host, meaning it opened the flow.

    Suricata captures both directions of a conversation as one flow record, so
    this is what determines whether bytes_toserver counts as bytes out or in.
    """
    if not local_addresses:
        return False
    return _to_ip(source_ip) in local_addresses


def local_address_set(
    addresses: list[str] | tuple[str, ...] | set[str] | frozenset[str] | None,
    interface_ips: list[str] | None = None,
) -> frozenset[str]:
    """Build the set of addresses treated as belonging to this host.

    ``addresses`` is the operator-configured list; ``interface_ips`` is
    auto-detected from the host and merged in so a misconfigured collector
    still attributes flows correctly.
    """
    resolved: set[str] = set()
    for raw in [*(addresses or []), *(interface_ips or [])]:
        value = _to_ip(raw)
        if value:
            resolved.add(value)
    return frozenset(resolved)


def detect_interface_addresses() -> list[str]:
    """Best-effort discovery of this host's IPv4/IPv6 addresses.

    Uses a UDP socket connect trick rather than ``netifaces`` to avoid a hard
    dependency; it selects the source address the kernel would use for an
    outbound packet without sending anything.
    """
    import socket

    found: list[str] = []
    probes = (
        (socket.AF_INET, ("8.8.8.8", 53)),
        (socket.AF_INET6, ("2001:4860:4860::8888", 53)),
    )
    for family, probe in probes:
        sock = socket.socket(family, socket.SOCK_DGRAM)
        try:
            sock.settimeout(0.2)
            sock.connect(probe)
            addr = sock.getsockname()[0]
            if addr and addr not in found:
                found.append(addr)
        except OSError:
            pass
        finally:
            sock.close()

    try:
        hostname = socket.gethostname()
        for info in socket.getaddrinfo(hostname, None):
            address = info[4][0]
            if address and address not in found:
                found.append(address)
    except OSError:
        pass

    return found


def is_noise_flow(flow: dict[str, Any]) -> bool:
    """True for bookkeeping flows that carry no security-relevant traffic."""
    reason = flow.get("reason")
    if not isinstance(reason, str):
        return False
    normalized = reason.strip().lower()
    if not normalized:
        return False
    # Suricata joins reasons with commas ("forced,timeout", "shutdown,timeout")
    # and sometimes adds trailing text, so the first token is the dominant
    # reason and the rest is detail.
    head = re.split(r"[,\s]", normalized, maxsplit=1)[0].strip(" ,")
    return head in _NOISE_FLOW_REASONS


def flow_to_flow_ingest(
    flow: dict[str, Any],
    local_addresses: frozenset[str] = frozenset(),
) -> dict[str, Any] | None:
    """Convert an EVE ``flow`` record into a ThreatPulse ``FlowIngest`` payload.

    Returns ``None`` when the record lacks the addressing needed to be a flow at
    all, so the caller can count it as malformed rather than storing a row with
    null endpoints.
    """
    source_ip = _to_ip(flow.get("src_ip"))
    destination_ip = _to_ip(flow.get("dest_ip"))
    if not source_ip or not destination_ip:
        return None

    origin_is_local = local_is_origin(source_ip, local_addresses)

    to_server = _to_int(flow.get("bytes_toserver"))
    to_client = _to_int(flow.get("bytes_toclient"))
    pkts_to_server = _to_int(flow.get("pkts_toserver"))
    pkts_to_client = _to_int(flow.get("pkts_toclient"))

    if origin_is_local:
        bytes_out, bytes_in = to_server, to_client
        packets_out, packets_in = pkts_to_server, pkts_to_client
    else:
        bytes_in, bytes_out = to_server, to_client
        packets_in, packets_out = pkts_to_server, pkts_to_client

    start = _parse_timestamp(flow.get("start"))
    end_value = flow.get("end")
    end = _parse_timestamp(end_value) if end_value else None

    protocol = flow.get("proto")
    if not isinstance(protocol, str) or not protocol:
        protocol = "unknown"

    state = flow.get("state")
    flags = state if isinstance(state, str) and state else None

    return {
        "source_ip": source_ip,
        "source_port": _to_port(flow.get("src_port")),
        "destination_ip": destination_ip,
        "destination_port": _to_port(flow.get("dest_port")),
        "protocol": protocol.lower()[:20],
        "bytes_in": bytes_in,
        "bytes_out": bytes_out,
        "packets_in": packets_in,
        "packets_out": packets_out,
        "flags": flags[:50] if flags else None,
        "start_time": start.isoformat(),
        "end_time": end.isoformat() if end else None,
    }


def alert_to_log_entry(
    alert: dict[str, Any],
    source: str,
    max_message_len: int = 2000,
) -> dict[str, Any] | None:
    """Convert an EVE ``alert`` record into a ThreatPulse SIEM log entry.

    Matches siem-app's ``LogEntryCreate``: ``timestamp``, ``level``, ``source``,
    ``message``, ``raw_data``, ``ip_address``. The full EVE record is preserved
    in ``raw_data`` so analysts keep signature, classification, and references
    without this shipper having to model every Suricata field.
    """
    signature = alert.get("signature")
    alert_id = alert.get("alert_id")
    category = alert.get("category") or "network"
    if not signature and not alert_id:
        return None

    code = _to_int(alert.get("severity")) or 4
    level = SEVERITY_BY_CODE.get(code, "low")

    src_ip = _to_ip(alert.get("src_ip")) or "unknown"
    dest_ip = _to_ip(alert.get("dest_ip"))
    dest_port = _to_port(alert.get("dest_port"))

    signature_id = alert.get("signature_id")
    sid = f"S{signature_id}" if signature_id else "unknown"
    title = signature or "suricata alert"

    message = f"[{category}/{sid}] {title}"
    if dest_ip:
        destination = f"{dest_ip}:{dest_port}" if dest_port else dest_ip
        message = f"{message} {src_ip} -> {destination}"

    entry: dict[str, Any] = {
        "timestamp": _parse_timestamp(alert.get("timestamp")).isoformat(),
        "level": level,
        "source": source,
        "message": message[:max_message_len],
        "ip_address": src_ip,
        "category": "network",
        "raw_data": alert,
    }
    if dest_ip:
        entry["destination_ip"] = dest_ip
    return entry


def parse_eve_line(line: str) -> dict[str, Any] | None:
    """Parse one EVE line, tolerating Suricata's occasional malformed output."""
    text = line.strip()
    if not text or text.startswith("#"):
        return None
    try:
        record = json.loads(text)
    except json.JSONDecodeError:
        return None
    return record if isinstance(record, dict) else None
