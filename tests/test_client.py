"""Tests for the HTTP clients' auth headers and failure handling.

Delivery correctness is the whole point of this agent, so the auth schemes and
the distinction between retryable and terminal failures are pinned here. httpx
mock transport is used, so no real network or ThreatPulse instance is needed.
"""

from __future__ import annotations

import hashlib
import hmac
import json

import httpx

from suricata_shipper.client import AlertClient, FlowClient


def _flow_payload(n: int = 0) -> dict:
    return {
        "source_ip": "10.0.0.5",
        "source_port": 51514,
        "destination_ip": "93.184.216.34",
        "destination_port": 443,
        "protocol": "tcp",
        "bytes_in": 100,
        "bytes_out": 200,
        "packets_in": 10,
        "packets_out": 20,
        "start_time": "2026-09-29T10:00:00+00:00",
        "end_time": "2026-09-29T10:00:05+00:00",
        "n": n,
    }


def _client(handler, **kwargs) -> FlowClient:
    """Swap in a mock transport while keeping the real client's default headers.

    Assigning a fresh AsyncClient would drop the auth headers under test, so the
    transport is replaced in place instead.
    """
    client = FlowClient(**kwargs)
    client.client._transport = httpx.MockTransport(handler)
    return client


# --- flow client -------------------------------------------------------------


async def test_flow_batch_sends_api_key_and_collector():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = json.loads(request.content)
        return httpx.Response(202, json={"accepted": 1, "rejected": 0})

    client = _client(
        handler,
        url="http://tp/api/network/api/v1/traffic/ingest/batch",
        api_key="secret",
        collector="akamai-web-01",
    )
    try:
        accepted, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert accepted == 1
    assert error == ""
    assert captured["headers"]["x-api-key"] == "secret"
    assert captured["body"]["collector"] == "akamai-web-01"
    assert captured["body"]["flows"][0]["destination_ip"] == "93.184.216.34"


async def test_flow_partial_accept_is_still_a_success():
    """The endpoint validates per record, so a partial accept must not retry."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"accepted": 2, "rejected": 1, "errors": ["flow[2]"]})

    client = _client(
        handler,
        url="http://tp/flow",
        api_key="secret",
        collector="web-01",
    )
    try:
        accepted, error = await client.send([_flow_payload(i) for i in range(3)])
    finally:
        await client.close()

    assert accepted == 3
    assert error == ""


async def test_flow_batch_accepts_202_from_the_real_endpoint():
    """Regression: the endpoint answers 202, not 200.

    Pinning 200 made every real batch look like an unexpected status, so nothing
    was ever acked and the queue dead-lettered the entire backlog.
    """

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(202, json={"accepted": 1, "rejected": 0, "errors": []})

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        handled, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert handled == 1
    assert error == ""


async def test_flow_batch_accepts_any_2xx():
    for code in (200, 201, 202, 204):
        def handler(request: httpx.Request, code: int = code) -> httpx.Response:
            return httpx.Response(code)

        client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
        try:
            handled, error = await client.send([_flow_payload()])
        finally:
            await client.close()

        assert handled == 1, f"status {code} was not treated as delivered"
        assert error == ""


async def test_flow_422_is_requeued_not_acked():
    """A whole-request rejection stored nothing, so the batch must be requeued.

    Acking it would silently discard the records, which is worse than a requeue.
    """
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(422, json={"detail": "validation error"})

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        handled, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert handled == 0
    assert "422" in error
    assert attempts == 1


async def test_flow_413_is_requeued_rather_than_acked():
    """413 stores nothing either; the fix is a smaller batch, not a discard."""

    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(413, text="payload too large")

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        handled, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert handled == 0
    assert "413" in error


async def test_flow_503_is_retried_then_reported():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(503, text="unavailable")

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01", max_attempts=3)
    try:
        handled, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert handled == 0
    assert "503" in error
    assert attempts == 3


async def test_flow_401_is_terminal_and_does_not_retry():
    attempts = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal attempts
        attempts += 1
        return httpx.Response(401, text="unauthorized")

    client = _client(handler, url="http://tp/flow", api_key="bad", collector="web-01")
    try:
        handled, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert handled == 0
    assert "auth rejected" in error
    assert attempts == 1


async def test_empty_batch_short_circuits():
    called = False

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal called
        called = True
        return httpx.Response(200)

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        accepted, error = await client.send([])
    finally:
        await client.close()

    assert (accepted, error) == (0, "")
    assert called is False


async def test_auth_rejection_is_terminal_not_retried():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401, json={"detail": "Invalid or missing API key"})

    client = _client(handler, url="http://tp/flow", api_key="wrong", collector="web-01")
    try:
        accepted, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert accepted == 0
    assert "auth rejected" in error
    assert calls == 1, "a bad key must not be retried into a full queue"


async def test_server_error_is_retried_then_reported():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(503)

    client = _client(
        handler, url="http://tp/flow", api_key="k", collector="web-01", max_attempts=3
    )
    try:
        accepted, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert accepted == 0
    assert "503" in error
    assert calls == 3, "should back off and retry before giving up"


async def test_oversized_batch_is_reported_without_retry():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(413)

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        accepted, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert accepted == 0
    assert "413" in error
    assert calls == 1


async def test_connection_error_is_reported_for_requeue():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _client(handler, url="http://tp/flow", api_key="k", collector="web-01")
    try:
        accepted, error = await client.send([_flow_payload()])
    finally:
        await client.close()

    assert accepted == 0
    assert "connection error" in error


# --- alert client ------------------------------------------------------------


def _alert_client(handler, **kwargs) -> AlertClient:
    client = AlertClient(**kwargs)
    client.client._transport = httpx.MockTransport(handler)
    return client


async def test_alert_sends_hmac_signature_over_the_body():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        captured["body"] = request.content
        return httpx.Response(202)

    client = _alert_client(
        handler,
        url="http://tp/api/siem/api/v1/webhooks",
        webhook_secret="shared-secret",
    )
    try:
        sent, error = await client.send([{"level": "high", "message": "test"}])
    finally:
        await client.close()

    expected = hmac.new(b"shared-secret", captured["body"], hashlib.sha256).hexdigest()
    assert sent == 1
    assert error == ""
    assert captured["headers"]["x-webhook-signature"] == expected
    assert "x-api-key" not in captured["headers"]


async def test_alert_falls_back_to_api_key_when_no_secret():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(202)

    client = _alert_client(
        handler, url="http://tp/api/siem/api/v1/webhooks", api_key="plain-key"
    )
    try:
        await client.send([{"level": "high", "message": "test"}])
    finally:
        await client.close()

    assert captured["headers"]["x-api-key"] == "plain-key"
    assert "x-webhook-signature" not in captured["headers"]


async def test_secret_takes_precedence_over_api_key():
    captured: dict = {}

    def handler(request: httpx.Request) -> httpx.Response:
        captured["headers"] = dict(request.headers)
        return httpx.Response(202)

    client = _alert_client(
        handler, url="http://tp/hook", api_key="plain", webhook_secret="secret"
    )
    try:
        await client.send([{"level": "low", "message": "m"}])
    finally:
        await client.close()

    assert "x-webhook-signature" in captured["headers"]
    assert "x-api-key" not in captured["headers"]


async def test_alert_batch_stops_at_first_terminal_failure():
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(401)

    client = _alert_client(handler, url="http://tp/hook", api_key="wrong")
    try:
        sent, error = await client.send([{"n": i} for i in range(5)])
    finally:
        await client.close()

    assert sent == 0
    assert "auth rejected" in error
    assert calls == 1


async def test_alert_reports_partial_delivery():
    """Only the delivered entries are acked; the rest go back for retry."""
    calls = 0

    def handler(request: httpx.Request) -> httpx.Response:
        nonlocal calls
        calls += 1
        return httpx.Response(202 if calls <= 2 else 400)

    client = _alert_client(handler, url="http://tp/hook", api_key="k")
    try:
        sent, error = await client.send([{"n": i} for i in range(4)])
    finally:
        await client.close()

    assert sent == 2
    assert error


async def test_alert_connection_error_is_reported():
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("refused")

    client = _alert_client(handler, url="http://tp/hook", api_key="k")
    try:
        sent, error = await client.send([{"n": 1}])
    finally:
        await client.close()

    assert sent == 0
    assert "connection error" in error
