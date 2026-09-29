"""HTTP clients for the two ThreatPulse ingest surfaces.

Flows go to network-monitor's batch endpoint with an ``X-API-Key`` header;
alerts go to siem-app's webhook, which ThreatPulse authenticates with an HMAC
``X-Webhook-Signature`` over the raw body. Both are separate classes because the
auth schemes and failure semantics differ, and a flow batch succeeding says
nothing about whether the alert batch landed.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
from typing import Any

import httpx

logger = logging.getLogger(__name__)

USER_AGENT = "suricata-shipper/1.0"


class FlowClient:
    """Batched flow delivery to ``/api/v1/traffic/ingest/batch``."""

    def __init__(
        self,
        url: str,
        api_key: str,
        collector: str,
        tls_verify: bool = True,
        timeout: float = 30.0,
        max_attempts: int = 4,
    ):
        self.url = url
        self.api_key = api_key
        self.collector = collector
        self.max_attempts = max_attempts
        self.client = httpx.AsyncClient(
            verify=tls_verify,
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={
                "Content-Type": "application/json",
                "X-API-Key": api_key,
                "User-Agent": USER_AGENT,
            },
        )

    async def send(self, flows: list[dict[str, Any]]) -> tuple[int, str]:
        """Deliver a batch. Returns ``(handled, error)``.

        ``handled`` counts flows the server took responsibility for. It equals
        ``len(flows)`` on any 2xx and 0 on a delivery failure with a non-empty
        ``error``, which lets the caller requeue without inspecting exceptions.

        Per-record validation happens server-side, so a record the server
        rejected counts as handled: the server logged the reason, and replaying
        an identical payload would just dead-letter it.
        """
        if not flows:
            return 0, ""

        payload = {"flows": flows, "collector": self.collector}
        last_error = ""

        for attempt in range(self.max_attempts):
            try:
                response = await self.client.post(self.url, json=payload)
            except httpx.RequestError as exc:
                last_error = f"connection error: {exc}"
            else:
                # The batch endpoint replies 202 Accepted. Accept any 2xx rather
                # than pinning 200, so an implementation change that keeps the
                # semantics but shifts the code does not dead-letter the queue.
                if 200 <= response.status_code < 300:
                    return len(flows), ""

                if response.status_code in (401, 403):
                    # Retrying a bad key forever just fills the queue.
                    return 0, f"auth rejected ({response.status_code}): check the API key"

                if response.status_code in (413, 422):
                    # The server stored nothing, so this must not be acked:
                    # that would silently discard the batch. Requeue instead.
                    # 413 is resolved by a smaller batch size, and 422 by a
                    # payload fix, so both stay requeueable rather than terminal.
                    return 0, f"batch rejected ({response.status_code}): {response.text[:200]}"

                if response.status_code == 429 or response.status_code >= 500:
                    last_error = f"server error {response.status_code}"
                else:
                    return 0, f"unexpected {response.status_code}: {response.text[:200]}"

            if attempt < self.max_attempts - 1:
                delay = 2**attempt
                logger.warning("Flow batch failed (%s), retrying in %ds", last_error, delay)
                await asyncio.sleep(delay)

        return 0, last_error

    async def close(self) -> None:
        await self.client.aclose()


class AlertClient:
    """Alert delivery to siem-app's webhook endpoint.

    siem-app accepts either ``X-API-Key`` or an HMAC ``X-Webhook-Signature``.
    The HMAC is preferred when ``WEBHOOK_SECRET`` is set on the server, since a
    signature covers the body and cannot be replayed against another sink.
    """

    def __init__(
        self,
        url: str,
        api_key: str = "",
        webhook_secret: str = "",
        tls_verify: bool = True,
        timeout: float = 30.0,
        max_attempts: int = 4,
    ):
        self.url = url
        self.api_key = api_key
        self.webhook_secret = webhook_secret
        self.max_attempts = max_attempts
        self.client = httpx.AsyncClient(
            verify=tls_verify,
            timeout=httpx.Timeout(timeout, connect=10.0),
            headers={"Content-Type": "application/json", "User-Agent": USER_AGENT},
        )

    def _headers(self, body: bytes) -> dict[str, str]:
        headers: dict[str, str] = {}
        if self.webhook_secret:
            signature = hmac.new(
                self.webhook_secret.encode(), body, hashlib.sha256
            ).hexdigest()
            headers["X-Webhook-Signature"] = signature
        elif self.api_key:
            headers["X-API-Key"] = self.api_key
        return headers

    async def send(self, entries: list[dict[str, Any]]) -> tuple[int, str]:
        """Deliver a batch of log entries. Returns ``(sent, error)``.

        Unlike the flow endpoint, the webhook accepts one entry per request, so
        entries are sent sequentially and partial progress is reported honestly.
        """
        if not entries:
            return 0, ""

        sent = 0
        last_error = ""

        for entry in entries:
            body = self._encode(entry)
            delivered = False

            for attempt in range(self.max_attempts):
                try:
                    response = await self.client.post(
                        self.url, content=body, headers=self._headers(body)
                    )
                except httpx.RequestError as exc:
                    last_error = f"connection error: {exc}"
                else:
                    if response.status_code in (200, 201, 202, 204):
                        delivered = True
                        break
                    if response.status_code in (401, 403):
                        return sent, (
                            f"auth rejected ({response.status_code}): check the webhook secret"
                        )
                    if response.status_code == 429 or response.status_code >= 500:
                        last_error = f"server error {response.status_code}"
                        if attempt < self.max_attempts - 1:
                            await asyncio.sleep(2**attempt)
                        continue
                    last_error = f"unexpected {response.status_code}: {response.text[:200]}"
                    break

            if delivered:
                sent += 1
            else:
                # Stop the batch: a systemic failure will not clear per entry.
                break

        return sent, "" if sent == len(entries) else last_error

    @staticmethod
    def _encode(entry: dict[str, Any]) -> bytes:
        return json.dumps(entry, default=str).encode()

    async def close(self) -> None:
        await self.client.aclose()
