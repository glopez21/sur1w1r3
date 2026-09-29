"""Sur1W1r3 CLI."""

from __future__ import annotations

import asyncio
import logging
import sys
from typing import Any

import typer
from rich.console import Console
from rich.table import Table

from suricata_shipper import __version__
from suricata_shipper.config import ShipperConfig
from suricata_shipper.queue import PositionStore, ShipQueue
from suricata_shipper.shipper import SuricataShipper, setup_signal_handlers

app = typer.Typer(
    name="sur1w1r3",
    help="Ship Suricata EVE telemetry to ThreatPulse",
    add_completion=False,
)
console = Console()


def _setup_logging(level: str = "INFO") -> None:
    logging.basicConfig(
        level=getattr(logging, level.upper(), logging.INFO),
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
        datefmt="%Y-%m-%dT%H:%M:%S",
    )


@app.callback()
def callback() -> None:
    """Sur1W1r3 — Suricata EVE telemetry to SOC ingest."""


@app.command()
def run(
    eve_path: str = typer.Option("", "--eve", "-e", help="Path to Suricata eve.json"),
    flow_url: str = typer.Option("", "--flow-url", help="network-monitor batch ingest URL"),
    flow_api_key: str = typer.Option("", "--flow-key", help="network-monitor X-API-Key"),
    alert_url: str = typer.Option("", "--alert-url", help="siem-app webhook URL"),
    alert_api_key: str = typer.Option("", "--alert-key", help="siem-app X-API-Key"),
    alert_webhook_secret: str = typer.Option(
        "", "--alert-secret", help="siem-app WEBHOOK_SECRET for HMAC signing"
    ),
    source: str = typer.Option("", "--source", "-s", help="Source hostname identifier"),
    config_file: str = typer.Option("", "--config", "-c", help="Path to .env config file"),
    skip_existing: bool = typer.Option(
        False, "--skip-existing", help="Start from the end of eve.json instead of resuming"
    ),
    log_level: str = typer.Option("INFO", "--log-level", "-l", help="Log level"),
) -> None:
    """Run the shipper loop."""
    _setup_logging(log_level)

    overrides: dict[str, Any] = {}
    if eve_path:
        overrides["eve_path"] = eve_path
    if flow_url:
        overrides["flow_url"] = flow_url
    if flow_api_key:
        overrides["flow_api_key"] = flow_api_key
    if alert_url:
        overrides["alert_url"] = alert_url
    if alert_api_key:
        overrides["alert_api_key"] = alert_api_key
    if alert_webhook_secret:
        overrides["alert_webhook_secret"] = alert_webhook_secret
    if source:
        overrides["source"] = source

    if config_file:
        overrides["_env_file"] = config_file

    config = ShipperConfig(**overrides)
    if config_file:
        config.model_config["env_file"] = config_file

    shipper = SuricataShipper(config, skip_existing=skip_existing)

    async def _run() -> None:
        setup_signal_handlers(shipper)
        await shipper.run_forever()

    try:
        asyncio.run(_run())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]Shutting down...[/]")
        shipper.stop()
    except SystemExit as exc:
        console.print(f"[bold red]{exc}[/]")
        sys.exit(1)


@app.command()
def status(
    state_path: str = typer.Option(
        "/var/lib/suricata-shipper/state.json", "--state", help="Position store path"
    ),
) -> None:
    """Show queue depth, dead letters, and read position."""
    queue_path = f"{state_path.rsplit('.', 1)[0]}.queue.db"
    store = PositionStore(state_path)
    offset, inode = store.load()

    table = Table(title="Sur1W1r3 status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="green")

    table.add_row("EVE offset", str(offset))
    table.add_row("EVE inode", str(inode))

    queue = ShipQueue(queue_path)
    try:
        depths = queue.depth_by_kind()
        table.add_row("Queued flows", str(depths["flow"]))
        table.add_row("Queued alerts", str(depths["alert"]))
        table.add_row("Total queue depth", str(queue.depth()))
        table.add_row("Dead letters", str(queue.dead_letters()))
    finally:
        queue.close()

    console.print(table)


@app.command()
def test(
    flow_url: str = typer.Option("", "--flow-url", help="network-monitor batch ingest URL"),
    flow_api_key: str = typer.Option("", "--flow-key", help="network-monitor X-API-Key"),
    alert_url: str = typer.Option("", "--alert-url", help="siem-app webhook URL"),
    alert_webhook_secret: str = typer.Option("", "--alert-secret", help="siem-app HMAC secret"),
    config_file: str = typer.Option("", "--config", "-c", help="Path to .env config file"),
) -> None:
    """Send one synthetic flow and alert to verify connectivity and auth."""

    _setup_logging("INFO")

    config = ShipperConfig(**({"_env_file": config_file} if config_file else {}))
    if config_file:
        config.model_config["env_file"] = config_file

    from suricata_shipper.client import AlertClient, FlowClient
    from suricata_shipper.parsers import alert_to_log_entry, flow_to_flow_ingest

    results: list[tuple[str, bool, str]] = []

    if flow_url or flow_api_key:
        payload = flow_to_flow_ingest(
            {
                "src_ip": "10.0.0.1",
                "src_port": 51514,
                "dest_ip": "93.184.216.34",
                "dest_port": 443,
                "proto": "tcp",
                "state": "established",
                "start": "2026-09-29T10:00:00+00:00",
                "end": "2026-09-29T10:00:05+00:00",
                "bytes_toserver": 1024,
                "bytes_toclient": 2048,
                "pkts_toserver": 10,
                "pkts_toclient": 12,
            },
            frozenset({"10.0.0.1"}),
        )
        client = FlowClient(
            flow_url or config.flow_url,
            flow_api_key or config.flow_api_key,
            config.source,
            config.tls_verify,
        )
        try:
            handled, error = asyncio.run(client.send([payload]))
            results.append(("flow", handled == 1, error or f"handled={handled}"))
        finally:
            asyncio.run(client.close())
    else:
        results.append(("flow", False, "not configured"))

    if alert_url or alert_webhook_secret:
        entry = alert_to_log_entry(
            {
                "signature": "Sur1W1r3 connectivity test",
                "signature_id": 0,
                "category": "shipper-selftest",
                "severity": 3,
                "src_ip": "10.0.0.1",
                "dest_ip": "10.0.0.2",
                "dest_port": 443,
                "timestamp": "2026-09-29T10:00:00+00:00",
            },
            config.source,
        )
        client = AlertClient(
            alert_url or config.alert_url,
            config.alert_api_key,
            alert_webhook_secret or config.alert_webhook_secret,
            config.tls_verify,
        )
        try:
            sent, error = asyncio.run(client.send([entry]))
            results.append(("alert", sent == 1, error or f"sent={sent}"))
        finally:
            asyncio.run(client.close())
    else:
        results.append(("alert", False, "not configured"))

    failed = 0
    for target, ok, detail in results:
        mark = "[green]PASS[/]" if ok else "[red]FAIL[/]"
        console.print(f"{mark:20} {target:6} {detail}")
        if not ok:
            failed += 1

    if failed:
        console.print("\n[bold red]Some checks failed. Verify the API keys and network path.[/]")
        sys.exit(1)
    console.print("\n[bold green]All checks passed.[/]")


@app.command()
def version() -> None:
    """Print the shipper version."""
    console.print(f"Sur1W1r3 {__version__}")


def main() -> None:
    app()


if __name__ == "__main__":
    main()
