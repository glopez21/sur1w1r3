"""Tail Suricata's EVE JSON file and convert records into ThreatPulse payloads.

Two concerns live here:

* **Rotation safety.** Suricata rotates ``eve.json`` and compresses old files.
  The reader tracks its position by ``(inode, offset)`` and detects a smaller
  file or a changed inode as a restart, resetting to the beginning rather than
  seeking mid-record.
* **Backpressure.** The file is read line-by-line and records are pushed into
  the queue, so a slow or unreachable ThreatPulse cannot cause unbounded memory
  growth in the shipper.
"""

from __future__ import annotations

import logging
import os
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from suricata_shipper.config import ShipperConfig
from suricata_shipper.parsers import (
    alert_to_log_entry,
    detect_interface_addresses,
    flow_to_flow_ingest,
    is_noise_flow,
    local_address_set,
    parse_eve_line,
)

logger = logging.getLogger(__name__)


class EveStats:
    """Counters for a ship cycle, logged so dropped records are never silent."""

    def __init__(self) -> None:
        self.read = 0
        self.malformed = 0
        self.skipped_type = 0
        self.noise_flows = 0
        self.flows = 0
        self.alerts = 0
        self.bytes_consumed = 0

    def as_dict(self) -> dict[str, int]:
        return {
            "read": self.read,
            "malformed": self.malformed,
            "skipped_type": self.skipped_type,
            "noise_flows": self.noise_flows,
            "flows": self.flows,
            "alerts": self.alerts,
            "bytes_consumed": self.bytes_consumed,
        }

    def __str__(self) -> str:
        return ", ".join(f"{k}={v}" for k, v in self.as_dict().items())


class EveReader:
    """Incremental, rotation-aware reader for a newline-delimited EVE file.

    Two offsets are tracked deliberately:

    * ``_offset`` is the persisted file position — the point up to which data has
      been consumed and is safe to resume from after a restart.
    * ``_pending`` holds a trailing line that is not newline-terminated yet.

    A partial line is *not* advanced past in ``_offset``, because a crash
    between reading it and its continuation arriving would otherwise skip the
    record. The line is instead held in ``_pending`` and the offset is rewound
    to the last newline, so the next read re-consumes it from disk exactly once.
    """

    def __init__(self, config: ShipperConfig):
        self.config = config
        self.path = Path(config.eve_path)
        self._offset = 0
        self._inode: int | None = None
        self._pending = ""
        self._loaded = False
        # Bytes of complete lines handed to the caller, for progress reporting.
        self.bytes_consumed = 0

    # --- position tracking ----------------------------------------------------

    def load_position(self, offset: int, inode: int | None) -> None:
        self._offset = offset
        self._inode = inode
        self._pending = ""
        self._loaded = True

    def position(self) -> tuple[int, int | None]:
        return self._offset, self._inode

    def _current_inode(self) -> int | None:
        try:
            return os.stat(self.path).st_ino
        except OSError:
            return None

    def _reset_if_rotated(self, size: int, inode: int | None) -> bool:
        """Return True when reading should restart from the top of the file.

        Rotation is detected by inode change, which is what a rename-based
        logrotate policy produces and is the only unambiguous signal. A
        ``copytruncate`` rotation keeps the inode, so it is only detectable while
        the file is still shorter than the last read; if it regrows past that
        point before the next cycle, the skipped bytes cannot be recovered.
        The shipped logrotate config therefore renames and signals Suricata
        instead of truncating in place.
        """
        if not self._loaded:
            self._loaded = True
            return True

        rotated = False
        if self._inode is not None and inode is not None and inode != self._inode:
            logger.info("EVE file inode changed (%s -> %s), restarting read", self._inode, inode)
            rotated = True
        elif size < self._offset:
            # In-place truncation, as logrotate's copytruncate performs. Any
            # records written between the last read and the truncation are gone
            # from the file, so the read restarts at 0.
            logger.warning(
                "EVE file truncated in place (%d -> %d); restarting read. Records "
                "written since the last cycle were discarded by the rotation",
                self._offset,
                size,
            )
            rotated = True

        if rotated:
            self._offset = 0
            self._pending = ""
        self._inode = inode
        return rotated

    # --- reading --------------------------------------------------------------

    def read_new_records(self) -> Iterator[dict[str, Any]]:
        """Yield complete EVE records appended since the last call.

        Reading is text-based for UTF-8 handling, but the persisted offset is
        only ever advanced by whole lines that end in ``\\n``, and it is rewound
        to the start of any trailing partial line. That keeps the saved position
        aligned to line boundaries so a resume never begins mid-record.
        """
        try:
            stat = os.stat(self.path)
        except FileNotFoundError:
            if self._loaded:
                logger.warning("EVE file %s missing; waiting for Suricata", self.path)
            self._offset = 0
            self._inode = None
            self._pending = ""
            return
        except OSError as exc:
            logger.error("Cannot stat EVE file %s: %s", self.path, exc)
            return

        self._reset_if_rotated(stat.st_size, stat.st_ino)

        if stat.st_size == self._offset and not self._pending:
            return

        start_offset = self._offset

        try:
            handle = self.path.open("r", encoding="utf-8", errors="replace")
        except OSError as exc:
            logger.error("Cannot open EVE file %s: %s", self.path, exc)
            return

        with handle:
            try:
                handle.seek(self._offset)
            except OSError as exc:
                logger.error("Cannot seek EVE file: %s", exc)
                return

            data = handle.read()
            self._pending = ""

            if len(data) > self.config.max_line_bytes and "\n" not in data:
                logger.error(
                    "EVE line exceeded %d bytes with no newline, discarding",
                    self.config.max_line_bytes,
                )
                # Skip past the junk so it is not re-read on every cycle.
                self._offset = stat.st_size
                return

            # A record is only complete once its terminating newline is on
            # disk, so the offset advances by the length of emitted lines
            # alone. A trailing unterminated line stays put and is re-read
            # next cycle, which also makes a restart resume cleanly.
            lines = data.split("\n")
            self._pending = lines.pop()
            self._offset += sum(len(line) + 1 for line in lines)
            self.bytes_consumed += self._offset - start_offset

            for line in lines:
                record = parse_eve_line(line)
                if record is not None:
                    yield record

    def seek_to_end(self) -> None:
        """Skip existing content; used by ``--skip-existing`` on first run."""
        try:
            self._offset = os.stat(self.path).st_size
            self._inode = self._current_inode()
            self._loaded = True
            logger.info("Starting from end of EVE file at offset %d", self._offset)
        except OSError:
            self._offset = 0


def _flatten(record: dict[str, Any], sub_key: str) -> dict[str, Any]:
    """Merge an EVE record with its nested sub-object.

    Suricata splits a single event across two levels: 5-tuple addressing
    (``src_ip``, ``dest_port``, ``proto``) sits at the top level while the
    counters and metadata live in a nested object (``flow`` for flow events,
    ``alert`` for alert events). Either half alone is unusable, so the two are
    merged into one view before conversion.

    The top level is applied first and the nested object second, so a key
    present in both prefers the nested value. In practice the two sets are
    disjoint, but the ordering keeps the more specific object authoritative.
    """
    nested = record.get(sub_key)
    if not isinstance(nested, dict):
        return record
    return {**record, **nested}


class EveCollector:
    """Turn raw EVE records into queued flow and alert payloads."""

    def __init__(self, config: ShipperConfig, stats: EveStats):
        self.config = config
        self.stats = stats
        self.local_addresses = local_address_set(
            config.local_addresses,
            detect_interface_addresses() if config.auto_detect_addresses else None,
        )
        if self.local_addresses:
            logger.info("Local addresses: %s", ", ".join(sorted(self.local_addresses)))
        else:
            logger.warning(
                "No local addresses detected; flow byte counters will be "
                "reported from the remote host's perspective"
            )

    def convert(
        self, record: dict[str, Any]
    ) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
        """Return ``(flows, alerts)`` for one EVE record."""
        self.stats.read += 1
        event_type = record.get("event_type")

        if event_type not in ("flow", "alert"):
            self.stats.skipped_type += 1
            if self.config.debug_events:
                logger.debug("Skipping event_type=%s", event_type)
            return [], []

        if event_type == "flow":
            if is_noise_flow(record.get("flow", {})):
                self.stats.noise_flows += 1
                return [], []
            payload = flow_to_flow_ingest(_flatten(record, "flow"), self.local_addresses)
            if payload is None:
                self.stats.malformed += 1
                return [], []
            self.stats.flows += 1
            return [payload], []

        payload = alert_to_log_entry(_flatten(record, "alert"), self.config.source)
        if payload is None:
            self.stats.malformed += 1
            return [], []
        self.stats.alerts += 1
        return [], [payload]
