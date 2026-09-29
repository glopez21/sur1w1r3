"""Standalone SQLite buffering for flow and alert delivery."""

from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from pathlib import Path
from typing import Any


class ShipQueue:
    """Durable, kind-partitioned SQLite queue with retry/dead-letter handling.

    Flows and alerts have independent claims, so an unavailable sink cannot
    block delivery to the other. Existing databases written by the original
    shipper (which used threatpulse-agent's queue schema) are migrated in place.
    """

    def __init__(self, path: str | Path, max_retries: int = 5):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._max_retries = max_retries
        self._lock = threading.Lock()
        old_umask = os.umask(0o077)
        try:
            self._conn = sqlite3.connect(
                str(self._path), timeout=30, check_same_thread=False
            )
        finally:
            os.umask(old_umask)
        # The spool contains raw security telemetry. Tighten existing databases
        # too, including any WAL sidecars left by a previous process.
        for path in (self._path, Path(f"{self._path}-wal"), Path(f"{self._path}-shm")):
            if path.exists():
                path.chmod(0o600)
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA synchronous=FULL")
        self._conn.execute(
            """CREATE TABLE IF NOT EXISTS entries (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                payload TEXT NOT NULL,
                created_at REAL NOT NULL,
                retries INTEGER NOT NULL DEFAULT 0,
                last_error TEXT,
                locked_at REAL,
                locked_by TEXT,
                kind TEXT
            )"""
        )
        # Migrate databases created by the first shipper, whose queue table
        # stored kind inside JSON but did not have an indexed kind column.
        columns = {row[1] for row in self._conn.execute("PRAGMA table_info(entries)")}
        if "kind" not in columns:
            self._conn.execute("ALTER TABLE entries ADD COLUMN kind TEXT")
        rows = self._conn.execute(
            "SELECT id, payload FROM entries WHERE kind IS NULL"
        ).fetchall()
        for entry_id, raw in rows:
            try:
                kind = json.loads(raw).get("kind")
            except (ValueError, TypeError, AttributeError):
                kind = None
            if kind in ("flow", "alert"):
                self._conn.execute("UPDATE entries SET kind = ? WHERE id = ?", (kind, entry_id))
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_kind_id ON entries(kind, id)")
        self._conn.execute("CREATE INDEX IF NOT EXISTS idx_entries_locked ON entries(locked_at)")
        self._conn.commit()
        self._release_stale_locks(300)
        self.path = str(path)

    def put_flows(self, flows: list[dict[str, Any]]) -> int:
        return self._put("flow", flows)

    def put_alerts(self, alerts: list[dict[str, Any]]) -> int:
        return self._put("alert", alerts)

    def _put(self, kind: str, items: list[dict[str, Any]]) -> int:
        if not items:
            return 0
        now = time.time()
        rows = [
            (kind, json.dumps({"kind": kind, "data": item}, default=str), now)
            for item in items
        ]
        with self._lock:
            self._conn.executemany(
                "INSERT INTO entries (kind, payload, created_at) VALUES (?, ?, ?)", rows
            )
            self._conn.commit()
        return len(rows)

    def claim(self, kind: str, batch_size: int, lock_seconds: int = 60) -> list[dict[str, Any]]:
        """Claim deliverable entries of ``kind`` without locking other sinks."""
        if batch_size <= 0 or kind not in ("flow", "alert"):
            return []
        now = time.time()
        claim_token = f"shipper-{uuid.uuid4().hex}"
        with self._lock:
            self._conn.execute("BEGIN IMMEDIATE")
            # Recover claims left behind by a crashed process.
            self._conn.execute(
                "UPDATE entries SET locked_at = NULL, locked_by = NULL "
                "WHERE locked_at IS NOT NULL AND locked_at < ?",
                (now - lock_seconds,),
            )
            rows = self._conn.execute(
                "SELECT id, payload FROM entries WHERE kind = ? AND retries < ? "
                "AND locked_at IS NULL ORDER BY id LIMIT ?",
                (kind, self._max_retries, batch_size),
            ).fetchall()
            ids = [row[0] for row in rows]
            if ids:
                placeholders = ",".join("?" for _ in ids)
                self._conn.execute(
                    f"UPDATE entries SET locked_at = ?, locked_by = ? WHERE id IN ({placeholders})",
                    [now, claim_token, *ids],
                )
            self._conn.commit()
        return [{"id": row[0], "payload": json.loads(row[1])} for row in rows]

    def ack(self, entry_ids: list[int]) -> None:
        if entry_ids:
            placeholders = ",".join("?" for _ in entry_ids)
            with self._lock:
                self._conn.execute(f"DELETE FROM entries WHERE id IN ({placeholders})", entry_ids)
                self._conn.commit()

    def fail(self, failures: list[tuple[int, str]], increment_retries: bool = True) -> None:
        if failures:
            with self._lock:
                for entry_id, error in failures:
                    if increment_retries:
                        self._conn.execute(
                            "UPDATE entries SET retries = retries + 1, last_error = ?, "
                            "locked_at = NULL, locked_by = NULL WHERE id = ?",
                            (error[:500], entry_id),
                        )
                    else:
                        self._conn.execute(
                            "UPDATE entries SET locked_at = NULL, locked_by = NULL WHERE id = ?",
                            (entry_id,),
                        )
                self._conn.commit()

    def depth(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM entries WHERE retries < ?", (self._max_retries,)
            ).fetchone()
        return int(row[0])

    def depth_by_kind(self) -> dict[str, int]:
        """Count deliverable entries per sink without mutating queue state."""
        with self._lock:
            rows = self._conn.execute(
                "SELECT kind, COUNT(*) FROM entries WHERE retries < ? GROUP BY kind",
                (self._max_retries,),
            ).fetchall()
        return {kind: count for kind, count in rows if kind}

    def dead_letters(self) -> int:
        with self._lock:
            row = self._conn.execute(
                "SELECT COUNT(*) FROM entries WHERE retries >= ?", (self._max_retries,)
            ).fetchone()
        return int(row[0])

    def enforce_max_depth(self, max_rows: int) -> int:
        if max_rows <= 0:
            return 0
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM entries WHERE id IN ("
                "SELECT id FROM entries ORDER BY id DESC LIMIT -1 OFFSET ?)",
                (max_rows,),
            )
            self._conn.commit()
        return cur.rowcount or 0

    def sweep(self, stale_seconds: float = 300.0, max_depth: int = 0) -> dict[str, int]:
        released = self._release_stale_locks(stale_seconds)
        purged = self.purge_dead_letters()
        evicted = self.enforce_max_depth(max_depth)
        self.checkpoint()
        return {"released": released, "purged": purged, "evicted": evicted}

    def _release_stale_locks(self, stale_seconds: float) -> int:
        with self._lock:
            cur = self._conn.execute(
                "UPDATE entries SET locked_at = NULL, locked_by = NULL "
                "WHERE locked_at IS NOT NULL AND locked_at < ?",
                (time.time() - stale_seconds,),
            )
            self._conn.commit()
        return cur.rowcount or 0

    def purge_dead_letters(self, older_than_seconds: int = 86400) -> int:
        cutoff = time.time() - older_than_seconds
        with self._lock:
            cur = self._conn.execute(
                "DELETE FROM entries WHERE retries >= ? AND created_at < ?",
                (self._max_retries, cutoff),
            )
            self._conn.commit()
        return cur.rowcount or 0

    def checkpoint(self) -> None:
        with self._lock:
            self._conn.execute("PRAGMA wal_checkpoint(PASSIVE)")

    def close(self) -> None:
        with self._lock:
            if self._conn is not None:
                self._conn.close()
                self._conn = None


class PositionStore:
    """Persists the EVE read offset so restarts do not re-ship the file.

    Stores ``(offset, inode, updated_at)`` as JSON. The inode lets the reader
    detect rotation; ``updated_at`` lets an operator see whether the shipper is
    actually advancing.
    """

    def __init__(self, path: str | Path):
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)

    def load(self) -> tuple[int, int | None]:
        import json

        try:
            data = json.loads(self._path.read_text())
            return int(data.get("offset", 0)), data.get("inode")
        except (OSError, ValueError, TypeError):
            return 0, None

    def save(self, offset: int, inode: int | None) -> None:
        import json

        payload = {"offset": offset, "inode": inode, "updated_at": time.time()}
        tmp = self._path.with_suffix(".tmp")
        # Write-then-rename so a crash mid-write cannot corrupt the position.
        tmp.write_text(json.dumps(payload))
        tmp.replace(self._path)
