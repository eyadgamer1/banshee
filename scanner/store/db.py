"""A6 — aiosqlite persistence layer.

Schema:
  scan_runs   — one row per `pps` invocation
  hosts       — one row per discovered host per run
  services    — one row per service per host per run
  findings    — one row per finding per host per run
  mac_baseline — cumulative MAC → first-seen table (drives E2 rogue detection)

Usage:
  async with ScanStore(path) as store:
      run_id = await store.save_result(result)
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import TYPE_CHECKING

import aiosqlite

if TYPE_CHECKING:
    from scanner.core.models import ScanResult

log = logging.getLogger(__name__)

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS scan_runs (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at  TEXT    NOT NULL,
    finished_at TEXT,
    mode        TEXT    NOT NULL,
    banner      TEXT,
    hosts_up    INTEGER NOT NULL DEFAULT 0,
    services    INTEGER NOT NULL DEFAULT 0,
    findings    INTEGER NOT NULL DEFAULT 0,
    config_json TEXT
);

CREATE TABLE IF NOT EXISTS hosts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id      INTEGER NOT NULL REFERENCES scan_runs(id) ON DELETE CASCADE,
    ip          TEXT    NOT NULL,
    hostname    TEXT,
    mac         TEXT,
    vendor      TEXT,
    os_guess    TEXT,
    device_type TEXT,
    state       TEXT    NOT NULL,
    confidence  TEXT    NOT NULL,
    names_json  TEXT,
    first_seen  TEXT,
    last_seen   TEXT
);
CREATE INDEX IF NOT EXISTS idx_hosts_run ON hosts(run_id);
CREATE INDEX IF NOT EXISTS idx_hosts_ip  ON hosts(ip);

CREATE TABLE IF NOT EXISTS services (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id    INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    port       INTEGER NOT NULL,
    proto      TEXT    NOT NULL,
    state      TEXT    NOT NULL,
    name       TEXT,
    product    TEXT,
    version    TEXT,
    banner     TEXT,
    confidence TEXT    NOT NULL,
    source     TEXT
);

CREATE TABLE IF NOT EXISTS findings (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    host_id      INTEGER NOT NULL REFERENCES hosts(id) ON DELETE CASCADE,
    finding_id   TEXT    NOT NULL,
    title        TEXT    NOT NULL,
    severity     TEXT    NOT NULL,
    confidence   TEXT    NOT NULL,
    description  TEXT,
    evidence     TEXT,
    source       TEXT,
    is_llm       INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS mac_baseline (
    mac        TEXT PRIMARY KEY,
    ip         TEXT,
    vendor     TEXT,
    hostname   TEXT,
    first_seen TEXT NOT NULL,
    run_id     INTEGER
);
"""


class ScanStore:
    """Async context manager wrapping an aiosqlite connection."""

    def __init__(self, db_path: str | Path = "pps.db") -> None:
        self._path = Path(db_path)
        self._conn: aiosqlite.Connection | None = None

    async def __aenter__(self) -> ScanStore:
        self._conn = await aiosqlite.connect(self._path)
        self._conn.row_factory = aiosqlite.Row
        await self._conn.executescript(_DDL)
        await self._conn.commit()
        return self

    async def __aexit__(self, *_: object) -> None:
        if self._conn:
            await self._conn.close()
            self._conn = None

    async def save_result(self, result: ScanResult) -> int:
        """Persist a ScanResult; return the new scan_run id."""
        if not self._conn:
            raise RuntimeError("ScanStore not opened — use async with")

        config_json = result.config.model_dump_json()
        cur = await self._conn.execute(
            """INSERT INTO scan_runs
               (started_at, finished_at, mode, banner, hosts_up, services, findings, config_json)
               VALUES (?,?,?,?,?,?,?,?)""",
            (
                result.started_at.isoformat(),
                result.finished_at.isoformat() if result.finished_at else None,
                result.config.mode.value,
                result.banner,
                result.stats.hosts_up,
                result.stats.services_found,
                result.stats.findings,
                config_json,
            ),
        )
        run_id = cur.lastrowid
        assert run_id is not None

        for host in result.hosts:
            host_cur = await self._conn.execute(
                """INSERT INTO hosts
                   (run_id, ip, hostname, mac, vendor, os_guess, device_type,
                    state, confidence, names_json, first_seen, last_seen)
                   VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
                (
                    run_id,
                    host.ip,
                    host.hostname,
                    host.mac,
                    host.vendor,
                    host.os_guess,
                    host.device_type,
                    host.state.value,
                    host.confidence.value,
                    json.dumps(host.names),
                    host.first_seen.isoformat(),
                    host.last_seen.isoformat(),
                ),
            )
            host_id = host_cur.lastrowid
            assert host_id is not None

            for svc in host.services:
                await self._conn.execute(
                    """INSERT INTO services
                       (host_id, port, proto, state, name, product, version,
                        banner, confidence, source)
                       VALUES (?,?,?,?,?,?,?,?,?,?)""",
                    (
                        host_id,
                        svc.port,
                        svc.proto.value,
                        svc.state.value,
                        svc.name,
                        svc.product,
                        svc.version,
                        svc.banner,
                        svc.confidence.value,
                        svc.source,
                    ),
                )

            for finding in host.findings:
                await self._conn.execute(
                    """INSERT INTO findings
                       (host_id, finding_id, title, severity, confidence,
                        description, evidence, source, is_llm)
                       VALUES (?,?,?,?,?,?,?,?,?)""",
                    (
                        host_id,
                        finding.id,
                        finding.title,
                        finding.severity.value,
                        finding.confidence.value,
                        finding.description,
                        finding.evidence,
                        finding.source,
                        int(finding.is_llm_inferred),
                    ),
                )

            # Update MAC baseline
            if host.mac:
                await self._conn.execute(
                    """INSERT OR IGNORE INTO mac_baseline
                       (mac, ip, vendor, hostname, first_seen, run_id)
                       VALUES (?,?,?,?,?,?)""",
                    (
                        host.mac,
                        host.ip,
                        host.vendor,
                        host.hostname,
                        host.first_seen.isoformat(),
                        run_id,
                    ),
                )

        await self._conn.commit()
        log.debug("A6 saved run_id=%d (%d hosts)", run_id, len(result.hosts))
        return run_id

    async def get_known_macs(self) -> set[str]:
        """Return all MACs ever seen (from mac_baseline), lower-cased.

        RogueDetector compares lower-cased MACs; normalising here keeps a MAC
        stored as AA:BB:.. from reading as unknown on the next run.
        """
        if not self._conn:
            raise RuntimeError("ScanStore not opened")
        async with self._conn.execute("SELECT mac FROM mac_baseline") as cur:
            rows = await cur.fetchall()
        return {row["mac"].lower() for row in rows if row["mac"]}

    async def get_runs(self, limit: int = 20) -> list[dict[str, object]]:
        """Return recent scan runs as plain dicts."""
        if not self._conn:
            raise RuntimeError("ScanStore not opened")
        async with self._conn.execute(
            "SELECT * FROM scan_runs ORDER BY id DESC LIMIT ?", (limit,)
        ) as cur:
            rows = await cur.fetchall()
        return [dict(row) for row in rows]
