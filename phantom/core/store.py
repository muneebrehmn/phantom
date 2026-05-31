"""
phantom/core/store.py

SQLite-backed scan state persistence.

WHY THIS EXISTS
───────────────
Without persistence, every Phantom run starts from scratch.  Security teams
cannot:
  - Mark findings as accepted risk, suppressed, or confirmed
  - Track which findings are new vs. already known
  - Produce a delta report ("new findings since last scan")
  - Avoid re-alerting on the same finding in CI/CD pipelines

ScanStore solves this with a lightweight SQLite database stored next to the
report output files.  No server, no config, no external dependency.

SCHEMA
──────
findings     — one row per unique finding fingerprint across all scans
suppressions — operator-managed table: accepted risk / suppressed findings
scans        — metadata for each scan run (target, timestamp, finding count)

FINGERPRINTING
──────────────
A finding is uniquely identified by:
    SHA-256( surface_url + ":" + payload_category + ":" + payload_id )

This fingerprint is stable across runs: the same vulnerability on the same
surface with the same payload class always produces the same fingerprint,
even if the raw_response wording changes slightly.

USAGE
─────
From phantom.py scan pipeline:

    store = ScanStore(config.output_dir / "phantom_store.db")
    store.record_scan(config.target_url, state.findings)
    new_findings = store.filter_new(state.findings)   # findings not seen before
    suppressed   = store.get_suppressions(config.target_url)

From CLI suppression management (future --suppress / --accept-risk flags):

    store.suppress(fingerprint, reason="accepted_risk", note="Low business impact")
    store.unsuppress(fingerprint)
"""

from __future__ import annotations

import hashlib
import json
import sqlite3
import time
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Iterator, List, Optional

from phantom.core.findings import Finding
from phantom.core.logger import get_logger

log = get_logger(__name__)

# Current schema version — increment when schema changes
_SCHEMA_VERSION = 1

_DDL = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS schema_version (
    version INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    target_url    TEXT    NOT NULL,
    started_at    TEXT    NOT NULL,
    finished_at   TEXT,
    finding_count INTEGER DEFAULT 0,
    new_count     INTEGER DEFAULT 0,
    meta          TEXT    DEFAULT '{}'
);

CREATE TABLE IF NOT EXISTS findings (
    fingerprint      TEXT PRIMARY KEY,
    target_url       TEXT    NOT NULL,
    surface_url      TEXT    NOT NULL,
    surface_type     TEXT    NOT NULL,
    payload_category TEXT    NOT NULL,
    payload_id       TEXT    NOT NULL,
    severity         TEXT    NOT NULL,
    confidence       REAL    NOT NULL,
    first_seen       TEXT    NOT NULL,
    last_seen        TEXT    NOT NULL,
    seen_count       INTEGER DEFAULT 1,
    finding_json     TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS suppressions (
    fingerprint  TEXT PRIMARY KEY,
    reason       TEXT NOT NULL DEFAULT 'suppressed',
    note         TEXT DEFAULT '',
    suppressed_at TEXT NOT NULL,
    suppressed_by TEXT DEFAULT 'operator',
    FOREIGN KEY (fingerprint) REFERENCES findings(fingerprint)
);

CREATE INDEX IF NOT EXISTS idx_findings_target  ON findings(target_url);
CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
CREATE INDEX IF NOT EXISTS idx_suppressions_fp  ON suppressions(fingerprint);
"""


# ---------------------------------------------------------------------------
# Suppression record
# ---------------------------------------------------------------------------

@dataclass
class Suppression:
    fingerprint:   str
    reason:        str
    note:          str
    suppressed_at: str
    suppressed_by: str


# ---------------------------------------------------------------------------
# ScanStore
# ---------------------------------------------------------------------------

class ScanStore:
    """
    Persistent store for Phantom scan findings across runs.

    Thread-safe for concurrent reads; writes use WAL mode to avoid blocking.

    Args:
        db_path: Path to the SQLite database file.
                 Created automatically if it does not exist.
    """

    def __init__(self, db_path: Path) -> None:
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._init_schema()

    # ------------------------------------------------------------------
    # Context manager for connections
    # ------------------------------------------------------------------

    @contextmanager
    def _connect(self) -> Iterator[sqlite3.Connection]:
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Schema initialisation
    # ------------------------------------------------------------------

    def _init_schema(self) -> None:
        with self._connect() as conn:
            conn.executescript(_DDL)
            row = conn.execute("SELECT version FROM schema_version").fetchone()
            if row is None:
                conn.execute(
                    "INSERT INTO schema_version(version) VALUES (?)",
                    (_SCHEMA_VERSION,),
                )
        log.debug("[store] Database ready at %s", self.db_path)

    # ------------------------------------------------------------------
    # Scan lifecycle
    # ------------------------------------------------------------------

    def start_scan(self, target_url: str) -> int:
        """
        Record the start of a scan.  Returns the scan ID for use in finish_scan().
        """
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            cur = conn.execute(
                "INSERT INTO scans(target_url, started_at) VALUES (?, ?)",
                (target_url, now),
            )
            return cur.lastrowid

    def finish_scan(self, scan_id: int, findings: List[Finding], new_count: int) -> None:
        """Update the scan record with final finding counts."""
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                """UPDATE scans
                   SET finished_at=?, finding_count=?, new_count=?
                   WHERE id=?""",
                (now, len(findings), new_count, scan_id),
            )

    # ------------------------------------------------------------------
    # Finding persistence
    # ------------------------------------------------------------------

    def record_findings(
        self, target_url: str, findings: List[Finding]
    ) -> List[str]:
        """
        Upsert findings into the store.

        If a finding's fingerprint already exists: increment seen_count
        and update last_seen.  If new: insert fresh.

        Returns a list of fingerprints that are NEW (first time seen).
        """
        now   = datetime.now().isoformat(timespec="seconds")
        new_fps: List[str] = []

        with self._connect() as conn:
            for finding in findings:
                fp = fingerprint(finding)
                existing = conn.execute(
                    "SELECT fingerprint, seen_count FROM findings WHERE fingerprint=?",
                    (fp,),
                ).fetchone()

                if existing:
                    conn.execute(
                        """UPDATE findings
                           SET last_seen=?, seen_count=seen_count+1,
                               confidence=?, finding_json=?
                           WHERE fingerprint=?""",
                        (now, finding.confidence,
                         json.dumps(finding.to_dict()), fp),
                    )
                    log.debug("[store] Updated finding %s (seen %d times)", fp[:12], existing["seen_count"] + 1)
                else:
                    conn.execute(
                        """INSERT INTO findings
                           (fingerprint, target_url, surface_url, surface_type,
                            payload_category, payload_id, severity, confidence,
                            first_seen, last_seen, seen_count, finding_json)
                           VALUES (?,?,?,?,?,?,?,?,?,?,1,?)""",
                        (fp, target_url, finding.surface_url, finding.surface_type,
                         finding.payload_category, finding.payload_id,
                         finding.severity.value, finding.confidence,
                         now, now, json.dumps(finding.to_dict())),
                    )
                    new_fps.append(fp)
                    log.debug("[store] New finding recorded: %s (%s)", fp[:12], finding.payload_id)

        return new_fps

    def filter_new(
        self, target_url: str, findings: List[Finding]
    ) -> List[Finding]:
        """
        Return only findings whose fingerprint has not been seen before
        for this target.  Used for delta reporting in CI/CD pipelines.
        """
        with self._connect() as conn:
            existing_fps = {
                row["fingerprint"]
                for row in conn.execute(
                    "SELECT fingerprint FROM findings WHERE target_url=?",
                    (target_url,),
                )
            }

        return [f for f in findings if fingerprint(f) not in existing_fps]

    def get_history(
        self,
        target_url: str,
        severity: Optional[str] = None,
        limit: int = 100,
    ) -> List[dict]:
        """
        Return stored findings for a target, optionally filtered by severity.

        Returns plain dicts (not Finding objects) since the DB may contain
        findings from older versions.
        """
        query  = "SELECT finding_json FROM findings WHERE target_url=?"
        params = [target_url]
        if severity:
            query  += " AND severity=?"
            params.append(severity)
        query += " ORDER BY last_seen DESC LIMIT ?"
        params.append(limit)

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        results = []
        for row in rows:
            try:
                results.append(json.loads(row["finding_json"]))
            except json.JSONDecodeError:
                pass
        return results

    # ------------------------------------------------------------------
    # Suppression management
    # ------------------------------------------------------------------

    def suppress(
        self,
        fp: str,
        reason: str = "suppressed",
        note: str = "",
        suppressed_by: str = "operator",
    ) -> None:
        """
        Suppress a finding by fingerprint.

        Suppressed findings are excluded from delta reports and CI/CD
        failure conditions.  They remain in the findings table for audit.

        Args:
            fp:           Finding fingerprint (from fingerprint() helper).
            reason:       "suppressed" | "accepted_risk" | "false_positive" | "wont_fix"
            note:         Free-text explanation for the suppression.
            suppressed_by: Username or system that applied the suppression.
        """
        now = datetime.now().isoformat(timespec="seconds")
        with self._connect() as conn:
            conn.execute(
                """INSERT OR REPLACE INTO suppressions
                   (fingerprint, reason, note, suppressed_at, suppressed_by)
                   VALUES (?,?,?,?,?)""",
                (fp, reason, note, now, suppressed_by),
            )
        log.info("[store] Suppressed finding %s (%s)", fp[:12], reason)

    def unsuppress(self, fp: str) -> None:
        """Remove a suppression — finding will appear in future delta reports."""
        with self._connect() as conn:
            conn.execute("DELETE FROM suppressions WHERE fingerprint=?", (fp,))
        log.info("[store] Unsuppressed finding %s", fp[:12])

    def is_suppressed(self, fp: str) -> bool:
        """Return True if the fingerprint has an active suppression."""
        with self._connect() as conn:
            row = conn.execute(
                "SELECT 1 FROM suppressions WHERE fingerprint=?", (fp,)
            ).fetchone()
        return row is not None

    def get_suppressions(self, target_url: Optional[str] = None) -> List[Suppression]:
        """
        Return all active suppressions, optionally filtered by target.

        If target_url is None, returns suppressions for all targets.
        """
        if target_url:
            query = """
                SELECT s.* FROM suppressions s
                JOIN findings f ON s.fingerprint = f.fingerprint
                WHERE f.target_url=?
            """
            params = [target_url]
        else:
            query  = "SELECT * FROM suppressions"
            params = []

        with self._connect() as conn:
            rows = conn.execute(query, params).fetchall()

        return [
            Suppression(
                fingerprint=r["fingerprint"],
                reason=r["reason"],
                note=r["note"],
                suppressed_at=r["suppressed_at"],
                suppressed_by=r["suppressed_by"],
            )
            for r in rows
        ]

    def filter_suppressed(self, findings: List[Finding]) -> List[Finding]:
        """
        Return findings that are NOT suppressed.

        Used by the report builder to exclude accepted-risk findings from
        active reports while keeping them in the database for audit.
        """
        with self._connect() as conn:
            suppressed_fps = {
                row["fingerprint"] for row in conn.execute("SELECT fingerprint FROM suppressions")
            }
        return [f for f in findings if fingerprint(f) not in suppressed_fps]

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    def stats(self, target_url: Optional[str] = None) -> dict:
        """Return a summary dict of stored findings and scan history."""
        with self._connect() as conn:
            if target_url:
                total = conn.execute(
                    "SELECT COUNT(*) as n FROM findings WHERE target_url=?", (target_url,)
                ).fetchone()["n"]
                scans = conn.execute(
                    "SELECT COUNT(*) as n FROM scans WHERE target_url=?", (target_url,)
                ).fetchone()["n"]
                suppressed = conn.execute(
                    """SELECT COUNT(*) as n FROM suppressions s
                       JOIN findings f ON s.fingerprint=f.fingerprint
                       WHERE f.target_url=?""",
                    (target_url,),
                ).fetchone()["n"]
            else:
                total      = conn.execute("SELECT COUNT(*) as n FROM findings").fetchone()["n"]
                scans      = conn.execute("SELECT COUNT(*) as n FROM scans").fetchone()["n"]
                suppressed = conn.execute("SELECT COUNT(*) as n FROM suppressions").fetchone()["n"]

        return {
            "total_findings":     total,
            "suppressed_findings": suppressed,
            "active_findings":    total - suppressed,
            "total_scans":        scans,
            "db_path":            str(self.db_path),
        }


# ---------------------------------------------------------------------------
# Fingerprint helper
# ---------------------------------------------------------------------------

def fingerprint(finding: Finding) -> str:
    """
    Compute a stable fingerprint for a finding.

    Stable means: same surface + same payload category + same payload ID
    always produces the same fingerprint, regardless of response text.

    This lets the store recognise the same vulnerability across scan runs
    even when the exact response wording changes.
    """
    key = f"{finding.surface_url}:{finding.payload_category}:{finding.payload_id}"
    return hashlib.sha256(key.encode()).hexdigest()