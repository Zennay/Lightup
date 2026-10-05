from __future__ import annotations

import hashlib
import json
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from uuid import uuid4


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    target TEXT NOT NULL,
    authorization_ref TEXT,
    activation_mode TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS capability_leases (
    run_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    worker_id TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    PRIMARY KEY (run_id, capability_id),
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS evidence (
    evidence_id TEXT PRIMARY KEY,
    run_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    kind TEXT NOT NULL,
    source TEXT NOT NULL,
    sha256 TEXT NOT NULL,
    metadata_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS future_attack_path_transition_resolutions (
    resolution_id TEXT PRIMARY KEY,
    resolution_sha256 TEXT NOT NULL,
    client_id TEXT NOT NULL,
    run_id TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (run_id) REFERENCES runs(run_id) ON DELETE CASCADE
);
"""


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


@dataclass(frozen=True)
class Lease:
    run_id: str
    capability_id: str
    worker_id: str
    expires_at: datetime


@dataclass(frozen=True)
class EvidenceRecord:
    evidence_id: str
    run_id: str
    capability_id: str
    kind: str
    source: str
    sha256: str
    metadata: tuple[tuple[str, str], ...]
    created_at: str


class StateStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self.connect() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def connect(self):
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        try:
            yield con
        finally:
            con.close()

    def create_run(
        self,
        target: str,
        activation_mode: str = "plan_only",
        authorization_ref: str | None = None,
    ) -> str:
        run_id = str(uuid4())
        with self.connect() as con:
            con.execute(
                "INSERT INTO runs(run_id,target,authorization_ref,activation_mode,status,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (run_id, target, authorization_ref, activation_mode, "planned", utcnow().isoformat()),
            )
        return run_id

    def acquire_lease(
        self,
        run_id: str,
        capability_id: str,
        worker_id: str,
        ttl_seconds: int = 600,
    ) -> Lease:
        if not 15 <= ttl_seconds <= 3600:
            raise ValueError("lease TTL must be between 15 and 3600 seconds")

        now = utcnow()
        expires_at = now + timedelta(seconds=ttl_seconds)
        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT worker_id, expires_at FROM capability_leases "
                "WHERE run_id=? AND capability_id=?",
                (run_id, capability_id),
            ).fetchone()
            if row is not None:
                existing_expiry = datetime.fromisoformat(row["expires_at"])
                if existing_expiry > now and row["worker_id"] != worker_id:
                    con.execute("ROLLBACK")
                    raise RuntimeError(
                        f"capability already leased by {row['worker_id']} until {row['expires_at']}"
                    )
            con.execute(
                "INSERT INTO capability_leases(run_id, capability_id, worker_id, expires_at) "
                "VALUES(?,?,?,?) "
                "ON CONFLICT(run_id, capability_id) DO UPDATE SET "
                "worker_id=excluded.worker_id, expires_at=excluded.expires_at",
                (run_id, capability_id, worker_id, expires_at.isoformat()),
            )
            con.execute("COMMIT")
        return Lease(run_id, capability_id, worker_id, expires_at)

    def add_evidence(
        self,
        run_id: str,
        capability_id: str,
        kind: str,
        source: str,
        payload: bytes,
        metadata: dict | None = None,
    ) -> str:
        evidence_id = str(uuid4())
        digest = hashlib.sha256(payload).hexdigest()
        metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
        with self.connect() as con:
            con.execute(
                "INSERT INTO evidence("
                "evidence_id,run_id,capability_id,kind,source,sha256,metadata_json,created_at"
                ") VALUES(?,?,?,?,?,?,?,?)",
                (
                    evidence_id,
                    run_id,
                    capability_id,
                    kind,
                    source,
                    digest,
                    metadata_json,
                    utcnow().isoformat(),
                ),
            )
        return evidence_id

    def record_future_attack_path_transition_resolution(
        self,
        resolution_id: str,
        resolution_sha256: str,
        client_id: str,
        run_id: str,
    ) -> bool:
        """Record one immutable transition resolution.

        Returns True when newly inserted and False for an exact replay.
        Reusing a resolution ID with different semantics fails closed.
        """
        for name, value in (
            ("resolution_id", resolution_id),
            ("resolution_sha256", resolution_sha256),
            ("client_id", client_id),
            ("run_id", run_id),
        ):
            if not value.strip():
                raise ValueError(f"{name} is required")

        with self.connect() as con:
            con.execute("BEGIN IMMEDIATE")
            row = con.execute(
                "SELECT resolution_sha256, client_id, run_id "
                "FROM future_attack_path_transition_resolutions "
                "WHERE resolution_id=?",
                (resolution_id,),
            ).fetchone()
            if row is None:
                con.execute(
                    "INSERT INTO future_attack_path_transition_resolutions("
                    "resolution_id,resolution_sha256,client_id,run_id,created_at"
                    ") VALUES(?,?,?,?,?)",
                    (
                        resolution_id,
                        resolution_sha256,
                        client_id,
                        run_id,
                        utcnow().isoformat(),
                    ),
                )
                con.execute("COMMIT")
                return True

            if (
                row["resolution_sha256"] == resolution_sha256
                and row["client_id"] == client_id
                and row["run_id"] == run_id
            ):
                con.execute("COMMIT")
                return False

            con.execute("ROLLBACK")
            raise ValueError(
                "future attack-path transition resolution ID collision"
            )

    def get_future_attack_path_transition_resolution(
        self,
        resolution_id: str,
    ) -> tuple[str, str, str] | None:
        if not resolution_id.strip():
            raise ValueError("resolution_id is required")
        with self.connect() as con:
            row = con.execute(
                "SELECT resolution_sha256, client_id, run_id "
                "FROM future_attack_path_transition_resolutions "
                "WHERE resolution_id=?",
                (resolution_id,),
            ).fetchone()
        if row is None:
            return None
        return (
            row["resolution_sha256"],
            row["client_id"],
            row["run_id"],
        )

    def get_evidence(self, evidence_id: str) -> EvidenceRecord:
        if not evidence_id.strip():
            raise ValueError("evidence_id is required")
        with self.connect() as con:
            row = con.execute(
                "SELECT evidence_id,run_id,capability_id,kind,source,sha256,"
                "metadata_json,created_at FROM evidence WHERE evidence_id=?",
                (evidence_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown evidence {evidence_id!r}")
        metadata_raw = json.loads(row["metadata_json"])
        if not isinstance(metadata_raw, dict):
            raise ValueError(f"evidence {evidence_id!r} has invalid metadata")
        return EvidenceRecord(
            evidence_id=row["evidence_id"],
            run_id=row["run_id"],
            capability_id=row["capability_id"],
            kind=row["kind"],
            source=row["source"],
            sha256=row["sha256"],
            metadata=tuple(
                sorted((str(key), str(value)) for key, value in metadata_raw.items())
            ),
            created_at=row["created_at"],
        )
