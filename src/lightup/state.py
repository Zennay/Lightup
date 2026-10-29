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

CREATE TABLE IF NOT EXISTS lab_evaluations (
    record_id TEXT PRIMARY KEY,
    scenario_id TEXT NOT NULL,
    run_id TEXT NOT NULL UNIQUE,
    created_at TEXT NOT NULL,
    record_json TEXT NOT NULL,
    record_sha256 TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_lab_evaluations_scenario_created
    ON lab_evaluations(scenario_id, created_at DESC);
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


    def add_lab_evaluation(self, record: dict) -> str:
        """Persist one lab evaluation as canonical JSON for later comparison."""
        required = ("record_id", "scenario_id", "run_id", "engine_version",
                    "model_bindings", "evidence_ids", "metrics", "created_at", "notes")
        if not isinstance(record, dict) or any(key not in record for key in required):
            raise ValueError("lab evaluation record is incomplete")
        for key in ("record_id", "scenario_id", "run_id", "engine_version", "created_at"):
            if not isinstance(record[key], str) or not record[key].strip():
                raise ValueError(f"lab evaluation {key} is required")
        if not isinstance(record["notes"], str) or not isinstance(record["metrics"], dict):
            raise ValueError("lab evaluation notes or metrics have an invalid shape")
        bindings = record["model_bindings"]
        if not isinstance(bindings, (tuple, list)) or any(
            not isinstance(pair, (tuple, list)) or len(pair) != 2
            or any(not isinstance(value, str) for value in pair) for pair in bindings
        ):
            raise ValueError("lab evaluation model bindings must be string pairs")
        evidence_ids = record["evidence_ids"]
        if (not isinstance(evidence_ids, (tuple, list))
                or any(not isinstance(item, str) or not item.strip() for item in evidence_ids)
                or len(set(evidence_ids)) != len(evidence_ids)):
            raise ValueError("lab evaluation evidence IDs must be unique non-empty strings")
        encoded = json.dumps(record, sort_keys=True, separators=(",", ":"), allow_nan=False)
        digest = hashlib.sha256(encoded.encode("utf-8")).hexdigest()
        with self.connect() as con:
            con.execute(
                "INSERT INTO lab_evaluations(record_id,scenario_id,run_id,created_at,record_json,record_sha256) "
                "VALUES(?,?,?,?,?,?)",
                (record["record_id"], record["scenario_id"], record["run_id"],
                 record["created_at"], encoded, digest),
            )
        return record["record_id"]

    @staticmethod
    def _decode_lab_evaluation(row: sqlite3.Row) -> dict:
        encoded = row["record_json"]
        if hashlib.sha256(encoded.encode("utf-8")).hexdigest() != row["record_sha256"]:
            raise ValueError("persisted lab evaluation checksum mismatch")
        record = json.loads(encoded)
        if (not isinstance(record, dict) or record.get("record_id") != row["record_id"]
                or record.get("scenario_id") != row["scenario_id"]
                or record.get("run_id") != row["run_id"]):
            raise ValueError("persisted lab evaluation identity does not match its index")
        return record

    def get_lab_evaluation(self, record_id: str) -> dict:
        if not isinstance(record_id, str) or not record_id.strip():
            raise ValueError("record_id is required")
        with self.connect() as con:
            row = con.execute(
                "SELECT record_id,scenario_id,run_id,record_json,record_sha256 FROM lab_evaluations WHERE record_id=?",
                (record_id,),
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown lab evaluation {record_id!r}")
        return self._decode_lab_evaluation(row)

    def list_lab_evaluations(self, scenario_id: str | None = None, limit: int = 20) -> list[dict]:
        if type(limit) is not int or not 1 <= limit <= 1000:
            raise ValueError("limit must be an integer between 1 and 1000")
        if scenario_id is not None and (not isinstance(scenario_id, str) or not scenario_id.strip()):
            raise ValueError("scenario_id must be a non-empty string when provided")
        query = "SELECT record_id,scenario_id,run_id,record_json,record_sha256 FROM lab_evaluations "
        params: tuple = (limit,)
        if scenario_id is not None:
            query += "WHERE scenario_id=? "
            params = (scenario_id, limit)
        query += "ORDER BY created_at DESC, record_id DESC LIMIT ?"
        with self.connect() as con:
            rows = con.execute(query, params).fetchall()
        return [self._decode_lab_evaluation(row) for row in rows]
