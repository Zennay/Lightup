"""Offline-only, non-authorizing durable attempt bookkeeping reference (#1454).

Never imported by the installed executor. The caller supplies a disposable SQLite
connection; no callbacks, tool handlers, targets, socket clients or grants exist here.
A REVIEW_ONLY receipt has *six false permission flags* and must never dispatch.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import re
import sqlite3


_ID = re.compile(r"fixture-[a-z0-9-]{1,48}\Z", re.ASCII)
_ASSET = re.compile(r"fixture-[a-z0-9-]{1,48}\.invalid\Z", re.ASCII)
_SHA = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_SCHEMA = """
CREATE TABLE IF NOT EXISTS offline_scope_1454_attempts (
    attempt_id TEXT PRIMARY KEY,
    sealed_binding TEXT NOT NULL,
    operation_fingerprint TEXT NOT NULL UNIQUE,
    phase TEXT NOT NULL CHECK(phase IN ('reserved', 'uncertain', 'recorded')),
    evidence_digest TEXT
);
"""


@dataclass(frozen=True)
class SyntheticAttempt:
    attempt_id: str
    run_id: str
    client_id: str
    engagement_id: str
    grant_id: str
    tool_id: str
    capability_id: str
    asset: str
    risk: int


@dataclass(frozen=True)
class ReviewReceipt:
    status: str
    reason: str
    authorization_allowed: bool = False
    permit_allowed: bool = False
    dispatch_allowed: bool = False
    merge_allowed: bool = False
    deploy_allowed: bool = False
    release_allowed: bool = False

    def __post_init__(self) -> None:
        # Prevent a caller constructing an "APPROVED" or truthy receipt with
        # the same schema as the non-authorizing reviewer output.
        expected = {
            "HOLD": "manual_review_required",
            "REVIEW_ONLY": "not_an_execution_authorization",
        }
        if (
            type(self) is not ReviewReceipt
            or type(self.status) is not str
            or type(self.reason) is not str
            or expected.get(self.status) != self.reason
            or any(
                type(getattr(self, field)) is not bool
                or getattr(self, field) is not False
                for field in (
                    "authorization_allowed", "permit_allowed", "dispatch_allowed",
                    "merge_allowed", "deploy_allowed", "release_allowed",
                )
            )
        ):
            raise ValueError("offline review receipt must be non-authorizing")

    def __bool__(self) -> bool:
        raise TypeError("an offline receipt can never act as execution permission")

    def as_dict(self) -> dict[str, object]:
        # Fixed literal output; never includes an ID, hash, path or exception.
        expected = {
            "HOLD": "manual_review_required",
            "REVIEW_ONLY": "not_an_execution_authorization",
        }
        state = vars(self) if type(self) is ReviewReceipt else {}
        schema = {
            "status", "reason", "authorization_allowed", "permit_allowed",
            "dispatch_allowed", "merge_allowed", "deploy_allowed",
            "release_allowed",
        }
        canonical = (
            type(state) is dict
            and set(state) == schema
            and type(state["status"]) is str
            and type(state["reason"]) is str
            and expected.get(state["status"]) == state["reason"]
            and all(type(state[k]) is bool and state[k] is False
                    for k in schema - {"status", "reason"})
        )
        status = state["status"] if canonical else "HOLD"
        reason = expected[status]
        return {
            "status": status,
            "reason": reason,
            "authorization_allowed": False,
            "permit_allowed": False,
            "dispatch_allowed": False,
            "merge_allowed": False,
            "deploy_allowed": False,
            "release_allowed": False,
        }


@dataclass(frozen=True)
class OfflineBacklogReview:
    """Aggregate counts only; never an executable capability or consent token."""

    receipt: ReviewReceipt
    reserved_count: int
    uncertain_count: int
    recorded_count: int

    def __post_init__(self) -> None:
        if (
            type(self) is not OfflineBacklogReview
            or type(self.receipt) is not ReviewReceipt
            or any(type(n) is not int or not 0 <= n <= 256 for n in (
                self.reserved_count, self.uncertain_count, self.recorded_count
            ))
            or self.reserved_count + self.uncertain_count + self.recorded_count > 256
            or (self.receipt.status == "HOLD" and
                (self.reserved_count or self.uncertain_count or self.recorded_count))
        ):
            raise ValueError("invalid offline backlog review")

    def __bool__(self) -> bool:
        raise TypeError("an offline backlog can never act as permission")

    def as_dict(self) -> dict[str, object]:
        # Frozen instances are not a security boundary against in-process
        # object.__setattr__. Never echo mutated counts or forged metadata.
        state = vars(self) if type(self) is OfflineBacklogReview else {}
        valid = (
            type(state) is dict
            and set(state) == {
                "receipt", "reserved_count", "uncertain_count", "recorded_count"
            }
            and type(state["receipt"]) is ReviewReceipt
            and all(type(state[k]) is int and 0 <= state[k] <= 256 for k in (
                "reserved_count", "uncertain_count", "recorded_count"
            ))
            and sum(state[k] for k in (
                "reserved_count", "uncertain_count", "recorded_count"
            )) <= 256
        )
        safe = state["receipt"].as_dict() if valid else _hold().as_dict()
        trustworthy = safe["status"] == "REVIEW_ONLY"
        return {
            **safe,
            "reserved_count": self.reserved_count if trustworthy else 0,
            "uncertain_count": self.uncertain_count if trustworthy else 0,
            "recorded_count": self.recorded_count if trustworthy else 0,
            "requires_manual_reconciliation": (
                self.reserved_count + self.uncertain_count if trustworthy else 0
            ),
        }


def _hold() -> ReviewReceipt:
    return ReviewReceipt("HOLD", "manual_review_required")


def _review() -> ReviewReceipt:
    return ReviewReceipt("REVIEW_ONLY", "not_an_execution_authorization")


def _sealed(attempt: SyntheticAttempt) -> str | None:
    # Exact dataclass and built-in primitive identity; never fall back to repr
    # or implicitly normalized data that can refer to another tenant/asset.
    if type(attempt) is not SyntheticAttempt:
        return None
    try:
        fields = (
            attempt.attempt_id, attempt.run_id, attempt.client_id,
            attempt.engagement_id, attempt.grant_id, attempt.tool_id,
            attempt.capability_id,
        )
        if not all(type(v) is str and _ID.fullmatch(v) for v in fields):
            return None
        if type(attempt.asset) is not str or not _ASSET.fullmatch(attempt.asset):
            return None
        if type(attempt.risk) is not int or not 0 <= attempt.risk <= 4:
            return None
        payload = json.dumps(
            [*fields, attempt.asset, attempt.risk],
            separators=(",", ":"), ensure_ascii=True,
        ).encode("ascii")
        return hashlib.sha256(payload).hexdigest()
    except (AttributeError, TypeError, ValueError, UnicodeError):
        return None


def _operation_fingerprint(attempt: SyntheticAttempt) -> str | None:
    """Stable per-run synthetic action key, independent of an arbitrary attempt ID."""
    if _sealed(attempt) is None:
        return None
    details = (
        attempt.run_id, attempt.client_id, attempt.engagement_id,
        attempt.grant_id, attempt.tool_id, attempt.capability_id,
        attempt.asset, attempt.risk,
    )
    return hashlib.sha256(
        json.dumps(details, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    ).hexdigest()


class OfflineAttemptJournal:
    """Synthetic SQLite reference, deliberately NOT an execution wrapper.

    Do not pass customer database connections. If the database has *any*
    pre-existing table besides this tool's own synthetic table, construction
    refuses it before schema writes. Use only throwaway in-memory/temp DBs.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection or connection.in_transaction:
            raise ValueError("synthetic offline connection required")
        def _canonical_sql(sql: str) -> str:
            return " ".join(sql.strip().rstrip(";").split()).casefold()

        expected = {
            _canonical_sql(_SCHEMA),
            _canonical_sql(_SCHEMA.replace("IF NOT EXISTS ", "")),
        }

        def _trusted_schema() -> bool:
            # An attacker-controlled same-name table, trigger, view, attached
            # DB or TEMP shadow table must never be counted as a reservation.
            databases = [row[1] for row in connection.execute("PRAGMA database_list")]
            # SQLite may instantiate its built-in TEMP schema on a read of
            # sqlite_temp_master even when that schema contains no objects.
            # Only foreign ATTACH aliases are forbidden unconditionally.
            if "main" not in databases or any(
                name not in {"main", "temp"} for name in databases
            ):
                return False
            if connection.execute(
                "SELECT 1 FROM sqlite_temp_master LIMIT 1"
            ).fetchone() is not None:
                return False
            objects = connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
            if len(objects) != 1:
                return False
            kind, name, sql = objects[0]
            return (
                kind == "table"
                and name == "offline_scope_1454_attempts"
                and type(sql) is str
                and _canonical_sql(sql) in expected
            )

        try:
            # Read-only schema inspection BEFORE any write. Existing unrelated
            # customer tables, views, triggers or attached databases are denied.
            objects = connection.execute(
                "SELECT type,name,sql FROM sqlite_master WHERE sql IS NOT NULL"
            ).fetchall()
            if objects:
                if not _trusted_schema():
                    raise ValueError("synthetic offline connection required")
            else:
                db_names = [row[1] for row in connection.execute(
                    "PRAGMA database_list"
                )]
                if "main" not in db_names or any(
                    name not in {"main", "temp"} for name in db_names
                ):
                    raise ValueError("synthetic offline connection required")
                if connection.execute(
                    "SELECT 1 FROM sqlite_temp_master LIMIT 1"
                ).fetchone() is not None:
                    raise ValueError("synthetic offline connection required")
            connection.execute(_SCHEMA)
            connection.commit()
            if not _trusted_schema():
                raise ValueError("synthetic offline connection required")
        except sqlite3.Error:
            raise ValueError("synthetic offline connection required") from None
        self._con = connection
        # Retain the inspector for EVERY operation, not only construction.
        # SQLite schema can change on the supplied connection after init.
        self._schema_valid = _trusted_schema

    def _rollback_quietly(self) -> None:
        try:
            self._con.rollback()
        except sqlite3.Error:
            # A dead connection must not turn a denied synthetic attempt
            # into a traceback or mask the original database failure.
            pass

    def _transition(
        self, attempt: SyntheticAttempt, expected: str, next_phase: str,
        evidence_digest: str | None = None,
    ) -> ReviewReceipt:
        binding = _sealed(attempt)
        fingerprint = _operation_fingerprint(attempt)
        if binding is None or fingerprint is None:
            return _hold()
        owned_transaction = False
        try:
            if self._con.in_transaction:
                # Never roll back a transaction owned by a different caller.
                return _hold()
            self._con.execute("BEGIN IMMEDIATE")
            owned_transaction = True
            # Inspect under the same SQLite write transaction as mutation.
            # No REVIEW_ONLY receipt may survive later trigger/table/ATTACH
            # injection or a TEMP-table shadow introduced after init.
            if not self._schema_valid():
                self._rollback_quietly()
                return _hold()
            row = self._con.execute(
                "SELECT sealed_binding,operation_fingerprint,phase,evidence_digest "
                "FROM offline_scope_1454_attempts "
                "WHERE attempt_id=?", (attempt.attempt_id,)
            ).fetchone()
            # A record must remain bound to the SAME operation, not just the
            # same attempt ID; no already-filled evidence on reserved phase.
            if (row is None or tuple(row) != (binding, fingerprint, expected, None)):
                self._rollback_quietly()
                return _hold()
            self._con.execute(
                "UPDATE offline_scope_1454_attempts SET phase=?,evidence_digest=? "
                "WHERE attempt_id=? AND sealed_binding=? AND phase=?",
                (next_phase, evidence_digest, attempt.attempt_id, binding, expected)
            )
            if self._con.execute("SELECT changes()").fetchone()[0] != 1:
                self._rollback_quietly()
                return _hold()
            observed = self._con.execute(
                "SELECT phase,evidence_digest FROM offline_scope_1454_attempts "
                "WHERE attempt_id=? AND sealed_binding=?",
                (attempt.attempt_id, binding),
            ).fetchone()
            if observed is None or tuple(observed) != (next_phase, evidence_digest):
                self._rollback_quietly()
                return _hold()
            self._con.commit()
            return _review()
        except sqlite3.Error:
            if owned_transaction:
                self._rollback_quietly()
            return _hold()

    def reserve(self, attempt: SyntheticAttempt) -> ReviewReceipt:
        """Persist fixture identity before an *external* mock callback.

        A reservation only records evidence of review. It never confers
        consent, isolation, handler permission, or a replayable lease.
        """
        binding = _sealed(attempt)
        fingerprint = _operation_fingerprint(attempt)
        if binding is None or fingerprint is None:
            return _hold()
        owned_transaction = False
        try:
            if self._con.in_transaction:
                # Never roll back a transaction owned by a different caller.
                return _hold()
            self._con.execute("BEGIN IMMEDIATE")
            owned_transaction = True
            # Inspect under the same SQLite write transaction as mutation.
            # No REVIEW_ONLY receipt may survive later trigger/table/ATTACH
            # injection or a TEMP-table shadow introduced after init.
            if not self._schema_valid():
                self._rollback_quietly()
                return _hold()
            self._con.execute(
                "INSERT INTO offline_scope_1454_attempts "
                "(attempt_id,sealed_binding,operation_fingerprint,phase,evidence_digest) "
                "VALUES(?,?,?,'reserved',NULL)",
                (attempt.attempt_id, binding, fingerprint),
            )
            # A trigger installed *after* journal construction must never make
            # an ignored or altered INSERT look like a successful reservation.
            if self._con.execute("SELECT changes()").fetchone()[0] != 1:
                self._rollback_quietly()
                return _hold()
            stored = self._con.execute(
                "SELECT sealed_binding,operation_fingerprint,phase,evidence_digest "
                "FROM offline_scope_1454_attempts WHERE attempt_id=?",
                (attempt.attempt_id,),
            ).fetchone()
            if stored is None or tuple(stored) != (
                binding, fingerprint, "reserved", None
            ):
                self._rollback_quietly()
                return _hold()
            self._con.commit()
            return _review()
        except sqlite3.Error:
            if owned_transaction:
                self._rollback_quietly()
            return _hold()

    def mark_uncertain(self, attempt: SyntheticAttempt) -> ReviewReceipt:
        """Failure after synthetic callback: retain non-replayable attempt."""
        return self._transition(attempt, "reserved", "uncertain")

    def mark_recorded(
        self, attempt: SyntheticAttempt, evidence_sha256: str
    ) -> ReviewReceipt:
        if type(evidence_sha256) is not str or not _SHA.fullmatch(evidence_sha256):
            return _hold()
        return self._transition(attempt, "reserved", "recorded", evidence_sha256)

    def review_phase(self, attempt: SyntheticAttempt) -> tuple[str, ReviewReceipt]:
        """Returns only a fixed state label. No authority or private payload."""
        binding = _sealed(attempt)
        fingerprint = _operation_fingerprint(attempt)
        if binding is None or fingerprint is None:
            return "unknown", _hold()
        try:
            if not self._schema_valid():
                return "unknown", _hold()
            row = self._con.execute(
                "SELECT sealed_binding,operation_fingerprint,phase,evidence_digest "
                "FROM offline_scope_1454_attempts "
                "WHERE attempt_id=?", (attempt.attempt_id,)
            ).fetchone()
        except sqlite3.Error:
            return "unknown", _hold()
        if row is None or row[0] != binding or row[1] != fingerprint:
            return "unknown", _hold()
        phase, digest = row[2], row[3]
        # A 'recorded' claim without an exact sha256 is not evidence.
        # Nonterminal records must not carry fabricated evidence data.
        if phase == "recorded":
            if type(digest) is not str or _SHA.fullmatch(digest) is None:
                return "unknown", _hold()
        elif phase in ("reserved", "uncertain"):
            if digest is not None:
                return "unknown", _hold()
        else:
            return "unknown", _hold()
        return phase, _review()

    def review_backlog(self) -> OfflineBacklogReview:
        """Privacy-minimal, capped *offline* counts; no ID/hash/target export.

        A suspicious row, schema change, SQLite error, open caller transaction,
        or more than 256 records produces generic HOLD and zero visible counts.
        Neither REVIEW_ONLY nor a low backlog grants execution authority.
        """
        hold = OfflineBacklogReview(_hold(), 0, 0, 0)
        try:
            if self._con.in_transaction or not self._schema_valid():
                return hold
            rows = self._con.execute(
                "SELECT sealed_binding,operation_fingerprint,phase,evidence_digest "
                "FROM offline_scope_1454_attempts LIMIT 257"
            ).fetchall()
            if len(rows) > 256:
                return hold
            counts = {"reserved": 0, "uncertain": 0, "recorded": 0}
            for digest_binding, fingerprint, phase, evidence in rows:
                if (type(digest_binding) is not str or _SHA.fullmatch(digest_binding) is None
                    or type(fingerprint) is not str or _SHA.fullmatch(fingerprint) is None):
                    return hold
                if phase == "recorded":
                    if type(evidence) is not str or _SHA.fullmatch(evidence) is None:
                        return hold
                elif phase in ("reserved", "uncertain"):
                    if evidence is not None:
                        return hold
                else:
                    return hold
                counts[phase] += 1
            return OfflineBacklogReview(
                _review(), counts["reserved"], counts["uncertain"], counts["recorded"]
            )
        except sqlite3.Error:
            return hold
