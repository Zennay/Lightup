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


class OfflineAttemptJournal:
    """Synthetic SQLite reference, deliberately NOT an execution wrapper.

    Do not pass customer database connections. If the database has *any*
    pre-existing table besides this tool's own synthetic table, construction
    refuses it before schema writes. Use only throwaway in-memory/temp DBs.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection or connection.in_transaction:
            raise ValueError("synthetic offline connection required")
        try:
            names = {
                row[0] for row in connection.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'"
                )
            }
            if names - {"offline_scope_1454_attempts"}:
                raise ValueError("synthetic offline connection required")
            connection.execute(_SCHEMA)
            connection.commit()
        except sqlite3.Error as exc:
            raise ValueError("synthetic offline connection required") from None
        self._con = connection

    def _transition(
        self, attempt: SyntheticAttempt, expected: str, next_phase: str,
        evidence_digest: str | None = None,
    ) -> ReviewReceipt:
        binding = _sealed(attempt)
        if binding is None:
            return _hold()
        try:
            self._con.execute("BEGIN IMMEDIATE")
            row = self._con.execute(
                "SELECT sealed_binding,phase FROM offline_scope_1454_attempts "
                "WHERE attempt_id=?", (attempt.attempt_id,)
            ).fetchone()
            if row is None or row[0] != binding or row[1] != expected:
                self._con.rollback()
                return _hold()
            self._con.execute(
                "UPDATE offline_scope_1454_attempts SET phase=?,evidence_digest=? "
                "WHERE attempt_id=? AND sealed_binding=? AND phase=?",
                (next_phase, evidence_digest, attempt.attempt_id, binding, expected)
            )
            if self._con.execute("SELECT changes()").fetchone()[0] != 1:
                self._con.rollback()
                return _hold()
            self._con.commit()
            return _review()
        except sqlite3.Error:
            self._con.rollback()
            return _hold()

    def reserve(self, attempt: SyntheticAttempt) -> ReviewReceipt:
        """Persist fixture identity before an *external* mock callback.

        A reservation only records evidence of review. It never confers
        consent, isolation, handler permission, or a replayable lease.
        """
        binding = _sealed(attempt)
        if binding is None:
            return _hold()
        try:
            self._con.execute("BEGIN IMMEDIATE")
            self._con.execute(
                "INSERT INTO offline_scope_1454_attempts "
                "(attempt_id,sealed_binding,phase,evidence_digest) "
                "VALUES(?,?,'reserved',NULL)",
                (attempt.attempt_id, binding),
            )
            self._con.commit()
            return _review()
        except sqlite3.Error:
            self._con.rollback()
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
        if binding is None:
            return "unknown", _hold()
        try:
            row = self._con.execute(
                "SELECT sealed_binding,phase FROM offline_scope_1454_attempts "
                "WHERE attempt_id=?", (attempt.attempt_id,)
            ).fetchone()
        except sqlite3.Error:
            return "unknown", _hold()
        if row is None or row[0] != binding or row[1] not in (
            "reserved", "uncertain", "recorded"
        ):
            return "unknown", _hold()
        return row[1], _review()
