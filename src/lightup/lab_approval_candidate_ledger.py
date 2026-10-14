"""Offline-only candidate ledger for destructive laboratory step-up (issue #1173).

This is deliberately NOT a source of executable authority. An authenticated,
operator-owned identity/role decision and actual isolated lab attestation must
be implemented by the original dispatch owner before any production wiring.
A model, lab flag, request parameter or a successful local write is not consent.
"""
from __future__ import annotations

import sqlite3
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable
from uuid import uuid4


MAX_WINDOW = timedelta(hours=24)
_ACTIONS = frozenset(("issue", "revoke"))


class CandidateHeld(PermissionError):
    """Reject a candidate without exposing private operator/store details."""


@dataclass(frozen=True)
class LabApprovalCandidate:
    approval_id: str
    run_id: str
    client_id: str
    engagement_id: str
    asset: str
    capability_id: str
    tool_id: str
    approved_by: str
    approved_at: datetime
    expires_at: datetime
    revoked_at: datetime | None


# An independently authenticated and authorised operator system MUST supply
# this callback. Test doubles are NOT proof of real operator provenance.
OperatorGate = Callable[[str, str], bool]


def _identity(value: object) -> str:
    if (
        type(value) is not str or not 1 <= len(value) <= 128
        or value != value.strip()
        or not all(0x21 <= ord(ch) <= 0x7e for ch in value)
    ):
        raise CandidateHeld("invalid candidate identity")
    return value


def _utc(value: object) -> datetime:
    # Reject datetime subclasses, attacker-defined tzinfo/comparison hooks,
    # naive dates and non-UTC offsets before serialisation.
    if type(value) is not datetime or type(value.tzinfo) is not timezone:
        raise CandidateHeld("invalid candidate UTC instant")
    if value.utcoffset() != timedelta(0):
        raise CandidateHeld("invalid candidate UTC instant")
    return value.astimezone(timezone.utc)


def _stored_utc(value: object) -> datetime:
    """Read only the exact UTC instant encoding emitted by the local writer.

    SQLite rows are not a trusted approval authority. Ambiguous aliases, values
    from custom adapters and silently normalised datetimes must HOLD.
    """
    if type(value) is not str or not 20 <= len(value) <= 40:
        raise CandidateHeld("candidate timestamp corrupted")
    try:
        value_dt = _utc(datetime.fromisoformat(value))
    except (TypeError, ValueError, OverflowError, CandidateHeld):
        raise CandidateHeld("candidate timestamp corrupted") from None
    if value_dt.isoformat() != value:
        raise CandidateHeld("noncanonical candidate timestamp")
    return value_dt


def _operator(gate: OperatorGate | None, actor: object, action: str) -> str:
    actor_id = _identity(actor)
    if action not in _ACTIONS or not callable(gate):
        raise CandidateHeld("trusted operator review unavailable")
    try:
        approved = gate(actor_id, action)
    except Exception:
        raise CandidateHeld("trusted operator review unavailable") from None
    if approved is not True:
        raise CandidateHeld("operator review did not approve action")
    return actor_id


class LabApprovalCandidateLedger:
    """Isolated SQLite demonstration; never use as an authority resolver.

    One immutable candidate is allowed per run. Revocation is durable and
    cannot be reversed or bypassed by reissuing the same run id.
    """

    def __init__(self, connection: sqlite3.Connection):
        if type(connection) is not sqlite3.Connection:
            raise CandidateHeld("a canonical SQLite connection is required")
        self._db = connection
        try:
            self._db.execute("""
                CREATE TABLE IF NOT EXISTS lab_stepup_candidates_v1 (
                    approval_id TEXT PRIMARY KEY,
                    run_id TEXT NOT NULL UNIQUE,
                    client_id TEXT NOT NULL,
                    engagement_id TEXT NOT NULL,
                    asset TEXT NOT NULL,
                    capability_id TEXT NOT NULL,
                    tool_id TEXT NOT NULL,
                    approved_by TEXT NOT NULL,
                    approved_at TEXT NOT NULL,
                    expires_at TEXT NOT NULL,
                    revoked_at TEXT,
                    revoked_by TEXT
                )
            """)
        except sqlite3.Error:
            raise CandidateHeld("candidate store unavailable") from None

    def issue(
        self, *, run_id: str, client_id: str, engagement_id: str,
        asset: str, capability_id: str, tool_id: str, actor: str,
        expires_at: datetime, operator_gate: OperatorGate | None,
    ) -> LabApprovalCandidate:
        # Validate entire envelope BEFORE the identity callback or any write.
        ids = tuple(_identity(x) for x in (
            run_id, client_id, engagement_id, asset, capability_id, tool_id,
        ))
        expiry = _utc(expires_at)
        now = datetime.now(timezone.utc)
        if expiry <= now or expiry - now > MAX_WINDOW:
            raise CandidateHeld("candidate validity must be within 24 hours")
        actor_id = _operator(operator_gate, actor, "issue")
        approval_id = str(uuid4())
        # Never rollback a caller-owned open transaction on a rejected call.
        if self._db.in_transaction:
            raise CandidateHeld("candidate transaction isolation unavailable")
        began = False
        try:
            self._db.execute("BEGIN IMMEDIATE")
            began = True
            self._db.execute(
                """INSERT INTO lab_stepup_candidates_v1
                (approval_id,run_id,client_id,engagement_id,asset,
                 capability_id,tool_id,approved_by,approved_at,expires_at)
                VALUES (?,?,?,?,?,?,?,?,?,?)""",
                (approval_id, *ids, actor_id, now.isoformat(), expiry.isoformat()),
            )
            self._db.commit()
        except sqlite3.Error:
            if began:
                self._db.rollback()
            raise CandidateHeld("candidate issuance refused") from None
        return LabApprovalCandidate(
            approval_id, *ids, actor_id, now, expiry, None,
        )

    def revoke(
        self, *, run_id: str, actor: str, operator_gate: OperatorGate | None,
    ) -> None:
        key = _identity(run_id)
        actor_id = _operator(operator_gate, actor, "revoke")
        stamp = datetime.now(timezone.utc).isoformat()
        # Never rollback a caller-owned open transaction on a rejected call.
        if self._db.in_transaction:
            raise CandidateHeld("candidate transaction isolation unavailable")
        began = False
        try:
            self._db.execute("BEGIN IMMEDIATE")
            began = True
            result = self._db.execute(
                """UPDATE lab_stepup_candidates_v1
                SET revoked_at=?, revoked_by=?
                WHERE run_id=? AND revoked_at IS NULL""",
                (stamp, actor_id, key),
            )
            if result.rowcount != 1:
                self._db.rollback()
                raise CandidateHeld("candidate not revocable")
            self._db.commit()
        except sqlite3.Error:
            if began:
                self._db.rollback()
            raise CandidateHeld("candidate revocation unavailable") from None

    def revoke_engagement(
        self, *, client_id: str, engagement_id: str, actor: str,
        operator_gate: OperatorGate | None,
    ) -> int:
        """Atomically revoke every matching tenant/engagement candidate.

        No global, cross-tenant or wildcard revocation selector is accepted.
        All revocation writes are lab-only candidate state, never execution.
        """
        tenant = _identity(client_id)
        engagement = _identity(engagement_id)
        actor_id = _operator(operator_gate, actor, "revoke")
        stamp = datetime.now(timezone.utc).isoformat()
        # Never rollback a caller-owned open transaction on a rejected call.
        if self._db.in_transaction:
            raise CandidateHeld("candidate transaction isolation unavailable")
        began = False
        try:
            self._db.execute("BEGIN IMMEDIATE")
            began = True
            result = self._db.execute(
                """UPDATE lab_stepup_candidates_v1
                SET revoked_at=?, revoked_by=?
                WHERE client_id=? AND engagement_id=? AND revoked_at IS NULL""",
                (stamp, actor_id, tenant, engagement),
            )
            if result.rowcount < 1:
                self._db.rollback()
                raise CandidateHeld("no matching revocable candidates")
            count = result.rowcount
            self._db.commit()
            return count
        except sqlite3.Error:
            if began:
                self._db.rollback()
            raise CandidateHeld("engagement revocation unavailable") from None

    def inspect(self, run_id: str, *, client_id: str) -> LabApprovalCandidate | None:
        """Tenant-scoped review data only, never a permission or scan permit."""
        key = _identity(run_id)
        tenant = _identity(client_id)
        try:
            row = self._db.execute(
                """SELECT approval_id,run_id,client_id,engagement_id,asset,
                capability_id,tool_id,approved_by,approved_at,expires_at,
                revoked_at FROM lab_stepup_candidates_v1 WHERE run_id=? AND client_id=?""",
                (key, tenant),
            ).fetchone()
        except sqlite3.Error:
            raise CandidateHeld("candidate lookup unavailable") from None
        if row is None:
            return None
        try:
            for item in row[:8]:
                _identity(item)
            dates = tuple(
                None if item is None else _stored_utc(item)
                for item in row[8:]
            )
            issued, expiry, revoked = dates
            # Check original issuance invariants again on *every* read.
            # An actor with DB write access may be able to widen a stored row.
            if (
                issued >= expiry
                or expiry - issued > MAX_WINDOW
                or (revoked is not None and revoked < issued)
            ):
                raise CandidateHeld("candidate validity window corrupted")
            return LabApprovalCandidate(*row[:8], *dates)
        except (TypeError, ValueError, CandidateHeld):
            raise CandidateHeld("candidate record corrupted") from None

    def review(self, run_id: str, *, client_id: str) -> dict[str, object]:
        """Tenant-scoped non-authorizing receipt, even for live candidates."""
        candidate = self.inspect(run_id, client_id=client_id)
        now = datetime.now(timezone.utc)
        status = "REVIEW_ONLY" if (
            candidate is not None and candidate.revoked_at is None
            and candidate.approved_at <= now < candidate.expires_at
        ) else "HOLD"
        return {
            "status": status,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }
