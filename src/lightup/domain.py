"""Multi-client domain and persistence layer.

This module stores the product's durable records: clients, users, assessment
requests, engagements, authorization grants, risk approvals, findings and
prospects. It is deliberately independent from any web framework.

Tenant isolation is enforced here, in code, not in the UI:

- every read/write happens through an :class:`AccessContext`;
- operator contexts may act across clients;
- client contexts are hard-locked to their own ``client_id``;
- cross-tenant access raises :class:`TenantIsolationError`.

Authentication (passwords/sessions/SSO) is intentionally a later package.
Until it exists, the web layer must only be exposed on loopback.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import secrets
import sqlite3
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from enum import Enum
from pathlib import Path
from uuid import uuid4

from .engagements import (
    AssessmentMode,
    AuthorizationGrant,
    EngagementStatus,
    RiskLevel,
    ScopeDefinition,
)
from .models import RetestStatus, Severity


class Role(str, Enum):
    OPERATOR = "operator"
    CLIENT_ADMIN = "client_admin"
    CLIENT_MEMBER = "client_member"


class RequestStatus(str, Enum):
    SUBMITTED = "submitted"
    UNDER_REVIEW = "under_review"
    APPROVED = "approved"
    REJECTED = "rejected"


class ApprovalStatus(str, Enum):
    PENDING = "pending"
    APPROVED = "approved"
    DENIED = "denied"


class ProspectStatus(str, Enum):
    NEW = "new"
    CONTACTED = "contacted"
    AUTHORIZATION_REQUESTED = "authorization_requested"
    CONVERTED = "converted"
    DISMISSED = "dismissed"


class TenantIsolationError(PermissionError):
    """A context tried to touch another tenant's records."""


class AccountLockedError(PermissionError):
    """Too many failed sign-ins; the account is temporarily locked."""


class RoleError(PermissionError):
    """A context lacks the role required for an action."""


@dataclass(frozen=True)
class AccessContext:
    user_id: str
    role: Role
    client_id: str | None = None

    def __post_init__(self) -> None:
        if type(self.user_id) is not str:
            raise ValueError("access context user_id must be an exact string")
        if not self.user_id or self.user_id != self.user_id.strip() or "\x00" in self.user_id:
            raise ValueError("access context user_id must be canonical non-empty text")
        if type(self.role) is not Role:
            raise ValueError("access context role must be a Role member")
        if self.role is Role.OPERATOR:
            if self.client_id is not None:
                raise ValueError("operator contexts are not bound to a client")
        else:
            if type(self.client_id) is not str:
                raise ValueError("client contexts require an exact client_id string")
            if not self.client_id or self.client_id != self.client_id.strip() or "\x00" in self.client_id:
                raise ValueError("client contexts require a canonical client_id")

    @property
    def is_operator(self) -> bool:
        return self.role is Role.OPERATOR

    def require_operator(self, action: str) -> None:
        if not self.is_operator:
            raise RoleError(f"{action} requires an operator context")

    def resolve_client(self, client_id: str | None, action: str) -> str:
        """Resolve which client this action applies to, fail-closed."""
        if client_id is not None:
            if type(client_id) is not str:
                raise ValueError(f"{action}: client_id must be an exact string")
            if not client_id or client_id != client_id.strip() or "\x00" in client_id:
                raise ValueError(f"{action}: client_id must be canonical non-empty text")
        if self.is_operator:
            if client_id is None:
                raise ValueError(f"{action}: operator context must name a client_id")
            return client_id
        if client_id is not None and client_id != self.client_id:
            raise TenantIsolationError(
                f"{action}: context for client {self.client_id!r} "
                f"cannot act on client {client_id!r}"
            )
        assert self.client_id is not None
        return self.client_id


def utcnow() -> datetime:
    return datetime.now(timezone.utc)


SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;

CREATE TABLE IF NOT EXISTS clients (
    client_id TEXT PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    status TEXT NOT NULL DEFAULT 'active',
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS users (
    user_id TEXT PRIMARY KEY,
    email TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    role TEXT NOT NULL,
    client_id TEXT,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS assessment_requests (
    request_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    requested_assets_json TEXT NOT NULL,
    requested_mode TEXT NOT NULL,
    requested_risk INTEGER NOT NULL,
    notes TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS engagements (
    engagement_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    name TEXT NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (client_id) REFERENCES clients(client_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS authorization_grants (
    grant_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    approved_by TEXT NOT NULL,
    reference TEXT NOT NULL,
    assets_json TEXT NOT NULL,
    excluded_assets_json TEXT NOT NULL,
    allowed_capabilities_json TEXT NOT NULL,
    max_risk INTEGER NOT NULL,
    valid_from TEXT NOT NULL,
    valid_until TEXT NOT NULL,
    recurring_retest_allowed INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS risk_approvals (
    approval_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    requested_risk INTEGER NOT NULL,
    justification TEXT NOT NULL,
    status TEXT NOT NULL,
    requested_by TEXT NOT NULL,
    created_at TEXT NOT NULL,
    decided_by TEXT,
    decided_at TEXT,
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS findings (
    finding_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    title TEXT NOT NULL,
    severity TEXT NOT NULL,
    asset TEXT NOT NULL,
    impact TEXT NOT NULL,
    remediation TEXT NOT NULL,
    retest_status TEXT NOT NULL,
    evidence_ids_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS prospects (
    prospect_id TEXT PRIMARY KEY,
    company TEXT NOT NULL,
    exposure_summary TEXT NOT NULL,
    confidence REAL NOT NULL,
    status TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS credentials (
    user_id TEXT PRIMARY KEY,
    salt BLOB NOT NULL,
    password_hash BLOB NOT NULL,
    updated_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS sessions (
    token_hash TEXT PRIMARY KEY,
    user_id TEXT NOT NULL,
    csrf_token TEXT NOT NULL,
    created_at TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS login_failures (
    email TEXT PRIMARY KEY,
    failures INTEGER NOT NULL DEFAULT 0,
    locked_until TEXT
);

CREATE TABLE IF NOT EXISTS coverage_entries (
    engagement_id TEXT NOT NULL,
    capability_id TEXT NOT NULL,
    status TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    PRIMARY KEY (engagement_id, capability_id),
    FOREIGN KEY (engagement_id) REFERENCES engagements(engagement_id) ON DELETE CASCADE
);
"""


@dataclass(frozen=True)
class ClientRecord:
    client_id: str
    name: str
    status: str
    created_at: str


@dataclass(frozen=True)
class UserRecord:
    user_id: str
    email: str
    display_name: str
    role: Role
    client_id: str | None
    created_at: str


@dataclass(frozen=True)
class AssessmentRequestRecord:
    request_id: str
    client_id: str
    requested_assets: tuple[str, ...]
    requested_mode: AssessmentMode
    requested_risk: RiskLevel
    notes: str
    status: RequestStatus
    requested_by: str
    created_at: str
    decided_by: str | None
    decided_at: str | None


@dataclass(frozen=True)
class EngagementRecord:
    engagement_id: str
    client_id: str
    name: str
    status: EngagementStatus
    created_at: str


@dataclass(frozen=True)
class RiskApprovalRecord:
    approval_id: str
    client_id: str
    engagement_id: str
    requested_risk: RiskLevel
    justification: str
    status: ApprovalStatus
    requested_by: str
    created_at: str
    decided_by: str | None
    decided_at: str | None


@dataclass(frozen=True)
class FindingRecord:
    finding_id: str
    client_id: str
    engagement_id: str
    title: str
    severity: Severity
    asset: str
    impact: str
    remediation: str
    retest_status: RetestStatus
    evidence_ids: tuple[str, ...]
    created_at: str


@dataclass(frozen=True)
class ProspectRecord:
    prospect_id: str
    company: str
    exposure_summary: str
    confidence: float
    status: ProspectStatus
    created_at: str


class DomainStore:
    def __init__(self, path: str | Path):
        self.path = str(path)
        with self._connect() as con:
            con.executescript(SCHEMA)

    @contextmanager
    def _connect(self):
        con = sqlite3.connect(self.path, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        try:
            yield con
        finally:
            con.close()

    # -- clients / users ----------------------------------------------------

    def create_client(self, ctx: AccessContext, name: str) -> ClientRecord:
        ctx.require_operator("create_client")
        if not name.strip():
            raise ValueError("client name is required")
        record = ClientRecord(str(uuid4()), name.strip(), "active", utcnow().isoformat())
        with self._connect() as con:
            con.execute(
                "INSERT INTO clients(client_id,name,status,created_at) VALUES(?,?,?,?)",
                (record.client_id, record.name, record.status, record.created_at),
            )
        return record

    def list_clients(self, ctx: AccessContext) -> list[ClientRecord]:
        with self._connect() as con:
            if ctx.is_operator:
                rows = con.execute("SELECT * FROM clients ORDER BY name").fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM clients WHERE client_id=?", (ctx.client_id,)
                ).fetchall()
        return [ClientRecord(r["client_id"], r["name"], r["status"], r["created_at"]) for r in rows]

    def get_client(self, ctx: AccessContext, client_id: str) -> ClientRecord:
        client_id = ctx.resolve_client(client_id, "get_client")
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM clients WHERE client_id=?", (client_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown client {client_id!r}")
        return ClientRecord(row["client_id"], row["name"], row["status"], row["created_at"])

    def create_user(
        self,
        ctx: AccessContext,
        email: str,
        display_name: str,
        role: Role,
        client_id: str | None = None,
    ) -> UserRecord:
        ctx.require_operator("create_user")
        if role is Role.OPERATOR:
            if client_id is not None:
                raise ValueError("operator users are not bound to a client")
        elif not client_id:
            raise ValueError("client users require a client_id")
        record = UserRecord(
            str(uuid4()), email.strip().lower(), display_name.strip(), role, client_id, utcnow().isoformat()
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO users(user_id,email,display_name,role,client_id,created_at) "
                "VALUES(?,?,?,?,?,?)",
                (record.user_id, record.email, record.display_name, record.role.value,
                 record.client_id, record.created_at),
            )
        return record

    def context_for_user(self, user_id: str) -> AccessContext:
        with self._connect() as con:
            row = con.execute("SELECT * FROM users WHERE user_id=?", (user_id,)).fetchone()
        if row is None:
            raise KeyError(f"unknown user {user_id!r}")
        return AccessContext(row["user_id"], Role(row["role"]), row["client_id"])

    # -- credentials & sessions ----------------------------------------------
    #
    # Authentication primitives for the web shell. Passwords are scrypt-hashed
    # with a per-user salt; session tokens are stored only as SHA-256 hashes,
    # so a leaked database cannot be replayed into live sessions.

    _SCRYPT = {"n": 2**14, "r": 8, "p": 1, "dklen": 32}

    def _hash_password(self, password: str, salt: bytes) -> bytes:
        if len(password) < 10:
            raise ValueError("password must be at least 10 characters")
        return hashlib.scrypt(password.encode("utf-8"), salt=salt, **self._SCRYPT)

    def bootstrap_operator(self, email: str, display_name: str, password: str) -> UserRecord:
        """Create the first operator account. Local-process only (CLI bootstrap)."""
        with self._connect() as con:
            row = con.execute(
                "SELECT 1 FROM users WHERE role=?", (Role.OPERATOR.value,)
            ).fetchone()
        if row is not None:
            raise ValueError("an operator already exists; use create_user instead")
        system_ctx = AccessContext("bootstrap", Role.OPERATOR)
        user = self.create_user(system_ctx, email, display_name, Role.OPERATOR)
        self.set_password(system_ctx, user.user_id, password)
        return user

    def set_password(self, ctx: AccessContext, user_id: str, password: str) -> None:
        if not ctx.is_operator and ctx.user_id != user_id:
            raise RoleError("set_password requires an operator or the account owner")
        self.context_for_user(user_id)  # ensures the user exists
        salt = secrets.token_bytes(16)
        digest = self._hash_password(password, salt)
        with self._connect() as con:
            con.execute(
                "INSERT INTO credentials(user_id,salt,password_hash,updated_at) "
                "VALUES(?,?,?,?) ON CONFLICT(user_id) DO UPDATE SET "
                "salt=excluded.salt, password_hash=excluded.password_hash, "
                "updated_at=excluded.updated_at",
                (user_id, salt, digest, utcnow().isoformat()),
            )
            # Credential changes invalidate existing sessions.
            con.execute("DELETE FROM sessions WHERE user_id=?", (user_id,))

    def verify_password(self, email: str, password: str) -> UserRecord | None:
        """Return the user when email+password match; None otherwise (no oracle)."""
        with self._connect() as con:
            row = con.execute(
                "SELECT u.user_id,u.email,u.display_name,u.role,u.client_id,"
                "u.created_at,c.salt,c.password_hash FROM users u "
                "JOIN credentials c ON c.user_id=u.user_id WHERE u.email=?",
                (email.strip().lower(),),
            ).fetchone()
        if row is None:
            # Burn comparable time so missing users are not distinguishable.
            self._hash_password(password or "x" * 10, b"\x00" * 16)
            return None
        digest = self._hash_password(password, row["salt"])
        if not hmac.compare_digest(digest, row["password_hash"]):
            return None
        return UserRecord(row["user_id"], row["email"], row["display_name"],
                          Role(row["role"]), row["client_id"], row["created_at"])

    LOGIN_MAX_FAILURES = 5
    LOGIN_LOCKOUT_SECONDS = 900

    def authenticate(self, email: str, password: str) -> UserRecord | None:
        """verify_password plus brute-force lockout per email.

        Raises :class:`AccountLockedError` while locked; successful sign-in
        clears the failure counter.
        """
        email = email.strip().lower()
        now = utcnow()
        with self._connect() as con:
            row = con.execute(
                "SELECT failures, locked_until FROM login_failures WHERE email=?",
                (email,),
            ).fetchone()
        if row is not None and row["locked_until"]:
            locked_until = datetime.fromisoformat(row["locked_until"])
            if locked_until > now:
                raise AccountLockedError(
                    "too many failed sign-ins; try again later"
                )
        user = self.verify_password(email, password)
        with self._connect() as con:
            if user is not None:
                con.execute("DELETE FROM login_failures WHERE email=?", (email,))
            else:
                failures = (row["failures"] if row is not None else 0) + 1
                locked_until = None
                if failures >= self.LOGIN_MAX_FAILURES:
                    locked_until = (now + timedelta(
                        seconds=self.LOGIN_LOCKOUT_SECONDS)).isoformat()
                    failures = 0
                con.execute(
                    "INSERT INTO login_failures(email,failures,locked_until) "
                    "VALUES(?,?,?) ON CONFLICT(email) DO UPDATE SET "
                    "failures=excluded.failures, locked_until=excluded.locked_until",
                    (email, failures, locked_until),
                )
        return user

    @staticmethod
    def _token_hash(token: str) -> str:
        return hashlib.sha256(token.encode("utf-8")).hexdigest()

    def create_session(self, user_id: str, ttl_seconds: int = 8 * 3600) -> tuple[str, str]:
        """Return (session_token, csrf_token) for a verified user."""
        if not 60 <= ttl_seconds <= 30 * 24 * 3600:
            raise ValueError("session TTL out of range")
        self.context_for_user(user_id)
        token = secrets.token_urlsafe(32)
        csrf = secrets.token_urlsafe(32)
        now = utcnow()
        with self._connect() as con:
            con.execute(
                "INSERT INTO sessions(token_hash,user_id,csrf_token,created_at,expires_at) "
                "VALUES(?,?,?,?,?)",
                (self._token_hash(token), user_id, csrf, now.isoformat(),
                 (now + timedelta(seconds=ttl_seconds)).isoformat()),
            )
        return token, csrf

    def session_context(self, token: str) -> tuple[AccessContext, str] | None:
        """Resolve a session token to (AccessContext, csrf_token), or None."""
        if not token:
            return None
        with self._connect() as con:
            row = con.execute(
                "SELECT user_id,csrf_token,expires_at FROM sessions WHERE token_hash=?",
                (self._token_hash(token),),
            ).fetchone()
        if row is None:
            return None
        if datetime.fromisoformat(row["expires_at"]) <= utcnow():
            self.revoke_session(token)
            return None
        try:
            return self.context_for_user(row["user_id"]), row["csrf_token"]
        except (KeyError, ValueError):
            # Missing or non-canonical durable identity cannot authenticate a
            # session. Treat corruption as an invalid session, never as an
            # exception that can escape into the authorization-aware web layer.
            return None

    def revoke_session(self, token: str) -> None:
        with self._connect() as con:
            con.execute("DELETE FROM sessions WHERE token_hash=?",
                        (self._token_hash(token),))

    # -- assessment requests -------------------------------------------------

    def submit_assessment_request(
        self,
        ctx: AccessContext,
        requested_assets: tuple[str, ...],
        requested_mode: AssessmentMode,
        requested_risk: RiskLevel,
        notes: str = "",
        client_id: str | None = None,
    ) -> AssessmentRequestRecord:
        client_id = ctx.resolve_client(client_id, "submit_assessment_request")
        assets = tuple(a.strip() for a in requested_assets if a.strip())
        if not assets:
            raise ValueError("at least one requested asset is required")
        record = AssessmentRequestRecord(
            request_id=str(uuid4()),
            client_id=client_id,
            requested_assets=assets,
            requested_mode=requested_mode,
            requested_risk=requested_risk,
            notes=notes.strip(),
            status=RequestStatus.SUBMITTED,
            requested_by=ctx.user_id,
            created_at=utcnow().isoformat(),
            decided_by=None,
            decided_at=None,
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO assessment_requests("
                "request_id,client_id,requested_assets_json,requested_mode,requested_risk,"
                "notes,status,requested_by,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                (record.request_id, record.client_id, json.dumps(list(assets)),
                 record.requested_mode.value, int(record.requested_risk), record.notes,
                 record.status.value, record.requested_by, record.created_at),
            )
        return record

    @staticmethod
    def _request_from_row(row: sqlite3.Row) -> AssessmentRequestRecord:
        return AssessmentRequestRecord(
            request_id=row["request_id"],
            client_id=row["client_id"],
            requested_assets=tuple(json.loads(row["requested_assets_json"])),
            requested_mode=AssessmentMode(row["requested_mode"]),
            requested_risk=RiskLevel(row["requested_risk"]),
            notes=row["notes"],
            status=RequestStatus(row["status"]),
            requested_by=row["requested_by"],
            created_at=row["created_at"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
        )

    def list_assessment_requests(
        self, ctx: AccessContext, client_id: str | None = None
    ) -> list[AssessmentRequestRecord]:
        with self._connect() as con:
            if ctx.is_operator and client_id is None:
                rows = con.execute(
                    "SELECT * FROM assessment_requests ORDER BY created_at DESC"
                ).fetchall()
            else:
                scoped = ctx.resolve_client(client_id, "list_assessment_requests")
                rows = con.execute(
                    "SELECT * FROM assessment_requests WHERE client_id=? ORDER BY created_at DESC",
                    (scoped,),
                ).fetchall()
        return [self._request_from_row(r) for r in rows]

    def get_assessment_request(self, ctx: AccessContext, request_id: str) -> AssessmentRequestRecord:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM assessment_requests WHERE request_id=?", (request_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown assessment request {request_id!r}")
        record = self._request_from_row(row)
        ctx.resolve_client(record.client_id, "get_assessment_request")
        return record

    def review_assessment_request(
        self, ctx: AccessContext, request_id: str, approve: bool
    ) -> AssessmentRequestRecord:
        ctx.require_operator("review_assessment_request")
        status = RequestStatus.APPROVED if approve else RequestStatus.REJECTED
        with self._connect() as con:
            updated = con.execute(
                "UPDATE assessment_requests SET status=?, decided_by=?, decided_at=? "
                "WHERE request_id=? AND status IN (?,?)",
                (status.value, ctx.user_id, utcnow().isoformat(), request_id,
                 RequestStatus.SUBMITTED.value, RequestStatus.UNDER_REVIEW.value),
            ).rowcount
        if updated == 0:
            raise ValueError(f"request {request_id!r} is not open for review")
        return self.get_assessment_request(ctx, request_id)

    # -- engagements ----------------------------------------------------------

    def create_engagement(self, ctx: AccessContext, client_id: str, name: str) -> EngagementRecord:
        ctx.require_operator("create_engagement")
        if not name.strip():
            raise ValueError("engagement name is required")
        self.get_client(ctx, client_id)
        record = EngagementRecord(
            str(uuid4()), client_id, name.strip(), EngagementStatus.DRAFT, utcnow().isoformat()
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO engagements(engagement_id,client_id,name,status,created_at) "
                "VALUES(?,?,?,?,?)",
                (record.engagement_id, record.client_id, record.name,
                 record.status.value, record.created_at),
            )
        return record

    def list_engagements(
        self, ctx: AccessContext, client_id: str | None = None
    ) -> list[EngagementRecord]:
        with self._connect() as con:
            if ctx.is_operator and client_id is None:
                rows = con.execute("SELECT * FROM engagements ORDER BY created_at DESC").fetchall()
            else:
                scoped = ctx.resolve_client(client_id, "list_engagements")
                rows = con.execute(
                    "SELECT * FROM engagements WHERE client_id=? ORDER BY created_at DESC",
                    (scoped,),
                ).fetchall()
        return [
            EngagementRecord(r["engagement_id"], r["client_id"], r["name"],
                             EngagementStatus(r["status"]), r["created_at"])
            for r in rows
        ]

    def get_engagement(self, ctx: AccessContext, engagement_id: str) -> EngagementRecord:
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM engagements WHERE engagement_id=?", (engagement_id,)
            ).fetchone()
        if row is None:
            raise KeyError(f"unknown engagement {engagement_id!r}")
        record = EngagementRecord(row["engagement_id"], row["client_id"], row["name"],
                                  EngagementStatus(row["status"]), row["created_at"])
        ctx.resolve_client(record.client_id, "get_engagement")
        return record

    def set_engagement_status(
        self, ctx: AccessContext, engagement_id: str, status: EngagementStatus
    ) -> EngagementRecord:
        ctx.require_operator("set_engagement_status")
        record = self.get_engagement(ctx, engagement_id)
        with self._connect() as con:
            con.execute(
                "UPDATE engagements SET status=? WHERE engagement_id=?",
                (status.value, record.engagement_id),
            )
        return self.get_engagement(ctx, engagement_id)

    # -- authorization grants --------------------------------------------------

    def record_authorization_grant(
        self,
        ctx: AccessContext,
        engagement_id: str,
        approved_by: str,
        reference: str,
        scope: ScopeDefinition,
        valid_from: datetime,
        valid_until: datetime,
        recurring_retest_allowed: bool = False,
    ) -> AuthorizationGrant:
        ctx.require_operator("record_authorization_grant")
        if valid_from.tzinfo is None or valid_until.tzinfo is None:
            raise ValueError("grant validity must be timezone-aware")
        if valid_until <= valid_from:
            raise ValueError("grant validity window is empty")
        if not reference.strip() or not approved_by.strip():
            raise ValueError("grant requires approved_by and a reference")
        if not scope.assets:
            raise ValueError("grant scope requires at least one asset")
        engagement = self.get_engagement(ctx, engagement_id)
        grant = AuthorizationGrant(
            grant_id=str(uuid4()),
            client_id=engagement.client_id,
            engagement_id=engagement.engagement_id,
            approved_by=approved_by.strip(),
            reference=reference.strip(),
            scope=scope,
            valid_from=valid_from,
            valid_until=valid_until,
            recurring_retest_allowed=recurring_retest_allowed,
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO authorization_grants("
                "grant_id,client_id,engagement_id,approved_by,reference,assets_json,"
                "excluded_assets_json,allowed_capabilities_json,max_risk,valid_from,"
                "valid_until,recurring_retest_allowed,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (grant.grant_id, grant.client_id, grant.engagement_id, grant.approved_by,
                 grant.reference, json.dumps(list(scope.assets)),
                 json.dumps(list(scope.excluded_assets)),
                 json.dumps(list(scope.allowed_capabilities)), int(scope.max_risk),
                 valid_from.isoformat(), valid_until.isoformat(),
                 1 if recurring_retest_allowed else 0, utcnow().isoformat()),
            )
        return grant

    @staticmethod
    def _grant_from_row(row: sqlite3.Row) -> AuthorizationGrant:
        scope = ScopeDefinition(
            assets=tuple(json.loads(row["assets_json"])),
            max_risk=RiskLevel(row["max_risk"]),
            allowed_capabilities=tuple(json.loads(row["allowed_capabilities_json"])),
            excluded_assets=tuple(json.loads(row["excluded_assets_json"])),
        )
        return AuthorizationGrant(
            grant_id=row["grant_id"],
            client_id=row["client_id"],
            engagement_id=row["engagement_id"],
            approved_by=row["approved_by"],
            reference=row["reference"],
            scope=scope,
            valid_from=datetime.fromisoformat(row["valid_from"]),
            valid_until=datetime.fromisoformat(row["valid_until"]),
            recurring_retest_allowed=bool(row["recurring_retest_allowed"]),
        )

    def list_authorization_grants(
        self, ctx: AccessContext, engagement_id: str
    ) -> list[AuthorizationGrant]:
        engagement = self.get_engagement(ctx, engagement_id)
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM authorization_grants WHERE engagement_id=? ORDER BY created_at DESC",
                (engagement.engagement_id,),
            ).fetchall()
        return [self._grant_from_row(r) for r in rows]

    def get_current_grant(
        self, ctx: AccessContext, engagement_id: str, now: datetime | None = None
    ) -> AuthorizationGrant | None:
        now = now or utcnow()
        for grant in self.list_authorization_grants(ctx, engagement_id):
            if grant.is_current(now):
                return grant
        return None

    # -- risk elevation ---------------------------------------------------------

    def request_risk_elevation(
        self,
        ctx: AccessContext,
        engagement_id: str,
        requested_risk: RiskLevel,
        justification: str,
    ) -> RiskApprovalRecord:
        engagement = self.get_engagement(ctx, engagement_id)
        if not justification.strip():
            raise ValueError("risk elevation requires a justification")
        record = RiskApprovalRecord(
            approval_id=str(uuid4()),
            client_id=engagement.client_id,
            engagement_id=engagement.engagement_id,
            requested_risk=requested_risk,
            justification=justification.strip(),
            status=ApprovalStatus.PENDING,
            requested_by=ctx.user_id,
            created_at=utcnow().isoformat(),
            decided_by=None,
            decided_at=None,
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO risk_approvals("
                "approval_id,client_id,engagement_id,requested_risk,justification,"
                "status,requested_by,created_at) VALUES(?,?,?,?,?,?,?,?)",
                (record.approval_id, record.client_id, record.engagement_id,
                 int(record.requested_risk), record.justification, record.status.value,
                 record.requested_by, record.created_at),
            )
        return record

    @staticmethod
    def _approval_from_row(row: sqlite3.Row) -> RiskApprovalRecord:
        return RiskApprovalRecord(
            approval_id=row["approval_id"],
            client_id=row["client_id"],
            engagement_id=row["engagement_id"],
            requested_risk=RiskLevel(row["requested_risk"]),
            justification=row["justification"],
            status=ApprovalStatus(row["status"]),
            requested_by=row["requested_by"],
            created_at=row["created_at"],
            decided_by=row["decided_by"],
            decided_at=row["decided_at"],
        )

    def list_risk_approvals(
        self, ctx: AccessContext, engagement_id: str | None = None
    ) -> list[RiskApprovalRecord]:
        with self._connect() as con:
            if engagement_id is not None:
                engagement = self.get_engagement(ctx, engagement_id)
                rows = con.execute(
                    "SELECT * FROM risk_approvals WHERE engagement_id=? ORDER BY created_at DESC",
                    (engagement.engagement_id,),
                ).fetchall()
            elif ctx.is_operator:
                rows = con.execute(
                    "SELECT * FROM risk_approvals ORDER BY created_at DESC"
                ).fetchall()
            else:
                rows = con.execute(
                    "SELECT * FROM risk_approvals WHERE client_id=? ORDER BY created_at DESC",
                    (ctx.client_id,),
                ).fetchall()
        return [self._approval_from_row(r) for r in rows]

    def decide_risk_elevation(
        self, ctx: AccessContext, approval_id: str, approve: bool
    ) -> RiskApprovalRecord:
        """Only an operator may decide, and never on their own request."""
        ctx.require_operator("decide_risk_elevation")
        with self._connect() as con:
            row = con.execute(
                "SELECT * FROM risk_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
            if row is None:
                raise KeyError(f"unknown risk approval {approval_id!r}")
            record = self._approval_from_row(row)
            if record.status is not ApprovalStatus.PENDING:
                raise ValueError("risk approval already decided")
            if record.requested_by == ctx.user_id:
                raise RoleError("risk elevation cannot be self-approved")
            status = ApprovalStatus.APPROVED if approve else ApprovalStatus.DENIED
            con.execute(
                "UPDATE risk_approvals SET status=?, decided_by=?, decided_at=? "
                "WHERE approval_id=?",
                (status.value, ctx.user_id, utcnow().isoformat(), approval_id),
            )
            row = con.execute(
                "SELECT * FROM risk_approvals WHERE approval_id=?", (approval_id,)
            ).fetchone()
        return self._approval_from_row(row)

    # -- findings -------------------------------------------------------------

    def record_finding(
        self,
        ctx: AccessContext,
        engagement_id: str,
        title: str,
        severity: Severity,
        asset: str,
        impact: str,
        remediation: str,
        evidence_ids: tuple[str, ...] = (),
    ) -> FindingRecord:
        ctx.require_operator("record_finding")
        engagement = self.get_engagement(ctx, engagement_id)
        if not title.strip() or not remediation.strip():
            raise ValueError("finding requires a title and remediation")
        record = FindingRecord(
            finding_id=str(uuid4()),
            client_id=engagement.client_id,
            engagement_id=engagement.engagement_id,
            title=title.strip(),
            severity=severity,
            asset=asset.strip(),
            impact=impact.strip(),
            remediation=remediation.strip(),
            retest_status=RetestStatus.NOT_TESTED,
            evidence_ids=tuple(evidence_ids),
            created_at=utcnow().isoformat(),
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO findings("
                "finding_id,client_id,engagement_id,title,severity,asset,impact,"
                "remediation,retest_status,evidence_ids_json,created_at) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?)",
                (record.finding_id, record.client_id, record.engagement_id, record.title,
                 record.severity.value, record.asset, record.impact, record.remediation,
                 record.retest_status.value, json.dumps(list(record.evidence_ids)),
                 record.created_at),
            )
        return record

    @staticmethod
    def _finding_from_row(row: sqlite3.Row) -> FindingRecord:
        return FindingRecord(
            finding_id=row["finding_id"],
            client_id=row["client_id"],
            engagement_id=row["engagement_id"],
            title=row["title"],
            severity=Severity(row["severity"]),
            asset=row["asset"],
            impact=row["impact"],
            remediation=row["remediation"],
            retest_status=RetestStatus(row["retest_status"]),
            evidence_ids=tuple(json.loads(row["evidence_ids_json"])),
            created_at=row["created_at"],
        )

    def list_findings(
        self, ctx: AccessContext, client_id: str | None = None,
        engagement_id: str | None = None,
    ) -> list[FindingRecord]:
        with self._connect() as con:
            if engagement_id is not None:
                engagement = self.get_engagement(ctx, engagement_id)
                rows = con.execute(
                    "SELECT * FROM findings WHERE engagement_id=? ORDER BY created_at DESC",
                    (engagement.engagement_id,),
                ).fetchall()
            elif ctx.is_operator and client_id is None:
                rows = con.execute("SELECT * FROM findings ORDER BY created_at DESC").fetchall()
            else:
                scoped = ctx.resolve_client(client_id, "list_findings")
                rows = con.execute(
                    "SELECT * FROM findings WHERE client_id=? ORDER BY created_at DESC",
                    (scoped,),
                ).fetchall()
        return [self._finding_from_row(r) for r in rows]

    def set_retest_status(
        self, ctx: AccessContext, finding_id: str, status: RetestStatus
    ) -> FindingRecord:
        ctx.require_operator("set_retest_status")
        with self._connect() as con:
            updated = con.execute(
                "UPDATE findings SET retest_status=? WHERE finding_id=?",
                (status.value, finding_id),
            ).rowcount
            if updated == 0:
                raise KeyError(f"unknown finding {finding_id!r}")
            row = con.execute(
                "SELECT * FROM findings WHERE finding_id=?", (finding_id,)
            ).fetchone()
        return self._finding_from_row(row)

    # -- coverage ----------------------------------------------------------------

    def set_coverage(
        self, ctx: AccessContext, engagement_id: str, capability_id: str, status: str
    ) -> None:
        """Record per-domain coverage for an engagement (operator-only)."""
        ctx.require_operator("set_coverage")
        engagement = self.get_engagement(ctx, engagement_id)
        from .coverage import CoverageStatus

        CoverageStatus(status)  # validates
        with self._connect() as con:
            con.execute(
                "INSERT INTO coverage_entries(engagement_id,capability_id,status,"
                "updated_at) VALUES(?,?,?,?) "
                "ON CONFLICT(engagement_id,capability_id) DO UPDATE SET "
                "status=excluded.status, updated_at=excluded.updated_at",
                (engagement.engagement_id, capability_id, status, utcnow().isoformat()),
            )

    def get_coverage(self, ctx: AccessContext, engagement_id: str) -> dict[str, str]:
        """Coverage statuses stored for this engagement (tenant-scoped)."""
        engagement = self.get_engagement(ctx, engagement_id)
        with self._connect() as con:
            rows = con.execute(
                "SELECT capability_id,status FROM coverage_entries WHERE engagement_id=?",
                (engagement.engagement_id,),
            ).fetchall()
        return {row["capability_id"]: row["status"] for row in rows}

    # -- prospects (passive discovery; operator-only) ---------------------------

    def add_prospect(
        self, ctx: AccessContext, company: str, exposure_summary: str, confidence: float
    ) -> ProspectRecord:
        ctx.require_operator("add_prospect")
        if not 0.0 <= confidence <= 1.0:
            raise ValueError("confidence must be between 0 and 1")
        if not company.strip():
            raise ValueError("company is required")
        record = ProspectRecord(
            str(uuid4()), company.strip(), exposure_summary.strip(),
            confidence, ProspectStatus.NEW, utcnow().isoformat(),
        )
        with self._connect() as con:
            con.execute(
                "INSERT INTO prospects(prospect_id,company,exposure_summary,confidence,"
                "status,created_at) VALUES(?,?,?,?,?,?)",
                (record.prospect_id, record.company, record.exposure_summary,
                 record.confidence, record.status.value, record.created_at),
            )
        return record

    def list_prospects(self, ctx: AccessContext) -> list[ProspectRecord]:
        ctx.require_operator("list_prospects")
        with self._connect() as con:
            rows = con.execute(
                "SELECT * FROM prospects ORDER BY confidence DESC, company"
            ).fetchall()
        return [
            ProspectRecord(r["prospect_id"], r["company"], r["exposure_summary"],
                           r["confidence"], ProspectStatus(r["status"]), r["created_at"])
            for r in rows
        ]

    def set_prospect_status(
        self, ctx: AccessContext, prospect_id: str, status: ProspectStatus
    ) -> None:
        ctx.require_operator("set_prospect_status")
        with self._connect() as con:
            updated = con.execute(
                "UPDATE prospects SET status=? WHERE prospect_id=?",
                (status.value, prospect_id),
            ).rowcount
        if updated == 0:
            raise KeyError(f"unknown prospect {prospect_id!r}")
