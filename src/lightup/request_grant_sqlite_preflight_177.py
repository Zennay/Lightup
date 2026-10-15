"""Opt-in, read-only SQLite request→grant→engagement integrity preflight (#177).

NEVER authoritative: even a genuine persisted FK plus coherent read transaction
produces REVIEW_ONLY, not a permit, valid customer consent or production release.
No modifications to existing DomainStore or its production schema.
"""
from __future__ import annotations

import json
import sqlite3
from contextlib import closing
from pathlib import Path, PosixPath, WindowsPath

from .domain import AssessmentRequestRecord, EngagementRecord, RequestStatus
from .engagements import (
    AssessmentMode,
    AuthorizationGrant,
    EngagementStatus,
    RiskLevel,
    ScopeDefinition,
)
from .request_grant_offline_review_177 import (
    RequestGrantReview,
    ReviewStatus,
    _decision_time,
    _identifier,
    _utc_instant,
    review_request_grant_engagement,
)


_HOLD = RequestGrantReview(ReviewStatus.HOLD, "invalid_or_unverified_input")


def _json_array(value: object) -> tuple[str, ...] | None:
    if type(value) is not str or len(value) > 32_768:
        return None
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, RecursionError):
        return None
    if type(decoded) is not list or not all(type(item) is str for item in decoded):
        return None
    return tuple(decoded)


def _enum(enum_type, value: object):
    if type(value) is not str:
        return None
    try:
        return enum_type(value)
    except ValueError:
        return None


def _risk(value: object) -> RiskLevel | None:
    if type(value) is not int:
        return None
    try:
        return RiskLevel(value)
    except ValueError:
        return None


def _is_real_table(connection: sqlite3.Connection, name: str) -> bool:
    row = connection.execute(
        "SELECT type FROM sqlite_master WHERE name=? LIMIT 2", (name,)
    ).fetchall()
    return len(row) == 1 and row[0][0] == "table"


def _has_provenance_fk(connection: sqlite3.Connection) -> bool:
    """Require structural FK; a plain self-asserted request ID is insufficient."""
    fk_rows = connection.execute(
        "PRAGMA foreign_key_list(authorization_grants)"
    ).fetchall()
    # (id, seq, table, from, to, on_update, on_delete, match)
    bound = [row for row in fk_rows if row[3] == "approved_request_id"]
    return (
        len(bound) == 1
        and bound[0][1] == 0
        and bound[0][2] == "assessment_requests"
        and bound[0][4] == "request_id"
    )


def _load_review(
    connection: sqlite3.Connection,
    grant_id: str,
    reviewed_at,
) -> RequestGrantReview:
    for table in ("assessment_requests", "authorization_grants", "engagements"):
        if not _is_real_table(connection, table):
            return _HOLD
    if not _has_provenance_fk(connection):
        # Shipped M3/M7 schema currently lacks this column and FK.
        return _HOLD

    grants = connection.execute(
        "SELECT * FROM authorization_grants WHERE grant_id=? LIMIT 2",
        (grant_id,),
    ).fetchall()
    if len(grants) != 1:
        return _HOLD
    grant_row = grants[0]
    request_id = grant_row["approved_request_id"]
    if not _identifier(request_id):
        return _HOLD
    requests = connection.execute(
        "SELECT * FROM assessment_requests WHERE request_id=? LIMIT 2",
        (request_id,),
    ).fetchall()
    engagements = connection.execute(
        "SELECT * FROM engagements WHERE engagement_id=? LIMIT 2",
        (grant_row["engagement_id"],),
    ).fetchall()
    if len(requests) != 1 or len(engagements) != 1:
        return _HOLD

    r, e = requests[0], engagements[0]
    # Created-at is a separate durable chronology from the declared
    # not-before window; a grant inserted before operator approval or after
    # the review instant is not structurally admissible even as REVIEW_ONLY.
    decided_at = _decision_time(r["decided_at"])
    persisted_at = _decision_time(grant_row["created_at"])
    if (
        decided_at is None
        or persisted_at is None
        or not (decided_at <= persisted_at <= reviewed_at)
    ):
        return _HOLD
    requested_assets = _json_array(r["requested_assets_json"])
    granted_assets = _json_array(grant_row["assets_json"])
    excluded = _json_array(grant_row["excluded_assets_json"])
    capabilities = _json_array(grant_row["allowed_capabilities_json"])
    if any(item is None for item in (requested_assets, granted_assets, excluded, capabilities)):
        return _HOLD
    # SQLite INTEGER values must be exact ints, not coerced strings or bools.
    request_risk = _risk(r["requested_risk"])
    grant_risk = _risk(grant_row["max_risk"])
    retest = grant_row["recurring_retest_allowed"]
    valid_from = _decision_time(grant_row["valid_from"])
    valid_until = _decision_time(grant_row["valid_until"])
    request_mode = _enum(AssessmentMode, r["requested_mode"])
    request_status = _enum(RequestStatus, r["status"])
    engagement_status = _enum(EngagementStatus, e["status"])
    engagement_created_at = _decision_time(e["created_at"])
    if (
        request_risk is None
        or grant_risk is None
        or type(retest) is not int
        or retest not in (0, 1)
        or valid_from is None
        or valid_until is None
        or request_mode is None
        or request_status is None
        or engagement_status is None
        or engagement_created_at is None
        # A persisted grant may not claim validity before it was recorded,
        # and may not predate the engagement to which it claims to belong.
        # These are snapshot coherence checks, NOT authenticated approval.
        or not (engagement_created_at <= persisted_at <= valid_from)
    ):
        return _HOLD

    request = AssessmentRequestRecord(
        request_id=r["request_id"],
        client_id=r["client_id"],
        requested_assets=requested_assets,
        requested_mode=request_mode,
        requested_risk=request_risk,
        notes=r["notes"],
        status=request_status,
        requested_by=r["requested_by"],
        created_at=r["created_at"],
        decided_by=r["decided_by"],
        decided_at=r["decided_at"],
    )
    grant = AuthorizationGrant(
        grant_id=grant_row["grant_id"],
        client_id=grant_row["client_id"],
        engagement_id=grant_row["engagement_id"],
        approved_by=grant_row["approved_by"],
        reference=grant_row["reference"],
        scope=ScopeDefinition(
            assets=granted_assets,
            max_risk=grant_risk,
            allowed_capabilities=capabilities,
            excluded_assets=excluded,
        ),
        valid_from=valid_from,
        valid_until=valid_until,
        recurring_retest_allowed=bool(retest),
    )
    engagement = EngagementRecord(
        engagement_id=e["engagement_id"],
        client_id=e["client_id"],
        name=e["name"],
        status=engagement_status,
        created_at=e["created_at"],
    )
    # Extra structural checks only; remains REVIEW_ONLY even with real FK.
    return review_request_grant_engagement(
        request, grant, engagement, reviewed_at=reviewed_at
    )


def review_persisted_request_grant(
    database_path: object,
    grant_id: object,
    *,
    reviewed_at: object,
) -> RequestGrantReview:
    """Read a bounded single-grant SQLite snapshot, never authorizing a call.

    The path is an explicit local user-selected database. SQLite opens mode=ro,
    with query_only and an atomic BEGIN/read/ROLLBACK snapshot. Existing M3/M7
    tables lack the necessary approved_request_id foreign key, so HOLD is the
    only result for untouched production databases. Do not point at customer
    databases without separately obtained local data-access permission.
    """
    if type(database_path) not in (str, PosixPath, WindowsPath):
        return _HOLD
    if not _identifier(grant_id) or not _utc_instant(reviewed_at):
        return _HOLD
    try:
        path = Path(database_path).resolve(strict=True)
        if not path.is_file():
            return _HOLD
        # Path.as_uri() escapes query-string characters in the filename.
        uri = path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA trusted_schema=OFF")
            con.execute("BEGIN")
            try:
                return _load_review(con, grant_id, reviewed_at)
            finally:
                con.execute("ROLLBACK")
    except (OSError, sqlite3.Error, KeyError, ValueError, TypeError, OverflowError):
        # No filesystem/schema/SQL/identifier detail is reflected to caller.
        return _HOLD


def review_persisted_grant_batch(
    database_path: object,
    grant_ids: object,
    *,
    reviewed_at: object,
) -> RequestGrantReview:
    """Single-transaction, bounded, read-only review of 1..32 persisted grants.

    Individual REVIEW_ONLY proofs are required before checking duplicate
    persisted requests, cross-tenant records and overlapping effective targets.
    A bad member atomically denies the *entire* batch. This never grants a
    permission; the real M3/M7 schema lacking approved-request FK still HOLDS.
    """
    if type(grant_ids) is not tuple or not 1 <= len(grant_ids) <= 32:
        return _HOLD
    if not all(_identifier(grant_id) for grant_id in grant_ids):
        return _HOLD
    if len(set(grant_ids)) != len(grant_ids):
        return _HOLD
    if type(database_path) not in (str, PosixPath, WindowsPath) or not _utc_instant(reviewed_at):
        return _HOLD

    try:
        path = Path(database_path).resolve(strict=True)
        if not path.is_file():
            return _HOLD
        uri = path.as_uri() + "?mode=ro"
        with closing(sqlite3.connect(uri, uri=True, timeout=1, isolation_level=None)) as con:
            con.row_factory = sqlite3.Row
            con.execute("PRAGMA query_only=ON")
            con.execute("PRAGMA foreign_keys=ON")
            con.execute("PRAGMA trusted_schema=OFF")
            con.execute("BEGIN")
            try:
                tenant: str | None = None
                requests: set[str] = set()
                effective_assets: set[str] = set()
                for grant_id in grant_ids:
                    decision = _load_review(con, grant_id, reviewed_at)
                    if decision.status is not ReviewStatus.REVIEW_ONLY:
                        return _HOLD
                    row = con.execute(
                        "SELECT client_id, approved_request_id, assets_json, "
                        "excluded_assets_json FROM authorization_grants "
                        "WHERE grant_id=? LIMIT 2",
                        (grant_id,),
                    ).fetchall()
                    if len(row) != 1:
                        return _HOLD
                    grant = row[0]
                    client = grant["client_id"]
                    request_id = grant["approved_request_id"]
                    assets = _json_array(grant["assets_json"])
                    excluded = _json_array(grant["excluded_assets_json"])
                    if (
                        not _identifier(client)
                        or not _identifier(request_id)
                        or request_id in requests
                        or (tenant is not None and tenant != client)
                        or assets is None
                        or excluded is None
                    ):
                        return _HOLD
                    effective = set(assets) - set(excluded)
                    if effective_assets.intersection(effective):
                        return _HOLD
                    effective_assets.update(effective)
                    requests.add(request_id)
                    tenant = client
                # Return the same immutable NON-authorizing structural receipt.
                return RequestGrantReview(
                    ReviewStatus.REVIEW_ONLY,
                    "structurally_coherent_untrusted_snapshot",
                )
            finally:
                con.execute("ROLLBACK")
    except (OSError, sqlite3.Error, KeyError, ValueError, TypeError, OverflowError):
        return _HOLD
