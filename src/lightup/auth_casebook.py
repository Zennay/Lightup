"""Authenticated, non-authorizing casebook of original LightUp scope decisions.

Read the *real* existing domain SQLite records in one query-only snapshot.
An operator explicitly selects one client; a client reads its own tenant.
No grant, consent, request, scope, handler, scanner or risk decision is created.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
from getpass import getpass
import json
import os
from pathlib import Path
import sqlite3
import stat
import tempfile
from urllib.parse import quote

from .domain import AccountLockedError, DomainStore, Role

LIMIT = 200
MAX_OUTPUT_BYTES = 512 * 1024
AUTHORITY = {
    "source_authenticated": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "authorization_granted": False,
    "execution_allowed": False,
    "release_approved": False,
}


class CasebookHold(ValueError):
    """A generic, non-disclosing HOLD before any scope decision is inferred."""


def _identity(value: object, label: str) -> str:
    if (type(value) is not str or not 1 <= len(value) <= 180
            or value.strip() != value
            or any(ord(ch) < 33 or ord(ch) == 127 for ch in value)):
        raise CasebookHold(f"invalid {label}")
    return value


def _read_connection(database: str) -> sqlite3.Connection:
    path = Path(database)
    try:
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise CasebookHold("original domain must be a local regular file")
        uri = "file:" + quote(str(path.absolute()), safe="/") + "?mode=ro"
        connection = sqlite3.connect(uri, uri=True, timeout=5, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("PRAGMA foreign_keys=ON")
        connection.execute("BEGIN")
        return connection
    except (OSError, sqlite3.Error, ValueError):
        raise CasebookHold("private original domain unavailable") from None


def _bounded_rows(connection: sqlite3.Connection, sql: str, args: tuple) -> list[sqlite3.Row]:
    rows = connection.execute(sql + " LIMIT ?", (*args, LIMIT + 1)).fetchall()
    if len(rows) > LIMIT:
        raise CasebookHold("large source requires a narrower client selection")
    return rows


def _auth_actor(database: str, email: str, password: str) -> str:
    # Original credentials + lockout, never synthetic trusted contexts.
    path = Path(database)
    if not path.is_file() or path.is_symlink():
        raise CasebookHold("original domain unavailable")
    try:
        user = DomainStore(path).authenticate(email, password)
    except (AccountLockedError, sqlite3.Error, ValueError):
        raise CasebookHold("original account authentication refused") from None
    if user is None:
        raise CasebookHold("original account authentication refused")
    return _identity(user.user_id, "account identity")


def _value(row: sqlite3.Row, key: str, length: int = 180) -> str:
    value = row[key]
    if (type(value) is not str or len(value) > length
            or any(ord(c) < 32 or ord(c) == 127 for c in value)):
        raise CasebookHold("malformed stored source identity")
    return value


def _source_snapshot(database: str, *, actor_id: str, client_id: str | None) -> dict:
    con = _read_connection(database)
    try:
        actor = con.execute(
            "SELECT role,client_id FROM users WHERE user_id=?", (actor_id,)
        ).fetchone()
        if actor is None:
            raise CasebookHold("authenticated account unavailable in snapshot")
        try:
            role = Role(actor["role"])
        except (ValueError, TypeError):
            raise CasebookHold("unknown stored account role") from None
        if role is Role.OPERATOR:
            if actor["client_id"] is not None or client_id is None:
                raise CasebookHold("operator must select one explicit client")
            chosen = _identity(client_id, "selected tenant")
        elif role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
            chosen = _identity(actor["client_id"], "stored tenant")
            if client_id is not None and client_id != chosen:
                raise CasebookHold("client cannot view another tenant")
        else:
            raise CasebookHold("unknown account permission")
        client = con.execute(
            "SELECT client_id,status FROM clients WHERE client_id=?", (chosen,)
        ).fetchone()
        if client is None or _value(client, "client_id") != chosen:
            raise CasebookHold("selected tenant unavailable")
        if client["status"] != "active":
            raise CasebookHold("inactive client: snapshot denied")

        requests = _bounded_rows(
            con,
            "SELECT request_id,status,requested_mode,requested_risk,created_at,decided_at,"
            "client_id,requested_by,decided_by FROM assessment_requests "
            "WHERE client_id=? ORDER BY created_at DESC,request_id", (chosen,),
        )
        engagements = _bounded_rows(
            con,
            "SELECT engagement_id,client_id,status,created_at FROM engagements "
            "WHERE client_id=? ORDER BY created_at DESC,engagement_id", (chosen,),
        )
        grants = _bounded_rows(
            con,
            "SELECT grant_id,client_id,engagement_id,approved_request_id,"
            "max_risk,valid_from,valid_until,created_at "
            "FROM authorization_grants WHERE client_id=? "
            "OR engagement_id IN (SELECT engagement_id FROM engagements WHERE client_id=?) "
            "ORDER BY created_at DESC,grant_id", (chosen, chosen),
        )
        risks = _bounded_rows(
            con,
            "SELECT approval_id,client_id,engagement_id,requested_risk,status,"
            "created_at,decided_at FROM risk_approvals "
            "WHERE client_id=? OR engagement_id IN "
            "(SELECT engagement_id FROM engagements WHERE client_id=?) "
            "ORDER BY created_at DESC,approval_id", (chosen, chosen),
        )

        reqs = {}
        request_view = []
        for row in requests:
            rid = _identity(_value(row, "request_id"), "request identity")
            if rid in reqs or row["client_id"] != chosen:
                raise CasebookHold("conflicting request origin")
            if row["status"] not in ("submitted", "under_review", "approved", "rejected"):
                raise CasebookHold("unknown request status")
            reqs[rid] = row
            request_view.append({
                "request_id": rid,
                "status": row["status"],
                "requested_mode": _value(row, "requested_mode", 80),
                "requested_risk": row["requested_risk"],
                "created_at": _value(row, "created_at", 80),
                "decision_recorded": row["decided_at"] is not None,
            })
        engs = {}
        engagement_view = []
        for row in engagements:
            eid = _identity(_value(row, "engagement_id"), "engagement identity")
            if eid in engs or row["client_id"] != chosen:
                raise CasebookHold("conflicting engagement tenant")
            engs[eid] = row
            engagement_view.append({
                "engagement_id": eid, "status": _value(row, "status", 80),
                "created_at": _value(row, "created_at", 80),
            })
        grant_view = []
        seen_grants = set()
        for row in grants:
            gid = _identity(_value(row, "grant_id"), "grant identity")
            if gid in seen_grants:
                raise CasebookHold("duplicate stored grant")
            seen_grants.add(gid)
            eid = _identity(_value(row, "engagement_id"), "grant engagement")
            binding = row["approved_request_id"]
            if binding is not None:
                binding = _identity(binding, "request binding")
            origin = reqs.get(binding)
            # A linkage label is retrospective source observation only.
            # It NEVER performs canonical asset/capability/consent admission.
            if eid not in engs or row["client_id"] != chosen:
                notice = "HOLD_TENANT_OR_ENGAGEMENT_MISMATCH"
            elif binding is None:
                notice = "HOLD_NO_REQUEST_BINDING"
            elif origin is None:
                notice = "HOLD_REQUEST_SOURCE_MISSING"
            elif origin["status"] != "approved":
                notice = "HOLD_REQUEST_NOT_APPROVED"
            else:
                notice = "REQUEST_LINK_DECLARED_NOT_VERIFIED"
            grant_view.append({
                "grant_id": gid, "engagement_id": eid,
                "approved_request_id": binding, "request_link_observation": notice,
                "max_risk": row["max_risk"],
                "valid_from": _value(row, "valid_from", 80),
                "valid_until": _value(row, "valid_until", 80),
            })
        risk_view = []
        seen_risks = set()
        for row in risks:
            aid = _identity(_value(row, "approval_id"), "risk approval identity")
            if aid in seen_risks:
                raise CasebookHold("duplicate risk approval")
            seen_risks.add(aid)
            eid = _identity(_value(row, "engagement_id"), "risk engagement")
            risk_view.append({
                "approval_id": aid, "engagement_id": eid,
                "status": _value(row, "status", 80),
                "requested_risk": row["requested_risk"],
                "source_tenant_matches": row["client_id"] == chosen and eid in engs,
                "decision_recorded": row["decided_at"] is not None,
            })
        # Report no releases or consent. Do not validate grants by tally.
        anomalies = Counter(x["request_link_observation"] for x in grant_view)
        result = {
            "schema": "lightup.auth_casebook.v1",
            "status": "REVIEW_ONLY",
            "source": "original_persisted_domain_unverified",
            "as_of": datetime.now(timezone.utc).isoformat(),
            "client_id": chosen,
            "requests": request_view,
            "engagements": engagement_view,
            "grants": grant_view,
            "risk_approvals": risk_view,
            "declared_counts": {
                "requests": len(request_view), "engagements": len(engagement_view),
                "grants": len(grant_view), "risk_approvals": len(risk_view),
                "grant_link_hold": sum(v for k, v in anomalies.items() if k.startswith("HOLD_")),
                "risk_tenant_hold": sum(not v["source_tenant_matches"] for v in risk_view),
            },
            **AUTHORITY,
        }
        return result
    except (sqlite3.Error, TypeError, OverflowError, KeyError):
        raise CasebookHold("casebook source schema missing or not admitted") from None
    finally:
        con.close()


def authenticated_casebook(database: str, *, email: str,
                           password: str, client_id: str | None = None) -> dict:
    """Single-tenant authenticated source snapshot; no grant issuance."""
    user_id = _auth_actor(database, email, password)
    return _source_snapshot(database, actor_id=user_id, client_id=client_id)


def _write_private_json(destination: str, source: dict) -> None:
    """Exclusive, fsync'd, no-replace local private report publication."""
    payload = (json.dumps(source, sort_keys=True, indent=2, allow_nan=False) + "\n").encode("utf-8")
    if len(payload) > MAX_OUTPUT_BYTES:
        raise CasebookHold("casebook private source exceeded bound")
    target = Path(destination)
    if not target.parent.is_dir() or target.is_symlink() or target.exists():
        raise CasebookHold("private report destination unavailable")
    fd, temp = tempfile.mkstemp(prefix=".lightup-casebook-", dir=target.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as stream:
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.link(temp, target, follow_symlinks=False)
    except OSError:
        raise CasebookHold("private source could not be published") from None
    finally:
        try:
            os.unlink(temp)
        except OSError:
            pass


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.auth_casebook",
        description="Private original-domain request→grant→risk casebook; REVIEW_ONLY.",
    )
    parser.add_argument("--database", required=True, help="existing original local domain SQLite")
    parser.add_argument("--email", required=True, help="existing operator/client login")
    parser.add_argument("--client", help="required exact tenant ID for operator; optional matching ID for client")
    parser.add_argument("--output", help="new private 0600 JSON; never overwrite")
    args = parser.parse_args(argv)
    try:
        result = authenticated_casebook(
            args.database, email=args.email,
            password=getpass("LightUp account password: "), client_id=args.client,
        )
        if args.output is not None:
            _write_private_json(args.output, result)
        print(json.dumps({
            "schema": result["schema"], "status": result["status"],
            "declared_counts": result["declared_counts"],
            "private_output_created": args.output is not None,
            **AUTHORITY,
        }, sort_keys=True, indent=2))
        return 2
    except (CasebookHold, EOFError, KeyboardInterrupt):
        print(json.dumps({"status": "HOLD", **AUTHORITY}, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
