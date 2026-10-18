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
            "ORDER BY created_at DESC,grant_id", (chosen,),
        )
        risks = _bounded_rows(
            con,
            "SELECT approval_id,client_id,engagement_id,requested_risk,status,"
            "created_at,decided_at FROM risk_approvals "
            "WHERE client_id=? OR engagement_id IN "
            "(SELECT engagement_id FROM engagements WHERE client_id=?) "
            "ORDER BY created_at DESC,approval_id", (chosen, chosen),
        )

        # Never disclose records from a FOREIGN client merely because a
        # corrupted foreign row points at this tenant's engagement. Report
        # only which of OUR engagement IDs are affected and aggregate counts.
        foreign_rows = con.execute(
            "SELECT engagement_id, COUNT(*) AS n FROM ("
            "SELECT g.engagement_id FROM authorization_grants AS g "
            "JOIN engagements AS e ON e.engagement_id=g.engagement_id "
            "WHERE e.client_id=? AND (g.client_id<>? OR g.client_id IS NULL) "
            "UNION ALL "
            "SELECT r.engagement_id FROM risk_approvals AS r "
            "JOIN engagements AS e ON e.engagement_id=r.engagement_id "
            "WHERE e.client_id=? AND (r.client_id<>? OR r.client_id IS NULL)"
            ") GROUP BY engagement_id",
            (chosen, chosen, chosen, chosen),
        ).fetchall()
        foreign_by_engagement = {
            _identity(r["engagement_id"], "stored engagement"): r["n"]
            for r in foreign_rows
        }
        if sum(foreign_by_engagement.values()) > LIMIT:
            raise CasebookHold("too many foreign-tenant source conflicts")

        reqs = {}
        request_view = []
        for row in requests:
            rid = _identity(_value(row, "request_id"), "request identity")
            if rid in reqs or row["client_id"] != chosen:
                raise CasebookHold("conflicting request origin")
            if row["status"] not in ("submitted", "under_review", "approved", "rejected"):
                raise CasebookHold("unknown request status")
            if type(row["requested_risk"]) is not int or not 0 <= row["requested_risk"] <= 5:
                raise CasebookHold("noncanonical stored request risk")
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
            if type(row["max_risk"]) is not int or not 0 <= row["max_risk"] <= 5:
                raise CasebookHold("noncanonical stored grant risk")
            grant_view.append({
                "grant_id": gid, "engagement_id": eid if eid in engs else None,
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
            if type(row["requested_risk"]) is not int or not 0 <= row["requested_risk"] <= 5:
                raise CasebookHold("noncanonical stored risk decision")
            risk_view.append({
                "approval_id": aid, "engagement_id": eid if eid in engs else None,
                "status": _value(row, "status", 80),
                "requested_risk": row["requested_risk"],
                "source_tenant_matches": row["client_id"] == chosen and eid in engs,
                "decision_recorded": row["decided_at"] is not None,
            })
        # Report no releases or consent. Do not validate grants by tally.
        case_overview = []
        for engagement in engagement_view:
            eid = engagement["engagement_id"]
            linked = [item for item in grant_view if item["engagement_id"] == eid]
            associated_risk = [
                item for item in risk_view if item["engagement_id"] == eid
            ]
            if foreign_by_engagement.get(eid, 0) or any(item["request_link_observation"].startswith("HOLD_")
                   for item in linked) or any(
                not item["source_tenant_matches"] for item in associated_risk
            ):
                attention = "HOLD_SOURCE_PROVENANCE"
            elif linked:
                attention = "REVIEW_ONLY_UNVERIFIED_GRANT_LINK"
            else:
                attention = "NO_GRANT_RECORDED"
            case_overview.append({
                "engagement_id": eid,
                "status": engagement["status"],
                "grant_count": len(linked),
                "risk_record_count": len(associated_risk),
                "attention": attention,
            })
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
            "case_overview": case_overview,
            "declared_counts": {
                "requests": len(request_view), "engagements": len(engagement_view),
                "grants": len(grant_view), "risk_approvals": len(risk_view),
                "grant_link_hold": sum(v for k, v in anomalies.items() if k.startswith("HOLD_")),
                "risk_tenant_hold": sum(not v["source_tenant_matches"] for v in risk_view),
                "case_attention_hold": sum(v["attention"].startswith("HOLD_") for v in case_overview),
                "foreign_tenant_row_count": sum(foreign_by_engagement.values()),
            },
            **AUTHORITY,
        }
        return result
    except (sqlite3.Error, TypeError, OverflowError, KeyError):
        raise CasebookHold("casebook source schema missing or not admitted") from None
    finally:
        con.close()



def authenticated_client_inbox(database: str, *, email: str,
                               password: str) -> dict:
    """Read only real tenant IDs for a freshly authenticated selector.

    Operators can list at most 100 explicit IDs. Clients see only own ID.
    No names, emails, contacts, grants, assets or authorization claims.
    """
    actor_id = _auth_actor(database, email, password)
    con = _read_connection(database)
    try:
        row = con.execute(
            "SELECT role,client_id FROM users WHERE user_id=?",
            (actor_id,),
        ).fetchone()
        if row is None:
            raise CasebookHold("original account no longer present")
        try:
            role = Role(row["role"])
        except (ValueError, TypeError):
            raise CasebookHold("stored role invalid") from None
        if role is Role.OPERATOR and row["client_id"] is None:
            tenants = con.execute(
                "SELECT client_id,status FROM clients "
                "ORDER BY created_at DESC,client_id LIMIT 101"
            ).fetchall()
            if len(tenants) > 100:
                raise CasebookHold("operator tenant list exceeds bounded view")
        elif role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
            owned = _identity(row["client_id"], "persisted tenant")
            tenants = con.execute(
                "SELECT client_id,status FROM clients WHERE client_id=?",
                (owned,),
            ).fetchall()
        else:
            raise CasebookHold("account cannot list tenants")
        items = [{
            "client_id": _identity(t["client_id"], "stored tenant identity"),
            "original_status": _value(t, "status", 80),
        } for t in tenants]
        return {
            "schema": "lightup.auth_casebook_client_inbox.v1",
            "status": "REVIEW_ONLY",
            "clients": items,
            "declared_count": len(items),
            **AUTHORITY,
        }
    except (sqlite3.Error, ValueError, TypeError):
        raise CasebookHold("original client inbox not admitted") from None
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
    parser.add_argument("--list-clients", action="store_true", help="authenticated client-ID selector only")
    args = parser.parse_args(argv)
    if args.list_clients and (args.client is not None or args.output is not None):
        parser.error("--list-clients cannot be combined with --client or --output")
    try:
        password = getpass("LightUp account password: ")
        if args.list_clients:
            result = authenticated_client_inbox(
                args.database, email=args.email, password=password,
            )
            print(json.dumps(result, sort_keys=True, indent=2))
            return 2
        result = authenticated_casebook(
            args.database, email=args.email,
            password=password, client_id=args.client,
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
