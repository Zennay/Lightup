"""Authenticated, deny-only emergency STOP ledger for LightUp engagements.

Separate, source-isolated operator/client product. It can record and display a
durable STOP but cannot authorize, issue a grant, dispatch a handler, run a
model, or interact with a target. The central action-time execution boundary
must adopt this veto *in addition to*, never instead of, existing controls.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
import os
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote
from uuid import uuid4

from .domain import AccountLockedError, DomainStore, Role

_MAX_REASON = 500
_MAX_HISTORY = 64
_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorization_stop_events (
    stop_id TEXT PRIMARY KEY,
    client_id TEXT NOT NULL,
    engagement_id TEXT NOT NULL,
    actor_id TEXT NOT NULL,
    actor_role TEXT NOT NULL CHECK(actor_role IN ('operator','client_admin','client_member')),
    reason TEXT NOT NULL,
    stopped_at TEXT NOT NULL,
    FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id),
    FOREIGN KEY(actor_id) REFERENCES users(user_id),
    FOREIGN KEY(client_id) REFERENCES clients(client_id)
);
CREATE INDEX IF NOT EXISTS idx_authorization_stop_engagement
ON authorization_stop_events(client_id, engagement_id, stopped_at);
"""


class StopLedgerError(ValueError):
    """Generic refusal; never echo private database contents or passwords."""


def _literal(value: str, field: str, *, maximum: int = 180) -> str:
    if (type(value) is not str or not 1 <= len(value) <= maximum
            or any(ord(c) < 32 or ord(c) == 127 for c in value)
            or value != value.strip()):
        raise StopLedgerError(f"invalid {field}")
    return value


def _open_existing_db(path: str) -> sqlite3.Connection:
    """Open an existing local DB only; never accidentally create a new domain."""
    source = Path(path)
    try:
        info = source.lstat()
        if not stat.S_ISREG(info.st_mode) or stat.S_ISLNK(info.st_mode):
            raise StopLedgerError("domain database must be an existing regular file")
        uri = "file:" + quote(str(source.absolute()), safe="/") + "?mode=rw"
        con = sqlite3.connect(uri, uri=True, timeout=10, isolation_level=None)
        con.row_factory = sqlite3.Row
        con.execute("PRAGMA foreign_keys=ON")
        return con
    except (OSError, sqlite3.Error) as exc:
        raise StopLedgerError("domain database unavailable") from None


def _require_current_actor(con: sqlite3.Connection, actor_id: str,
                           client_id: str) -> Role:
    actor = con.execute(
        "SELECT role,client_id FROM users WHERE user_id=?", (actor_id,)
    ).fetchone()
    if actor is None:
        raise StopLedgerError("authenticated account no longer exists")
    try:
        role = Role(actor["role"])
    except (TypeError, ValueError):
        raise StopLedgerError("invalid persisted actor role") from None
    if role is Role.OPERATOR:
        if actor["client_id"] is not None:
            raise StopLedgerError("operator tenant provenance invalid")
    elif role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER):
        if actor["client_id"] != client_id:
            raise StopLedgerError("client is not owner of engagement")
    else:
        raise StopLedgerError("role cannot request STOP")
    return role


def _engagement_client(con: sqlite3.Connection, engagement_id: str) -> str:
    record = con.execute(
        "SELECT e.client_id FROM engagements AS e "
        "JOIN clients AS c ON c.client_id=e.client_id "
        "WHERE e.engagement_id=?",
        (engagement_id,),
    ).fetchone()
    if record is None or type(record["client_id"]) is not str:
        raise StopLedgerError("engagement not available")
    return _literal(record["client_id"], "stored client identity")


def authenticate_domain_user(db_path: str, email: str, password: str) -> str:
    """Authenticate through original persisted credentials and lockout.

    No operator/client identity may be supplied directly to a write operation.
    """
    con = _open_existing_db(db_path)
    con.close()
    try:
        user = DomainStore(db_path).authenticate(email, password)
    except (AccountLockedError, ValueError, sqlite3.Error) as exc:
        raise StopLedgerError("authentication unavailable or refused") from None
    if user is None:
        raise StopLedgerError("authentication refused")
    return _literal(user.user_id, "authenticated actor identity")


def _append_stop_authenticated_actor(db_path: str, *, engagement_id: str, actor_id: str,
                reason: str) -> dict:
    """Append one irreversible-through-this-API STOP with current persisted roles.

    Call only after authenticate_domain_user; web integrations MUST additionally
    resolve their own real authenticated session at the action instant.
    """
    engagement_id = _literal(engagement_id, "engagement identity")
    actor_id = _literal(actor_id, "actor identity")
    if type(reason) is not str or len(reason) > _MAX_REASON or any(
        ord(c) < 32 and c not in "\t" for c in reason
    ):
        raise StopLedgerError("STOP reason must be bounded plain text")
    con = _open_existing_db(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        client_id = _engagement_client(con, engagement_id)
        role = _require_current_actor(con, actor_id, client_id)
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                con.execute(statement)
        stop_id, when = str(uuid4()), datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO authorization_stop_events"
            "(stop_id,client_id,engagement_id,actor_id,actor_role,reason,stopped_at)"
            "VALUES (?,?,?,?,?,?,?)",
            (stop_id, client_id, engagement_id, actor_id, role.value,
             reason.strip(), when),
        )
        con.execute("COMMIT")
        return {
            "schema": "lightup.authenticated_stop.v1",
            "status": "STOP_RECORDED",
            "stop_id": stop_id,
            "stopped_at": when,
            "actor_role": role.value,
            "scope": "single_engagement",
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
            "source_cryptographically_signed": False,
        }
    except (sqlite3.Error, ValueError, TypeError) as exc:
        if con.in_transaction:
            con.execute("ROLLBACK")
        if isinstance(exc, StopLedgerError):
            raise
        raise StopLedgerError("STOP could not be durably recorded") from None
    finally:
        con.close()


def record_authenticated_stop(db_path: str, *, engagement_id: str,
                              email: str, password: str, reason: str = "") -> dict:
    """Public authenticated write entry point; identity is never caller-supplied."""
    actor_id = authenticate_domain_user(db_path, email, password)
    return _append_stop_authenticated_actor(
        db_path, engagement_id=engagement_id, actor_id=actor_id,
        reason=reason,
    )


def status_for_actor(db_path: str, *, engagement_id: str, actor_id: str) -> dict:
    """Read STOP history after a freshly authenticated user's role recheck."""
    engagement_id = _literal(engagement_id, "engagement identity")
    actor_id = _literal(actor_id, "actor identity")
    con = _open_existing_db(db_path)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        tenant = _engagement_client(con, engagement_id)
        _require_current_actor(con, actor_id, tenant)
        entries = con.execute(
            "SELECT stop_id,actor_role,stopped_at FROM authorization_stop_events "
            "WHERE engagement_id=? AND client_id=? "
            "ORDER BY stopped_at DESC,stop_id DESC LIMIT ?",
            (engagement_id, tenant, _MAX_HISTORY + 1),
        ).fetchall()
        return {
            "schema": "lightup.authenticated_stop.v1",
            "status": "STOP_ACTIVE" if entries else "NO_STOP_RECORDED",
            "stop_active": bool(entries),
            "history_truncated": len(entries) > _MAX_HISTORY,
            "recent_events": [
                {"stop_id": r["stop_id"], "actor_role": r["actor_role"],
                 "stopped_at": r["stopped_at"]} for r in entries[:_MAX_HISTORY]
            ],
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (sqlite3.Error, ValueError, TypeError):
        raise StopLedgerError("STOP status unavailable: HOLD") from None
    finally:
        con.close()


def deny_only_stop_state(db_path: str, *, engagement_id: str,
                         client_id: str) -> dict:
    """Engine-facing veto observation; *never* a positive authorization.

    Missing schema, DB, inconsistent tenant or source error means HOLD. A
    NO_STOP_RECORDED observation also leaves execution_allowed false. Upstream
    owner must wire this as a mandatory additional action-time guard.
    """
    try:
        engagement_id = _literal(engagement_id, "engagement identity")
        client_id = _literal(client_id, "client identity")
        con = _open_existing_db(db_path)
        try:
            con.execute("PRAGMA query_only=ON")
            con.execute("BEGIN")
            if _engagement_client(con, engagement_id) != client_id:
                raise StopLedgerError("tenant mismatch")
            if not _stop_schema_current(con):
                raise StopLedgerError("STOP schema mismatch")
            count = con.execute(
                "SELECT COUNT(*) AS n FROM authorization_stop_events "
                "WHERE client_id=? AND engagement_id=?",
                (client_id, engagement_id),
            ).fetchone()["n"]
            if type(count) is not int or count < 0:
                raise StopLedgerError("invalid STOP count")
        finally:
            con.close()
        state = "STOP_ACTIVE" if count else "NO_STOP_RECORDED"
    except (StopLedgerError, sqlite3.Error, ValueError, TypeError):
        state = "HOLD"
    return {
        "schema": "lightup.authenticated_stop_veto.v1",
        "status": state,
        "stop_active": state == "STOP_ACTIVE",
        "veto_execution": state != "NO_STOP_RECORDED",
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
    }



def initialize_authenticated_stop_ledger(db_path: str, *,
                                         email: str, password: str) -> dict:
    """Create empty deny-only STOP schema, with an authenticated real operator.

    This prepares only storage. It never approves, issues or resumes anything.
    """
    actor_id = authenticate_domain_user(db_path, email, password)
    con = _open_existing_db(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        actor = con.execute(
            "SELECT role,client_id FROM users WHERE user_id=?", (actor_id,)
        ).fetchone()
        if (actor is None or actor["role"] != Role.OPERATOR.value
                or actor["client_id"] is not None):
            raise StopLedgerError("STOP ledger setup requires a real operator")
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                con.execute(statement)
        if not _stop_schema_current(con):
            raise StopLedgerError("STOP schema mismatch: HOLD")
        con.execute("COMMIT")
        return {
            "schema": "lightup.authenticated_stop_setup.v1",
            "status": "LEDGER_INITIALIZED_REVIEW_ONLY",
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (sqlite3.Error, ValueError, TypeError) as exc:
        if con.in_transaction:
            con.execute("ROLLBACK")
        if isinstance(exc, StopLedgerError):
            raise
        raise StopLedgerError("STOP ledger initialization refused: HOLD") from None
    finally:
        con.close()


def _stop_schema_current(con: sqlite3.Connection) -> bool:
    """Check exact expected core shape before interpreting an empty ledger."""
    cols = con.execute("PRAGMA table_info(authorization_stop_events)").fetchall()
    if len(cols) != 7:
        return False
    names = ("stop_id", "client_id", "engagement_id", "actor_id",
             "actor_role", "reason", "stopped_at")
    if tuple(r["name"] for r in cols) != names:
        return False
    if any(r["type"].upper() != "TEXT" for r in cols):
        return False
    if cols[0]["pk"] != 1 or any(r["pk"] for r in cols[1:]):
        return False
    if any(r["notnull"] != 1 for r in cols[1:]):
        return False
    refs = {(r["from"], r["table"], r["to"])
            for r in con.execute("PRAGMA foreign_key_list(authorization_stop_events)")}
    return refs == {
        ("client_id", "clients", "client_id"),
        ("engagement_id", "engagements", "engagement_id"),
        ("actor_id", "users", "user_id"),
    }


def engagement_inbox(db_path: str, *, actor_id: str) -> dict:
    """Authenticated, bounded list of real engagements and recorded STOP state.

    No synthesized scope, consent, capability or launch permission is returned.
    """
    actor_id = _literal(actor_id, "actor identity")
    con = _open_existing_db(db_path)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        actor = con.execute(
            "SELECT role,client_id FROM users WHERE user_id=?", (actor_id,)
        ).fetchone()
        if actor is None:
            raise StopLedgerError("actor no longer exists")
        try:
            role = Role(actor["role"])
        except (ValueError, TypeError):
            raise StopLedgerError("invalid persisted role") from None
        if role is Role.OPERATOR and actor["client_id"] is None:
            rows = con.execute(
                "SELECT e.engagement_id,e.status FROM engagements AS e "
                "JOIN clients AS c ON c.client_id=e.client_id "
                "ORDER BY e.created_at DESC,e.engagement_id LIMIT 101"
            ).fetchall()
        elif role in (Role.CLIENT_ADMIN, Role.CLIENT_MEMBER) and actor["client_id"]:
            rows = con.execute(
                "SELECT e.engagement_id,e.status FROM engagements AS e "
                "JOIN clients AS c ON c.client_id=e.client_id "
                "WHERE e.client_id=? ORDER BY e.created_at DESC,e.engagement_id LIMIT 101",
                (actor["client_id"],),
            ).fetchall()
        else:
            raise StopLedgerError("account cannot view engagement inbox")
        has_table = con.execute(
            "SELECT 1 FROM sqlite_master "
            "WHERE type='table' AND name='authorization_stop_events'"
        ).fetchone() is not None
        result = []
        for row in rows[:100]:
            engagement_id = _literal(row["engagement_id"], "persisted engagement")
            if has_table:
                stopped = con.execute(
                    "SELECT 1 FROM authorization_stop_events "
                    "WHERE engagement_id=? LIMIT 1", (engagement_id,),
                ).fetchone() is not None
                state = "STOP_ACTIVE" if stopped else "NO_STOP_RECORDED"
            else:
                state = "HOLD_LEDGER_NOT_INITIALIZED"
            result.append({
                "engagement_id": engagement_id,
                "original_engagement_status": row["status"],
                "stop_status": state,
            })
        return {
            "schema": "lightup.authenticated_stop_inbox.v1",
            "status": "REVIEW_ONLY",
            "engagements": result,
            "truncated": len(rows) > 100,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (sqlite3.Error, ValueError, TypeError):
        raise StopLedgerError("STOP inbox unavailable: HOLD") from None
    finally:
        con.close()


def _private_receipt(path: str, result: dict) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    body = (json.dumps(result, sort_keys=True, indent=2) + "\n").encode("utf-8")
    if len(body) > 16_384:
        raise StopLedgerError("receipt size rejected")
    try:
        fd = os.open(path, flags, 0o600)
    except OSError:
        raise StopLedgerError("private receipt destination unavailable") from None
    try:
        with os.fdopen(fd, "wb") as writer:
            writer.write(body)
    except OSError:
        try:
            os.unlink(path)
        except OSError:
            pass
        raise StopLedgerError("receipt write failed; STOP may still be recorded") from None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.revocation_stop",
        description="Authenticated deny-only engagement STOP (NOT an authorization).",
    )
    parser.add_argument("action", choices=("stop", "status", "list", "init"))
    parser.add_argument("--database", required=True, help="existing LightUp domain SQLite")
    parser.add_argument("--engagement", help="exact existing engagement ID for stop/status")
    parser.add_argument("--email", required=True, help="existing operator/client account")
    parser.add_argument("--reason", default="", help="optional STOP reason; private DB only")
    parser.add_argument("--receipt", help="optional NEW owner-only JSON receipt for STOP")
    args = parser.parse_args(argv)
    if args.action not in ("list", "init") and not args.engagement:
        parser.error("--engagement is required for stop/status")
    if args.action in ("list", "init") and args.engagement:
        parser.error("--engagement is not used with list")
    if args.receipt and args.action != "stop":
        parser.error("--receipt is available only with stop")
    if args.action != "stop" and args.reason:
        parser.error("--reason is available only with stop")
    try:
        password = getpass("LightUp password: ")
        if args.action == "init":
            print(json.dumps(initialize_authenticated_stop_ledger(
                args.database, email=args.email, password=password,
            ), sort_keys=True, indent=2))
            return 2
        if args.action == "stop":
            result = record_authenticated_stop(
                args.database, engagement_id=args.engagement,
                email=args.email, password=password, reason=args.reason,
            )
            if args.receipt:
                try:
                    _private_receipt(args.receipt, result)
                    result["private_receipt_created"] = True
                except StopLedgerError:
                    result["private_receipt_created"] = False
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0
        actor_id = authenticate_domain_user(args.database, args.email, password)
        if args.action == "list":
            print(json.dumps(engagement_inbox(args.database, actor_id=actor_id), sort_keys=True, indent=2))
            return 2
        result = status_for_actor(
            args.database, engagement_id=args.engagement, actor_id=actor_id,
        )
        print(json.dumps(result, sort_keys=True, indent=2))
        return 2  # status inspection is never a signal to authorize
    except (StopLedgerError, KeyboardInterrupt, EOFError):
        print(json.dumps({
            "status": "HOLD", "authorization_granted": False,
            "execution_allowed": False, "release_approved": False,
        }))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
