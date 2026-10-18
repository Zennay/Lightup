"""Atomic authenticated emergency STOP for a bounded selected engagement cohort.

Manual incident response only. This cannot restart or authorize execution,
change an existing grant, or invoke a network target/handler.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
import sqlite3
from uuid import uuid4

from .revocation_stop import (
    StopLedgerError, _SCHEMA, _engagement_client, _literal,
    _open_existing_db, _private_receipt, _require_current_actor,
    _stop_schema_current,
    authenticate_domain_user,
)

MAX_BATCH = 32


def record_authenticated_stop_batch(
    database: str, *, engagements: tuple[str, ...], email: str,
    password: str, reason: str = "",
) -> dict:
    """All selected stops commit or none, using one authenticated actor."""
    if (type(engagements) is not tuple or not 1 <= len(engagements) <= MAX_BATCH):
        raise StopLedgerError("select 1–32 exact engagement IDs")
    ids = tuple(_literal(v, "engagement identity") for v in engagements)
    if len(set(ids)) != len(ids):
        raise StopLedgerError("duplicate engagement selection")
    if (type(reason) is not str or len(reason) > 500
            or any(ord(c) < 32 and c not in "\t" for c in reason)):
        raise StopLedgerError("invalid bounded stop reason")
    actor_id = authenticate_domain_user(database, email, password)
    con = _open_existing_db(database)
    try:
        con.execute("BEGIN IMMEDIATE")
        # Full-batch admission precedes all INSERTs; a client may select only
        # own tenant. Operators may explicitly select multiple clients.
        selection = []
        for engagement_id in ids:
            client_id = _engagement_client(con, engagement_id)
            role = _require_current_actor(con, actor_id, client_id)
            selection.append((engagement_id, client_id, role.value))
        for statement in _SCHEMA.split(";"):
            if statement.strip():
                con.execute(statement)
        if not _stop_schema_current(con):
            raise StopLedgerError("STOP schema mismatch: HOLD")
        when = datetime.now(timezone.utc).isoformat()
        private_events = []
        for engagement_id, client_id, actor_role in selection:
            stop_id = str(uuid4())
            con.execute(
                "INSERT INTO authorization_stop_events"
                "(stop_id,client_id,engagement_id,actor_id,actor_role,reason,stopped_at)"
                "VALUES (?,?,?,?,?,?,?)",
                (stop_id, client_id, engagement_id, actor_id,
                 actor_role, reason.strip(), when),
            )
            private_events.append({
                "engagement_id": engagement_id,
                "stop_id": stop_id,
            })
        con.execute("COMMIT")
        return {
            "schema": "lightup.authenticated_stop_batch.v1",
            "status": "STOP_RECORDED_BATCH",
            "recorded_count": len(private_events),
            "stopped_at": when,
            "records": private_events,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (StopLedgerError, sqlite3.Error, ValueError, TypeError) as exc:
        if con.in_transaction:
            con.execute("ROLLBACK")
        if isinstance(exc, StopLedgerError):
            raise
        raise StopLedgerError("batch emergency STOP unavailable: HOLD") from None
    finally:
        con.close()


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.stop_batch",
        description="Atomic deny-only incident STOP for 1–32 existing engagements.",
    )
    parser.add_argument("--database", required=True, help="existing private LightUp SQLite")
    parser.add_argument("--email", required=True, help="existing operator/client account")
    parser.add_argument("--engagement", required=True, action="append",
                        help="one existing ID; repeat this flag for each engagement")
    parser.add_argument("--reason", default="", help="optional private incident note")
    parser.add_argument("--receipt", help="optional NEW exclusive owner-only JSON receipt")
    args = parser.parse_args(argv)
    try:
        password = getpass("LightUp incident operator/client password: ")
        result = record_authenticated_stop_batch(
            args.database, engagements=tuple(args.engagement),
            email=args.email, password=password, reason=args.reason,
        )
        if args.receipt:
            try:
                _private_receipt(args.receipt, result)
                result["private_receipt_created"] = True
            except StopLedgerError:
                # Receipt is not part of durable STOP transaction.
                result["private_receipt_created"] = False
        # Standard output is a privacy-minimal receipt. Private record IDs
        # belong solely in the explicitly requested private file.
        print(json.dumps({
            k: v for k, v in result.items() if k != "records"
        }, indent=2, sort_keys=True))
        return 0
    except (StopLedgerError, EOFError, KeyboardInterrupt):
        print(json.dumps({
            "status": "HOLD", "authorization_granted": False,
            "execution_allowed": False, "release_approved": False,
        }))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
