"""Credential-backed, operator-only acknowledgment of emergency STOP events.

Acknowledgment is a communication receipt, not a grant, restart, lift of STOP,
client consent, security attestation or permission to execute.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
import sqlite3
from uuid import uuid4

from .domain import Role
from .revocation_stop import (
    StopLedgerError, _literal, _open_existing_db, authenticate_domain_user,
)

_ACK_SCHEMA = """
CREATE TABLE IF NOT EXISTS authorization_stop_acknowledgments (
    acknowledgment_id TEXT PRIMARY KEY,
    stop_id TEXT NOT NULL UNIQUE,
    engagement_id TEXT NOT NULL,
    operator_id TEXT NOT NULL,
    acknowledged_at TEXT NOT NULL,
    FOREIGN KEY(stop_id) REFERENCES authorization_stop_events(stop_id),
    FOREIGN KEY(engagement_id) REFERENCES engagements(engagement_id),
    FOREIGN KEY(operator_id) REFERENCES users(user_id)
)
"""
_INDEX = """
CREATE INDEX IF NOT EXISTS idx_authorization_stop_ack_engagement
ON authorization_stop_acknowledgments(engagement_id, acknowledged_at)
"""


def _require_operator(con: sqlite3.Connection, user_id: str) -> None:
    row = con.execute(
        "SELECT role,client_id FROM users WHERE user_id=?", (user_id,)
    ).fetchone()
    if row is None or row["role"] != Role.OPERATOR.value or row["client_id"] is not None:
        raise StopLedgerError("current persisted account is not a real operator")


def _ack_after_login(db_path: str, *, stop_id: str, actor_id: str) -> dict:
    stop_id = _literal(stop_id, "stop ID")
    actor_id = _literal(actor_id, "authenticated operator ID")
    con = _open_existing_db(db_path)
    try:
        con.execute("BEGIN IMMEDIATE")
        _require_operator(con, actor_id)
        event = con.execute(
            "SELECT s.stop_id,s.actor_id,s.engagement_id,s.client_id "
            "FROM authorization_stop_events AS s "
            "JOIN engagements AS e ON e.engagement_id=s.engagement_id "
            "AND e.client_id=s.client_id "
            "WHERE s.stop_id=?", (stop_id,),
        ).fetchone()
        if event is None:
            raise StopLedgerError("STOP event not found or corrupt")
        if event["actor_id"] == actor_id:
            raise StopLedgerError("STOP initiator cannot acknowledge own event")
        con.execute(_ACK_SCHEMA)
        con.execute(_INDEX)
        ack_id, at = str(uuid4()), datetime.now(timezone.utc).isoformat()
        con.execute(
            "INSERT INTO authorization_stop_acknowledgments"
            "(acknowledgment_id,stop_id,engagement_id,operator_id,acknowledged_at)"
            "VALUES (?,?,?,?,?)",
            (ack_id, stop_id, event["engagement_id"], actor_id, at),
        )
        con.execute("COMMIT")
        return {
            "schema": "lightup.stop_acknowledgment.v1",
            "status": "ACKNOWLEDGED_STOP_STILL_ACTIVE",
            "acknowledgment_id": ack_id,
            "stop_id": stop_id,
            "acknowledged_at": at,
            "client_consent_verified": False,
            "operator_consent_verified": False,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (StopLedgerError, sqlite3.Error, ValueError, TypeError) as exc:
        if con.in_transaction:
            con.execute("ROLLBACK")
        if isinstance(exc, StopLedgerError):
            raise
        raise StopLedgerError("STOP acknowledgment unavailable: HOLD") from None
    finally:
        con.close()


def acknowledge_stop(db_path: str, *, stop_id: str,
                     email: str, password: str) -> dict:
    """Authenticate a genuinely distinct live operator account before writing."""
    actor_id = authenticate_domain_user(db_path, email, password)
    return _ack_after_login(db_path, stop_id=stop_id, actor_id=actor_id)


def _pending_after_login(db_path: str, *, actor_id: str) -> dict:
    actor_id = _literal(actor_id, "authenticated operator ID")
    con = _open_existing_db(db_path)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        _require_operator(con, actor_id)
        ack_table = con.execute(
            "SELECT 1 FROM sqlite_master WHERE type='table' "
            "AND name='authorization_stop_acknowledgments'"
        ).fetchone()
        if ack_table is not None:
            rows = con.execute(
                "SELECT s.stop_id,s.stopped_at,s.actor_role "
                "FROM authorization_stop_events AS s "
                "LEFT JOIN authorization_stop_acknowledgments AS a "
                "ON a.stop_id=s.stop_id "
                "WHERE a.stop_id IS NULL "
                "ORDER BY s.stopped_at ASC,s.stop_id ASC LIMIT 101"
            ).fetchall()
        else:
            rows = con.execute(
                "SELECT s.stop_id,s.stopped_at,s.actor_role "
                "FROM authorization_stop_events AS s "
                "ORDER BY s.stopped_at ASC,s.stop_id ASC LIMIT 101"
            ).fetchall()
        return {
            "schema": "lightup.stop_acknowledgment_inbox.v1",
            "status": "REVIEW_ONLY",
            "pending": [
                {"stop_id": _literal(r["stop_id"], "persisted STOP ID"),
                 "stopped_at": r["stopped_at"],
                 "actor_role": r["actor_role"]}
                for r in rows[:100]
            ],
            "truncated": len(rows) > 100,
            "client_consent_verified": False,
            "operator_consent_verified": False,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (StopLedgerError, sqlite3.Error, ValueError, TypeError):
        raise StopLedgerError("pending STOP inbox unavailable: HOLD") from None
    finally:
        con.close()


def pending_stops(db_path: str, *, email: str, password: str) -> dict:
    actor_id = authenticate_domain_user(db_path, email, password)
    return _pending_after_login(db_path, actor_id=actor_id)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.stop_acknowledgment",
        description="Operator STOP inbox and two-person acknowledgment, never restart.",
    )
    parser.add_argument("action", choices=("pending", "ack"))
    parser.add_argument("--database", required=True, help="existing LightUp SQLite")
    parser.add_argument("--email", required=True, help="real original operator account")
    parser.add_argument("--stop-id", help="exact persisted STOP event for ack")
    args = parser.parse_args(argv)
    if args.action == "ack" and not args.stop_id:
        parser.error("ack requires --stop-id")
    if args.action == "pending" and args.stop_id:
        parser.error("pending does not accept a STOP ID")
    try:
        password = getpass("LightUp operator password: ")
        if args.action == "ack":
            result = acknowledge_stop(
                args.database, stop_id=args.stop_id,
                email=args.email, password=password,
            )
            print(json.dumps(result, sort_keys=True, indent=2))
            return 0  # receipt recorded; NOT a permission signal
        print(json.dumps(pending_stops(
            args.database, email=args.email, password=password,
        ), sort_keys=True, indent=2))
        return 2
    except (StopLedgerError, KeyboardInterrupt, EOFError):
        print(json.dumps({
            "status": "HOLD",
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
