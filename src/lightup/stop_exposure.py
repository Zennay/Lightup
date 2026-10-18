"""Authenticated, privacy-minimal stored grant exposure after emergency STOP.

This is an original persisted-source inventory only, not a live grant validity
check, client consent check, revocation mechanism or an execution decision.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from getpass import getpass
import json
import sqlite3

from .revocation_stop import (
    StopLedgerError, _literal, _open_existing_db, _engagement_client,
    _require_current_actor, _stop_schema_current, authenticate_domain_user,
)

_MAX_GRANTS = 256


def _read_exposure(db_path: str, *, actor_id: str, engagement_id: str) -> dict:
    actor_id = _literal(actor_id, "authenticated actor")
    engagement_id = _literal(engagement_id, "engagement")
    con = _open_existing_db(db_path)
    try:
        con.execute("PRAGMA query_only=ON")
        con.execute("BEGIN")
        client_id = _engagement_client(con, engagement_id)
        _require_current_actor(con, actor_id, client_id)
        if not _stop_schema_current(con):
            raise StopLedgerError("STOP ledger unavailable: HOLD")
        stopped = con.execute(
            "SELECT 1 FROM authorization_stop_events "
            "WHERE engagement_id=? AND client_id=? LIMIT 1",
            (engagement_id, client_id),
        ).fetchone() is not None
        rows = con.execute(
            "SELECT grant_id,client_id,engagement_id,approved_request_id,"
            "valid_from,valid_until FROM authorization_grants "
            "WHERE engagement_id=? LIMIT ?",
            (engagement_id, _MAX_GRANTS + 1),
        ).fetchall()
        if len(rows) > _MAX_GRANTS:
            raise StopLedgerError("stored grant inventory too large: HOLD")
        linked = legacy = window_declared_current = malformed = 0
        now = datetime.now(timezone.utc)
        for row in rows:
            if (type(row["grant_id"]) is not str or not row["grant_id"]
                    or type(row["client_id"]) is not str
                    or row["client_id"] != client_id
                    or row["engagement_id"] != engagement_id):
                raise StopLedgerError("stored grant tenant lineage inconsistent")
            if row["approved_request_id"] is None:
                legacy += 1
            elif (type(row["approved_request_id"]) is str
                  and 1 <= len(row["approved_request_id"]) <= 180):
                linked += 1
            else:
                raise StopLedgerError("stored grant request identity inconsistent")
            try:
                start = datetime.fromisoformat(row["valid_from"])
                end = datetime.fromisoformat(row["valid_until"])
                if (start.tzinfo is None or end.tzinfo is None
                        or start.utcoffset() is None or end.utcoffset() is None
                        or start > end):
                    malformed += 1
                elif start <= now <= end:
                    window_declared_current += 1
            except (ValueError, TypeError, OverflowError):
                malformed += 1
        return {
            "schema": "lightup.stop_grant_exposure.v1",
            "status": "REVIEW_ONLY",
            "stop_active": stopped,
            "persisted_grant_count": len(rows),
            "request_linked_grant_count": linked,
            "legacy_unbound_grant_count": legacy,
            "time_window_current_by_untrusted_columns": window_declared_current,
            "invalid_time_window_row_count": malformed,
            "human_attention": (
                "HOLD_MALFORMED_GRANT_SOURCE" if malformed
                else "STOP_WITH_STORED_GRANTS" if stopped and rows
                else "STOP_WITHOUT_STORED_GRANTS" if stopped
                else "SOURCE_GRANTS_REQUIRE_INDEPENDENT_REVIEW"
            ),
            "grant_validity_verified": False,
            "source_authenticated": False,
            "consent_verified": False,
            "authorization_granted": False,
            "execution_allowed": False,
            "release_approved": False,
        }
    except (StopLedgerError, sqlite3.Error, ValueError, TypeError):
        raise StopLedgerError("stored grant exposure unavailable: HOLD") from None
    finally:
        con.close()


def grant_exposure(db_path: str, *, engagement_id: str,
                   email: str, password: str) -> dict:
    """Authenticate via existing lockout then recheck persisted tenant role."""
    actor_id = authenticate_domain_user(db_path, email, password)
    return _read_exposure(
        db_path, actor_id=actor_id, engagement_id=engagement_id,
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m lightup.stop_exposure",
        description="Source-grant inventory with STOP flags, never authorization.",
    )
    parser.add_argument("--database", required=True, help="existing original LightUp SQLite")
    parser.add_argument("--engagement", required=True, help="exact persisted engagement")
    parser.add_argument("--email", required=True, help="existing authenticated account")
    args = parser.parse_args(argv)
    try:
        password = getpass("Original LightUp account password: ")
        output = grant_exposure(
            args.database, engagement_id=args.engagement,
            email=args.email, password=password,
        )
        print(json.dumps(output, sort_keys=True, indent=2))
        return 2  # REVIEW_ONLY intentionally never returns permission/exit 0
    except (StopLedgerError, KeyboardInterrupt, EOFError):
        print(json.dumps({
            "status": "HOLD", "authorization_granted": False,
            "execution_allowed": False, "release_approved": False,
        }, sort_keys=True))
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
