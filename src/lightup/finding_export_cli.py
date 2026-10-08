"""Run with python -m lightup.finding_export_cli."""
from __future__ import annotations

import argparse
from getpass import GetPassWarning, getpass
from pathlib import Path
import sqlite3
import sys
import warnings

from .domain import AccountLockedError, DomainStore
from .finding_export_service import render_client_findings_csv


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Export one client's finding summaries after interactive sign-in")
    parser.add_argument("--db", required=True, help="existing LightUp domain database")
    parser.add_argument("--email", required=True)
    parser.add_argument("--client-id", required=True)
    parser.add_argument("--engagement-id")
    args = parser.parse_args(argv)

    if not Path(args.db).is_file():
        print("Export requires an existing domain database.", file=sys.stderr)
        return 2
    if not sys.stdin.isatty():
        print("Interactive terminal required for secure password entry.", file=sys.stderr)
        return 2
    try:
        with warnings.catch_warnings():
            warnings.simplefilter("error", GetPassWarning)
            password = getpass("LightUp password: ")
        store = DomainStore(args.db)
        user = store.authenticate(args.email, password)
        del password
        if user is None:
            print("Sign-in failed.", file=sys.stderr)
            return 2
        # Resolve current persisted role/tenant after password verification.
        ctx = store.context_for_user(user.user_id)
        output = render_client_findings_csv(
            store, ctx, args.client_id, engagement_id=args.engagement_id)
    except GetPassWarning:
        print("Secure password entry unavailable.", file=sys.stderr)
        return 2
    except AccountLockedError:
        print("Sign-in temporarily locked.", file=sys.stderr)
        return 2
    except (PermissionError, ValueError, KeyError, sqlite3.DatabaseError):
        print("Export denied or stored data is invalid.", file=sys.stderr)
        return 2
    except (EOFError, KeyboardInterrupt):
        print("Export cancelled.", file=sys.stderr)
        return 2

    # Nothing reaches stdout until authentication, authorization and rendering pass.
    sys.stdout.write(output)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
