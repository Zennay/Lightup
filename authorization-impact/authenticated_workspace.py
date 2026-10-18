#!/usr/bin/env python3
"""Original authenticated Casebook -> complete PRIVATE offline Scope Impact workspace.

Reuses the original installed DomainStore/Casebook login, account lockout,
tenant selection and query-only snapshot exactly as provided by its owner.
This is an operator-side human handoff, NOT a new authorization path.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import json
from pathlib import Path
import sys

from prepare import Refused, SOURCE_LIMIT, publish_bytes


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Original authenticated single-tenant Casebook to PRIVATE offline human impact room (always HOLD)."
    )
    parser.add_argument("--database", required=True, help="Original existing LightUp domain SQLite")
    parser.add_argument("--email", required=True, help="Existing original operator or client account")
    parser.add_argument("--client", help="Exact existing tenant ID; mandatory for original operator role")
    parser.add_argument("--workspace", required=True, type=Path, help="New, nonexistent private directory")
    args = parser.parse_args(argv)

    # Never fetch a password from command-line, environment or a config file.
    # The original password-authenticator enforces its existing lockout policy.
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        print("HOLD: an interactive private terminal is required for original login.", file=sys.stderr)
        return 3
    try:
        from lightup.auth_casebook import (
            CasebookHold,
            authenticated_casebook,
        )

        original = authenticated_casebook(
            args.database,
            email=args.email,
            password=getpass("Original LightUp account password: "),
            client_id=args.client,
        )
        if type(original) is not dict:
            raise Refused("original Casebook schema")
        # Match the original Casebook's own native canonical JSON publisher.
        source = (
            json.dumps(original, indent=2, sort_keys=True, allow_nan=False) + "\n"
        ).encode("utf-8")
        if not 2 <= len(source) <= SOURCE_LIMIT:
            raise Refused("original source too large")
        publish_bytes(source, args.workspace, fresh_original_auth=True)
    except (CasebookHold, Refused, OSError, ValueError, TypeError, EOFError, KeyboardInterrupt):
        # No private user IDs, paths, account details, raw exception bytes,
        # targets or original source records ever go to stdout/stderr.
        print("HOLD: original authenticated private workspace could not be created.", file=sys.stderr)
        return 3

    print("REVIEW_ONLY: original authenticated single-tenant private impact workspace created.")
    print("No grant, client/operator consent, STOP clearance, scan or execution authority was issued.")
    return 2


if __name__ == "__main__":
    sys.exit(main())
