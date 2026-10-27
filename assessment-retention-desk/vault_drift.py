#!/usr/bin/env python3
"""PRIVATE encrypted source-revision HUMAN drift report, offline and non-authorizing.

Requires both original source sets and the original browser AES-GCM vaults.
All comparisons run in memory without plaintext file exports.
"""
from __future__ import annotations

import argparse
import getpass

from drift import build
from history import Hold, publish_private
from vault_history import decrypt_vault, original_sources


def password_for(position: str) -> str:
    try:
        password = getpass.getpass(f"PRIVATE {position} encrypted plan password (not echoed): ")
    except (EOFError, KeyboardInterrupt) as exc:
        raise Hold("interactive PRIVATE password entry unavailable or cancelled") from exc
    try:
        size = len(password.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise Hold("invalid password UTF-8") from exc
    if (not 12 <= len(password) <= 128 or size > 256
            or any(ord(ch) < 32 or 127 <= ord(ch) <= 159 for ch in password)):
        raise Hold("invalid original PRIVATE password shape")
    return password


def main() -> None:
    p = argparse.ArgumentParser(
        description="Compare encrypted PRIVATE HUMAN plans against their own original source bytes. "
                    "Read-only; no automatic HUMAN stage carry, grant, scan, consent or delete."
    )
    p.add_argument("--output", required=True, help="New private scriptless 0600 HTML report in existing 0700 folder")
    p.add_argument("--old-source-file", action="append", required=True, dest="old_sources",
                   help="Actual PRIVATE source in older plan; repeat for complete original set")
    p.add_argument("--new-source-file", action="append", required=True, dest="new_sources",
                   help="Actual PRIVATE source in newer plan; repeat for complete original set")
    p.add_argument("old_vault", help="PRIVATE encrypted plan file of operator-declared earlier source set")
    p.add_argument("new_vault", help="PRIVATE encrypted plan file of operator-declared current source set")
    args = p.parse_args()
    try:
        expected_old = original_sources(args.old_sources)
        expected_new = original_sources(args.new_sources)
        old = decrypt_vault(args.old_vault, password_for("older"))
        if {(sha, row["bytes"]) for sha, row in old.items()} != expected_old:
            raise Hold("older encrypted HUMAN plan disagrees with supplied older original bytes")
        new = decrypt_vault(args.new_vault, password_for("newer"))
        if {(sha, row["bytes"]) for sha, row in new.items()} != expected_new:
            raise Hold("newer encrypted HUMAN plan disagrees with supplied newer original bytes")
        result = build(old, new)
        publish_private(args.output, result)
    except Hold as exc:
        p.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE encrypted original-byte-confirmed HUMAN source-revision report created, no plaintext export.")


if __name__ == "__main__":
    main()
