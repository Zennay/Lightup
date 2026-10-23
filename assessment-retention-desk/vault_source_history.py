#!/usr/bin/env python3
"""PRIVATE encrypted HUMAN lineage across changing original source sets.

Decrypts each original .lurt only in process memory, checks it against that
snapshot's separately selected original bytes, and publishes a scriptless
source-minimal report. It never writes plaintext plans or carries decisions.
"""
from __future__ import annotations

import argparse
import getpass
import sys

from history import Hold, MAX_FILES, publish_private
from source_history import compose_history, render_bundle, render_html
from vault_history import MAX_ENVELOPE_BYTES, decrypt_vault_bytes, original_sources, read_bounded_regular


def password_for(position: int) -> str:
    try:
        password = getpass.getpass(
            f"PRIVATE encrypted plan {position} password (not echoed): "
        )
    except (EOFError, KeyboardInterrupt) as exc:
        raise Hold("interactive private password entry unavailable or cancelled") from exc
    try:
        encoded = password.encode("utf-8", "strict")
    except UnicodeError as exc:
        raise Hold("invalid password encoding") from exc
    if (not 12 <= len(password) <= 128 or len(encoded) > 256
            or any(ord(char) < 32 or 127 <= ord(char) <= 159 for char in password)):
        raise Hold("password does not meet the original private vault shape")
    return password


def source_sets_for(assignments: list[str], snapshot_count: int) -> list[list[str]]:
    source_sets: list[list[str]] = [[] for _ in range(snapshot_count)]
    for assignment in assignments:
        index_text, separator, path = assignment.partition("=")
        if not separator or not index_text.isascii() or not index_text.isdecimal() or not path:
            raise Hold("each --source-file must be SNAPSHOT_NUMBER=PATH")
        index = int(index_text)
        if not 1 <= index <= snapshot_count:
            raise Hold("source-file snapshot number is outside the selected vault range")
        source_sets[index - 1].append(path)
    if any(not paths for paths in source_sets):
        raise Hold("every encrypted plan needs its own complete original source-file set")
    return source_sets


def main() -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Compare 2–12 encrypted PRIVATE HUMAN plan snapshots with changing source membership. "
            "Original bytes are re-hashed per snapshot; no plaintext plan is written."
        )
    )
    outputs = parser.add_mutually_exclusive_group(required=True)
    outputs.add_argument("--output",
                         help="New scriptless HTML report in an existing owner-owned 0700 directory")
    outputs.add_argument("--bundle-output",
                         help="New private ZIP containing scriptless HTML, CSV, JSON and caveats")
    parser.add_argument(
        "--source-file", action="append", required=True, dest="source_files",
        metavar="SNAPSHOT=PATH",
        help="Original source file for one snapshot, e.g. 1=/private/older.json; repeat for every source",
    )
    parser.add_argument("vaults", nargs="+",
                        help="2–12 original encrypted .lurt vaults in manually chosen order")
    args = parser.parse_args()
    if not 2 <= len(args.vaults) <= MAX_FILES:
        parser.error("two to twelve encrypted original HUMAN plan snapshots required")
    try:
        source_sets = source_sets_for(args.source_files, len(args.vaults))
        plans = []
        expected_sets = []
        vault_bytes = []
        for index, (vault_path, source_paths) in enumerate(zip(args.vaults, source_sets), 1):
            expected = original_sources(source_paths, owner_private=True)
            raw_vault = read_bounded_regular(
                vault_path, MAX_ENVELOPE_BYTES, owner_private=True
            )
            password = password_for(index)
            try:
                plan = decrypt_vault_bytes(raw_vault, password)
            finally:
                password = ""
            observed = {(digest, row["bytes"]) for digest, row in plan.items()}
            if observed != expected:
                raise Hold("encrypted HUMAN plan does not match its own selected original source bytes")
            plans.append(plan)
            expected_sets.append(expected)
            vault_bytes.append(raw_vault)
        history = compose_history(plans)
        if args.bundle_output:
            report = render_bundle(history, original_bytes_rehashed=True)
            output_path = args.bundle_output
        else:
            report = render_html(history, original_bytes_rehashed=True)
            output_path = args.output
        # Re-admit every original input immediately before publishing. A changed
        # source set or vault refuses the complete report; no partial dossier.
        for source_paths, expected in zip(source_sets, expected_sets):
            if original_sources(source_paths, owner_private=True) != expected:
                raise Hold("original source bytes changed before lineage publication")
        for vault_path, expected_raw in zip(args.vaults, vault_bytes):
            if read_bounded_regular(
                vault_path, MAX_ENVELOPE_BYTES, owner_private=True
            ) != expected_raw:
                raise Hold("encrypted vault bytes changed before lineage publication")
        publish_private(output_path, report)
    except (Hold, OSError, ValueError, TypeError, MemoryError, RecursionError, UnicodeError):
        parser.exit(
            2,
            "HOLD: encrypted PRIVATE source-set lineage not admitted; no report published.\n",
        )
    print(
        "REVIEW_ONLY: encrypted PRIVATE HUMAN source-set lineage created; "
        "no plaintext export, decision carry or release."
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
