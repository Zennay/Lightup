#!/usr/bin/env python3
"""Interactive original-authenticated PRIVATE evidence material selector.

Creates a bounded 0600 source-index selection for the transfer pack command,
without hand-typing original finding IDs or checksums. No scanner or network.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import transfer

MAX_MENU = 120


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("db", "email", "client-id", "engagement-id"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--human", required=True, type=Path,
                        help="Current original encrypted HUMAN workspace .ltv")
    parser.add_argument("--output", required=True, type=Path,
                        help="NEW owner-private 0600 selection.json")
    parser.add_argument("--ack-private-selection", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_selection or not sys.stdin.isatty():
            raise ValueError("Explicit HUMAN local selection and private terminal required.")
        if args.output.suffix.lower() != ".json" or args.output.expanduser().absolute() == args.human.expanduser().absolute():
            raise ValueError("A new distinct PRIVATE .json selection is required.")
        vault = transfer.ORIGINAL._vault()
        _, _, indexed = transfer.current_human(args, vault)
        rows = sorted(indexed.values(), key=lambda x: (
            x["finding_id"].encode("utf-8"), x["file_name"].encode("utf-8"), x["sha256"]))
        if not rows or len(rows) > MAX_MENU:
            raise ValueError("No original indexed HUMAN files available for human-only transport.")
        print("PRIVATE ORIGINAL SOURCE/HUMAN FILE INDEX (not validated security evidence)")
        for i, record in enumerate(rows, 1):
            # Escaped labels cannot inject terminal control sequences.
            print(f'{i:>3}. {record["finding_id"]!a} · {record["file_name"]!a} · '
                  f'{record["byte_length"]} bytes · sha256:{record["sha256"][:14]}…')
        pick = input("Choose 1-12 indices separated by commas (empty cancels): ").strip()
        if not pick:
            raise ValueError("No files selected.")
        parts = [item.strip() for item in pick.split(",")]
        if not 1 <= len(parts) <= transfer.MAX_FILES or any(
                not item.isascii() or not item.isdecimal() for item in parts):
            raise ValueError("A bounded numeric selection is required.")
        positions = [int(n) for n in parts]
        if len(set(positions)) != len(positions) or any(
                n < 1 or n > len(rows) for n in positions):
            raise ValueError("Repeated or out-of-range source index.")
        selected = []
        total = 0
        for ordinal in positions:
            record = rows[ordinal-1]
            path = input(f'Original indexed material #{ordinal}: absolute owner-private file path: ').strip()
            if not path.startswith("/") or "\x00" in path or len(path) > 1024:
                raise ValueError("Literal bounded absolute path required.")
            raw = vault._private_input(Path(path), transfer.MAX_MATERIAL)
            if (not raw or len(raw) != record["byte_length"]
                    or transfer.digest(raw) != record["sha256"]):
                raise ValueError("Current local bytes differ from selected original HUMAN fingerprint.")
            total += len(raw)
            if total > transfer.MAX_TOTAL:
                raise ValueError("Selection exceeds transport bound.")
            selected.append({"finding_id":record["finding_id"],
                             "sha256":record["sha256"], "path":path})
        candidate = transfer.canonical({
            "kind":"lightup.private_local_material_selection",
            "schema_version":1, "items":selected})
        if len(candidate) > transfer.MAX_SELECTION:
            raise ValueError("PRIVATE selection exceeds original bounded manifest.")
        output = args.output.expanduser().absolute()
        vault._exclusive_output(output, candidate)
        print("Created NEW owner-only 0600 PRIVATE source-index selection.")
        print("Matched original HUMAN indexed files:", len(selected), "· bytes:", total)
        print("Next: run transfer.py pack; it will reauthenticate and rehash before sealing.")
        print("Selection files and SHA matching do NOT establish collection provenance or retest.")
        return 0
    except Exception:
        print("HUMAN HOLD: No complete PRIVATE selection produced; check original current source, "
              "indexed file membership, permissions and output destination.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
