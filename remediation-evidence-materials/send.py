#!/usr/bin/env python3
"""One-command PRIVATE original-index evidence send, no selector file on disk.

HUMAN explicitly chooses existing original indexed local material. Actual file
bytes remain local, then go straight into a NEW source-bound AES-GCM vault.
No scan, target, grant, client consent, verified retest or native Apply.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import transfer


def choose(indexed: dict, vault) -> list[dict]:
    rows = sorted(indexed.values(), key=lambda x: (
        x["finding_id"].encode("utf-8"), x["file_name"].encode("utf-8"),
        x["sha256"]))
    if not rows or len(rows) > 120:
        raise ValueError("No exact original HUMAN indexed material to select.")
    print("PRIVATE SOURCE-INDEXED MATERIAL · HUMAN ONLY / UNVERIFIED")
    for ordinal, record in enumerate(rows, 1):
        print(f'{ordinal:>3}. {record["finding_id"]!a} · {record["file_name"]!a} · '
              f'{record["byte_length"]} bytes · sha256:{record["sha256"][:14]}…')
    raw = input("Select 1–12 indices separated by commas (empty HOLD): ").strip()
    parts = [part.strip() for part in raw.split(",")]
    if (not raw or not 1 <= len(parts) <= transfer.MAX_FILES
            or any(not value.isascii() or not value.isdecimal() for value in parts)):
        raise ValueError("Explicit bounded original index selection required.")
    numbers = [int(text) for text in parts]
    if len(set(numbers)) != len(numbers) or any(v < 1 or v > len(rows) for v in numbers):
        raise ValueError("Unknown or repeated original HUMAN index.")
    material = []
    total = 0
    for index in numbers:
        record = rows[index - 1]
        path = input(f'Enter owner-private absolute local path for original file #{index}: ').strip()
        if not path.startswith("/") or len(path) > 1024 or "\x00" in path:
            raise ValueError("Exact literal absolute PRIVATE material path required.")
        candidate = Path(path)
        if candidate.is_dir():
            raise ValueError("Only original ordinary files, not directories, can be transferred.")
        data = vault._private_input(candidate, transfer.MAX_MATERIAL)
        if (not data or len(data) != record["byte_length"]
                or transfer.digest(data) != record["sha256"]):
            raise ValueError("Local original file content does not match source-indexed fingerprint.")
        total += len(data)
        if total > transfer.MAX_TOTAL:
            raise ValueError("Current selections exceed strict original material transfer size.")
        material.append({"finding_id":record["finding_id"],
                         "sha256":record["sha256"],"path":path})
    print("Current source-indexed candidate files:",len(material),"· LOCAL bytes:",total)
    print("No private selection file saved; pack stage independently reopens every file.")
    return material


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("db","email","client-id","engagement-id"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--human",required=True,type=Path,
                   help="Existing matching original encrypted HUMAN workspace .ltv")
    p.add_argument("--output",required=True,type=Path,
                   help="NEW 0600 encrypted evidence material transfer .ltv")
    p.add_argument("--ack-private-material",action="store_true")
    args=p.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("PRIVATE material HUMAN approval and interactive terminal required.")
        vault=transfer.ORIGINAL._vault()
        original, packet, indexed, original_key_hash = transfer.current_human(
            args,vault,keep_passphrase_fingerprint=True)
        material=choose(indexed,vault)
        # Reuses the very same strict canonical selection admission, independently
        # hashes each local file a second time before original AES-GCM sealing,
        # and refuses overwrite of any original PRIVATE vault.
        transfer.pack_selected(args,vault,original,packet,indexed,original_key_hash,material)
        print("Single-step send completed without a local selector.json intermediate.")
        return 0
    except Exception:
        print("HUMAN HOLD: No complete source-indexed private material transfer created. "
              "Verify original current account, source, matching local evidence and path policy.",
              file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
