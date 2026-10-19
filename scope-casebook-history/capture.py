#!/usr/bin/env python3
"""Original-account authenticated, single-tenant Casebook capture and HUMAN history.

This companion *uses* the unchanged original authenticated Casebook producer.
It cannot issue a grant/consent/scan or attest that stored rows are current
authorization. Only safe local original source capture and human review.
"""
from __future__ import annotations

import argparse
from getpass import getpass
import json
import os
from pathlib import Path
import sqlite3
import stat
import sys

from history import (
    Hold, admit, fail, generate, original_byte_inventory, publish, read_private,
)

OUTPUT_MAX = 12


def discover(folder: Path) -> list[Path]:
    info = folder.lstat()
    fail(stat.S_ISDIR(info.st_mode) and not stat.S_ISLNK(info.st_mode)
         and info.st_mode & 0o077 == 0,
         "private packet directory not admitted")
    children = sorted(folder.iterdir(), key=lambda item: item.name)
    fail(len(children) < OUTPUT_MAX, "private packet series is full")
    names = [p.name for p in children]
    fail(names == [f"casebook-{index:02d}.json"
                   for index in range(1, len(children) + 1)],
         "private packet series contains unexpected or missing files")
    return children


def capture(*, database: str, email: str, client: str | None,
            packet_dir: Path, history_dir: Path | None) -> int:
    existing = discover(packet_dir)
    # Validate ALL original existing bytes and ownership BEFORE login and
    # before any source file is added.
    admitted = [read_private(path) for path in existing]
    if admitted:
        tenant = admitted[0][0]["client_id"]
        fail(all(p["client_id"] == tenant for p, _ in admitted),
             "existing snapshots contain multiple tenants")
    else:
        tenant = None

    if history_dir is not None:
        fail(len(existing) >= 1, "need one earlier source for complete history")
        out_parent = history_dir.parent.lstat()
        fail(stat.S_ISDIR(out_parent.st_mode) and not stat.S_ISLNK(out_parent.st_mode)
             and out_parent.st_mode & 0o077 == 0,
             "private history parent not admitted")
        fail(not history_dir.exists() and not history_dir.is_symlink(),
             "private history destination already exists")
        fail(history_dir.parent.resolve(strict=True) != packet_dir.resolve(strict=True),
             "private history must be outside original source packet directory")

    # Reuse the ORIGINAL source owner's real credential path, lockout behavior,
    # current persisted actor/role and client selection; not our own trusted
    # AccessContext, cookie, password store, or authorization reimplementation.
    try:
        from lightup.auth_casebook import _write_private_json, authenticated_casebook
    except ImportError as exc:
        raise Hold("original LightUp Casebook implementation unavailable") from exc

    password = getpass("Original LightUp account password: ")
    try:
        original = authenticated_casebook(database, email=email, password=password,
                                          client_id=client)
    except ValueError as exc:
        raise Hold("original Casebook authority source did not admit input") from exc
    admit(original)
    fail(tenant is None or original["client_id"] == tenant,
         "authenticated original tenant differs from existing source series")

    destination = packet_dir / f"casebook-{len(existing)+1:02d}.json"
    fail(not destination.exists() and not destination.is_symlink(),
         "new original packet already exists")
    _write_private_json(str(destination), original)

    # The original producer writes a 0600 source as its own durable human
    # evidence output; its file is intentionally never deleted on downstream
    # HUMAN history failure. Re-read EXACT files through our no-follow
    # admission to avoid promoting the returned in-memory object to evidence.
    if history_dir is not None:
        snapshots = [read_private(path) for path in [*existing, destination]]
        all_docs = [doc for doc, _ in snapshots]
        fail(all(doc["client_id"] == original["client_id"] for doc in all_docs),
             "source tenant drift after original capture")
        artifacts = generate(all_docs)
        artifacts["private-source-inventory.json"] = original_byte_inventory(snapshots)
        publish(history_dir, artifacts)

    # No personal or source IDs / paths, assets or decision content printed.
    print(json.dumps({
        "status": "REVIEW_ONLY",
        "original_packet_ordinal": len(existing) + 1,
        "private_history_created": history_dir is not None,
        "source_authenticated": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
    }, sort_keys=True))
    return 2


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Capture one ORIGINAL authenticated Casebook packet; optional new private HUMAN history")
    parser.add_argument("--database", required=True,
                        help="Existing original domain SQLite, never modified by this companion's source reads")
    parser.add_argument("--email", required=True,
                        help="Original account email, only passed to original Casebook authenticator")
    parser.add_argument("--client", help="Required exact tenant for an original operator account")
    parser.add_argument("--packet-dir", required=True, type=Path,
                        help="Existing OWNER PRIVATE 0700 directory for casebook-01...-12.json")
    parser.add_argument("--history-output-dir", type=Path,
                        help="NEW HUMAN history directory under a 0700 private parent, requires one old packet")
    args = parser.parse_args()
    try:
        return capture(
            database=args.database, email=args.email, client=args.client,
            packet_dir=args.packet_dir, history_dir=args.history_output_dir,
        )
    except (Hold, OSError, sqlite3.Error,
            ValueError, TypeError, EOFError, KeyboardInterrupt):
        print("HOLD: original authenticated Casebook capture or local private history refused. "
              "Existing captures are not erased. No consent or authority.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
