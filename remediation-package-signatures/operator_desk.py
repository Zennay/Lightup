#!/usr/bin/env python3
"""Foreground local custody desk for LightUp source-only offline software.

No browser script, background worker, shell, network, live target, grant,
consent, deploy action or release authority. REVIEW_ONLY throughout.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import secrets
import sys

from offline_signatures import Hold
from inbox import inbox
from inbox_reopen import inspect
from trust_registry import _owner_private, init, listing, register, revoke


def _read(message: str) -> str:
    try:
        value = input(message).strip()
    except EOFError as exc:
        raise Hold("local operator cancelled or disconnected") from exc
    if not value:
        raise Hold("an explicit value is required")
    return value


def _path(message: str) -> Path:
    value = Path(_read(message))
    if not value.is_absolute():
        raise Hold("choose an absolute operator-controlled local path")
    return value


def _confirm(message: str) -> bool:
    answer = _read(message + " Type YES or NO: ").upper()
    if answer not in ("YES", "NO"):
        raise Hold("explicit YES or NO required")
    return answer == "YES"


def _receive(workdir: Path, registry: Path) -> Path:
    paths: list[Path] = []
    for number in range(1, 13):
        paths.append(_path(f"Portable signed source-only ZIP #{number} (absolute): "))
        if number == 12:
            break
        if not _confirm("Add another original software package?"):
            break
    two = _confirm("Require two distinct locally trusted signers for every package?")
    destination = workdir / ("software-inbox-" + secrets.token_hex(6))
    inbox(registry, paths, destination, two)
    return destination


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--workdir", type=Path, required=True,
        help="Existing 0700 absolute PRIVATE directory owned by the current operator",
    )
    args = parser.parse_args()
    try:
        _owner_private(args.workdir)
    except (Hold, OSError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3
    registry = args.workdir / "local-trust-registry"
    last_inbox: Path | None = None
    print("LightUp — PRIVATE source-only software custody desk")
    print("INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT-HOLD.")
    print("This desk cannot authenticate a client, issue grants or deploy software.")
    while True:
        print(
            "\n1  Initialize a fresh private local trust registry"
            "\n2  Register independently trusted Ed25519 public key"
            "\n3  List local trust, including revoked keys"
            "\n4  Receive signed original software package(s) into private offline inbox"
            "\n5  Re-open inbox against CURRENT local trust and original source"
            "\n6  Permanently revoke local trust for one signer"
            "\n0  End foreground session"
        )
        try:
            choice = _read("Choose 0–6: ")
            if choice == "0":
                print("REVIEW_ONLY desk ended; existing local private files remain.")
                return 2
            if choice == "1":
                init(registry)
            elif choice == "2":
                if not _confirm("Was the next Ed25519 fingerprint confirmed OUTSIDE the received software package?"):
                    raise Hold("independent trust confirmation required")
                register(
                    registry, _path("Absolute trusted public PEM: "),
                    _read("Independently confirmed 64-character lowercase fingerprint: "),
                    _read("Visible local HUMAN label (no personal secrets): "),
                )
            elif choice == "3":
                listing(registry)
            elif choice == "4":
                last_inbox = _receive(args.workdir, registry)
            elif choice == "5":
                selected = last_inbox
                if selected is None or not _confirm(f"Re-open last inbox at {selected}?"):
                    selected = _path("Existing owner-private inbox directory (absolute): ")
                inspect(
                    registry, selected,
                    _confirm("Require two distinct trusted signers on this reopen?"),
                )
            elif choice == "6":
                fingerprint = _read("Fingerprint to permanently revoke locally: ")
                if not _confirm("Permanently revoke this specific local signer (no restore)?"):
                    raise Hold("local revocation not confirmed")
                revoke(registry, fingerprint)
            else:
                print("Unknown choice; enter 0–6.")
        except (ValueError, OSError) as exc:
            print("HOLD:", exc, file=sys.stderr)
            print("Only this foreground operation was refused; no authority was granted.")


if __name__ == "__main__":
    raise SystemExit(main())
