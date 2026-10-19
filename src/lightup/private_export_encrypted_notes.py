"""Separate encrypted HUMAN coordination draft, bound to an original LightUp source.

A browser-created HUMAN workplan JSON is never trusted as evidence, consent
or an authenticated owner. This module encrypts validated original bytes to
another private AES-GCM envelope, and resumes it without cleartext disk writes.
"""
from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import sys

from .private_export_encrypted import _passphrase, _read_encrypted, _seal, _open_sealed
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_workdesk import _load_resume_bytes, _render, MAX_PLAN

MAGIC_PLAN = b"LIGHTUP-PRIVATE-HUMAN-DRAFT-V1\x00"
PLAN_EXTENSION = ".lun"
MAX_SEALED_PLAN = len(MAGIC_PLAN) + 16 + 12 + MAX_PLAN + 16


def _read_plan(path: str, secret: str, manifest: dict, rows: list[dict[str, str]]) -> tuple[dict, bytes]:
    file = Path(path).expanduser()
    if not file.is_file() or file.stat().st_size > MAX_SEALED_PLAN:
        raise ValueError("missing or oversized encrypted HUMAN plan")
    raw = _open_sealed(
        file.read_bytes(), secret, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN
    )
    return _load_resume_bytes(raw, manifest, rows), raw


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Original-source HUMAN draft encryption; never authorization or fixes"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    seal = sub.add_parser("seal", help="validate original source + plaintext HUMAN draft then encrypt .lun")
    seal.add_argument("encrypted_source")
    seal.add_argument("human_json")
    seal.add_argument("--output", required=True)
    open_cmd = sub.add_parser("workdesk", help="resume HUMAN draft entirely from encrypted source + plan")
    open_cmd.add_argument("encrypted_source")
    open_cmd.add_argument("encrypted_plan")
    open_cmd.add_argument("--output", required=True)
    inspect = sub.add_parser("inspect", help="verify encrypted source and HUMAN draft binding without printing notes")
    inspect.add_argument("encrypted_source")
    inspect.add_argument("encrypted_plan")
    rotate = sub.add_parser("rotate", help="change HUMAN draft passphrase, never writing cleartext JSON")
    rotate.add_argument("encrypted_source")
    rotate.add_argument("encrypted_plan")
    rotate.add_argument("--output", required=True)
    for command in (seal, open_cmd, inspect, rotate):
        command.add_argument("--ack-private-handling", action="store_true")
    for command in (open_cmd,):
        command.add_argument("--ack-plaintext-html", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_handling:
            raise ValueError("private recipient/storage confirmation absent")
        target = None
        if args.action in ("seal", "rotate"):
            target = _output_path(args.output, PLAN_EXTENSION)
        elif args.action == "workdesk":
            if not args.ack_plaintext_html:
                raise ValueError("original unencrypted HTML requires explicit human acknowledgment")
            target = _output_path(args.output, ".html")
        source_secret = _passphrase("Original encrypted findings source passphrase")
        manifest, rows, _original_zip = _read_encrypted(args.encrypted_source, source_secret)
        del source_secret

        if args.action == "seal":
            origin = Path(args.human_json).expanduser()
            if not origin.is_file() or origin.stat().st_size > MAX_PLAN:
                raise ValueError("HUMAN workplan file missing or oversized")
            plain_plan = origin.read_bytes()
            _load_resume_bytes(plain_plan, manifest, rows)
            new_secret = _passphrase("New HUMAN workplan passphrase", confirm=True)
            ciphertext = _seal(plain_plan, new_secret, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN)
            _atomic_private_publish(target, ciphertext)
            print("Encrypted private original-source HUMAN workplan. Original JSON remains; protect/remove manually.")
            print("Unsigned ciphertext SHA-256:", hashlib.sha256(ciphertext).hexdigest())
            return 0

        human_secret = _passphrase("Encrypted HUMAN workplan passphrase")
        annotations, original_plan_bytes = _read_plan(
            args.encrypted_plan, human_secret, manifest, rows
        )
        del human_secret
        if args.action == "inspect":
            print("Encrypted HUMAN workplan matches exact claimed original source.")
            print("Source records in human draft:", len(annotations))
            print("No HUMAN notes, aliases, original IDs or field contents shown.")
            print("Neither original client, consent nor fixes verified.")
        elif args.action == "workdesk":
            html = _render(manifest, rows, annotations)
            _atomic_private_publish(target, html)
            print("Created UNENCRYPTED private source-bound HUMAN HTML; recipient review required.")
        else:
            next_secret = _passphrase("New HUMAN workplan passphrase", confirm=True)
            resealed = _seal(
                original_plan_bytes, next_secret, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN
            )
            _atomic_private_publish(target, resealed)
            print("Re-encrypted same source-bound HUMAN draft without writing plaintext JSON.")
            print("New unsigned ciphertext SHA-256:", hashlib.sha256(resealed).hexdigest())
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN workplan HOLD: invalid ciphertext, original source, passphrase or output.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
