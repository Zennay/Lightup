"""Private encrypted custody for selected original-source HUMAN carry decisions.

A local operator can seal a reviewed source-bound decision sheet as a distinct
AES-256-GCM .lud artifact, inspect/rotate it privately and apply it directly
to a NEW original-compatible encrypted .lun plan. The original .lue sources,
.lun parent plan and every other owner workflow stay unchanged.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from .private_export_encrypted import _open_sealed, _passphrase, _seal
from .private_export_encrypted_notes import MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _no_duplicate_keys, _output_path
from .private_export_human_revision import _review_revision
from .private_export_human_revision_source import (
    _read_with_binding, _source_binding, _require_same_originals,
)
from .private_export_human_revision_choices import (
    MAX_CHOICES, _apply_choices, _make_choices, _read_private_choices,
)
from .private_export_workdesk import MAX_PLAN, _load_resume_bytes, _render

MAGIC_DECISIONS = b"LIGHTUP-PRIVATE-HUMAN-CHOICES-V2\x00"
DECISION_EXTENSION = ".lud"
BINDING_SIZE = 3 * hashlib.sha256().digest_size
MAX_BOUND_DECISIONS = MAX_CHOICES + BINDING_SIZE
MAX_DECISION_ENVELOPE = len(MAGIC_DECISIONS) + 16 + 12 + MAX_BOUND_DECISIONS + 16


def _read_ciphertext(path: str) -> bytes:
    """Reject symlink/public/partial ciphertext using one opened descriptor."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("private no-follow file admission unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(Path(path).expanduser(), flags)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_size > MAX_DECISION_ENVELOPE
            or info.st_size < len(MAGIC_DECISIONS) + 16 + 12 + 16
            or info.st_mode & 0o077
        ):
            raise ValueError("invalid or nonprivate encrypted HUMAN decision artifact")
        with os.fdopen(fd, "rb", closefd=False) as f:
            ciphertext = f.read(MAX_DECISION_ENVELOPE + 1)
    finally:
        os.close(fd)
    if len(ciphertext) > MAX_DECISION_ENVELOPE:
        raise ValueError("encrypted HUMAN decision artifact exceeds size limit")
    return ciphertext


def _admit_bytes(contents: bytes) -> dict:
    if type(contents) is not bytes or len(contents) > MAX_CHOICES:
        raise ValueError("unbounded original HUMAN decision document")
    try:
        document = json.loads(
            contents.decode("utf-8", "strict"),
            object_pairs_hook=_no_duplicate_keys,
        )
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("unrecognized private decision document") from exc
    if type(document) is not dict:
        raise ValueError("private decision document must be an object")
    return document


def _read_decisions(path: str, secret: str, binding: bytes) -> tuple[dict, bytes]:
    ciphertext = _read_ciphertext(path)
    original = _open_sealed(
        ciphertext, secret, magic=MAGIC_DECISIONS,
        max_plaintext=MAX_BOUND_DECISIONS,
    )
    if len(original) < BINDING_SIZE or original[:BINDING_SIZE] != binding:
        raise ValueError("private decisions belong to different original encrypted artifacts")
    return _admit_bytes(original[BINDING_SIZE:]), original


def _current_source(earlier: str, plan: str, later: str) -> tuple[dict, dict, list, dict, bytes]:
    old_meta, old_rows, old_annotations, new_meta, new_rows, before_binding = (
        _read_with_binding(earlier, plan, later)
    )
    expected = _make_choices(
        old_meta, old_rows, old_annotations, new_meta, new_rows
    )
    output, _ = _review_revision(
        old_meta, old_rows, old_annotations, new_meta, new_rows,
        carry_stage=True,
    )
    return expected, output, new_rows, new_meta, before_binding


def _require_current_original_ciphertext(args: argparse.Namespace, binding: bytes) -> None:
    """Refuse private publication if an original encrypted input has changed."""
    _require_same_originals(
        args.earlier_source, args.earlier_plan, args.later_source, binding
    )


def _reconcile(document: dict, expected: dict, output: dict,
               new_meta: dict, new_rows: list[dict[str, str]]) -> tuple[bytes, dict]:
    # Exact original source + all choices are checked together; a late mismatch
    # must not create a partial encrypted plan, even for previously valid rows.
    return _apply_choices(document, expected, output, new_meta, new_rows)


def _canonical_bytes(document: dict) -> bytes:
    encoded = json.dumps(
        document, ensure_ascii=False, separators=(",", ":"),
        allow_nan=False,
    ).encode("utf-8", "strict")
    if len(encoded) > MAX_CHOICES:
        raise ValueError("encrypted decision plaintext too large")
    return encoded


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LightUp AES-256-GCM source-locked private HUMAN decision custody; DRAFT/HOLD"
    )
    actions = parser.add_subparsers(dest="action", required=True)
    descriptions = {
        "seal": "encrypt a manually reviewed 0600 JSON choice sheet into NEW .lud",
        "inspect": "inspect bound ciphertext with anonymous HUMAN counts only",
        "apply": "create NEW exact-source encrypted original HUMAN .lun from .lud",
        "workdesk": "preview approved HUMAN plan as private UNENCRYPTED offline HTML",
        "rotate": "re-encrypt the unchanged selected decisions into NEW .lud",
        "open": "explicitly decrypt approved .lud into NEW UNENCRYPTED 0600 JSON",
    }
    for action, description in descriptions.items():
        cmd = actions.add_parser(action, help=description)
        cmd.add_argument("earlier_source")
        cmd.add_argument("earlier_plan")
        cmd.add_argument("later_source")
        cmd.add_argument("--ack-private-handling", action="store_true")
        cmd.add_argument("--ack-same-real-client", action="store_true")
        if action != "inspect":
            cmd.add_argument("--output", required=True)
        if action == "seal":
            cmd.add_argument("--choices", required=True,
                             help="original selected owner-private plaintext .json")
        else:
            cmd.add_argument("--encrypted-choices", required=True,
                             help="previously encrypted original decisions .lud")
        if action in ("seal", "apply"):
            cmd.add_argument("--ack-human-decisions", action="store_true")
        if action == "open":
            cmd.add_argument("--ack-unencrypted-original-ids", action="store_true")
        if action == "workdesk":
            cmd.add_argument("--ack-plaintext-html", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not args.ack_private_handling or not args.ack_same_real_client:
            raise ValueError("separate source client and private handling approval required")
        if args.action in ("seal", "apply") and not args.ack_human_decisions:
            raise ValueError("reviewer consent to HUMAN-only choices is missing")
        if args.action == "open" and not args.ack_unencrypted_original_ids:
            raise ValueError("explicit private plaintext output acknowledgment required")
        if args.action == "workdesk" and not args.ack_plaintext_html:
            raise ValueError("unencrypted full original HUMAN workdesk needs recipient acknowledgment")
        destination = None
        if args.action != "inspect":
            ext = (".lun" if args.action == "apply" else
                   ".json" if args.action == "open" else
                   ".html" if args.action == "workdesk" else DECISION_EXTENSION)
            destination = _output_path(args.output, ext)
        expected, template, new_rows, new_meta, source_binding = _current_source(
            args.earlier_source, args.earlier_plan, args.later_source
        )

        if args.action == "seal":
            document = _read_private_choices(args.choices)
            _reconcile(document, expected, template, new_meta, new_rows)
            plaintext = source_binding + _canonical_bytes(document)
            new_secret = _passphrase("New encrypted HUMAN decisions passphrase", confirm=True)
            package = _seal(
                plaintext, new_secret,
                magic=MAGIC_DECISIONS, max_plaintext=MAX_BOUND_DECISIONS,
            )
            del new_secret
            _require_current_original_ciphertext(args, source_binding)
            _atomic_private_publish(destination, package)
            print("Created NEW 0600 encrypted, original-source-bound HUMAN choices .lud.")
            print("Original plaintext choices remain; secure or retire them manually.")
            print("Unsigned local ciphertext SHA256:", hashlib.sha256(package).hexdigest())
            return 0

        secret = _passphrase("Encrypted original HUMAN decisions passphrase")
        document, original = _read_decisions(args.encrypted_choices, secret, source_binding)
        del secret
        prepared_plan, summary = _reconcile(
            document, expected, template, new_meta, new_rows
        )

        if args.action == "inspect":
            print("Encrypted original source-bound HUMAN decision artifact re-admitted.")
            for name, count in summary.items():
                print(name + ":", count)
            print("No original finding IDs, aliases, notes or source identities displayed.")
        elif args.action == "apply":
            fresh = _passphrase("New encrypted HUMAN plan passphrase", confirm=True)
            encrypted_plan = _seal(
                prepared_plan, fresh, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN,
            )
            del fresh
            _require_current_original_ciphertext(args, source_binding)
            _atomic_private_publish(destination, encrypted_plan)
            print("Created NEW source-bound original-format encrypted HUMAN workplan .lun.")
            for name, count in summary.items():
                print(name + ":", count)
            print("Unsigned plan ciphertext SHA256:", hashlib.sha256(encrypted_plan).hexdigest())
        elif args.action == "workdesk":
            # Reuse the unchanged original workdesk UI/HTML renderer. The
            # resulting plaintext may expose all original finding IDs, title,
            # remedies, HUMAN aliases and notes. Never publish implicitly.
            annotations = _load_resume_bytes(prepared_plan, new_meta, new_rows)
            html = _render(new_meta, new_rows, annotations)
            _require_current_original_ciphertext(args, source_binding)
            _atomic_private_publish(destination, html)
            print("Created NEW UNENCRYPTED 0600 PRIVATE original-source HUMAN workdesk.")
            print("Full original source details and HUMAN notes are PRIVATE; verify actual recipients.")
            print("The encrypted decisions, earlier plan and finding sources were untouched.")
        elif args.action == "rotate":
            fresh = _passphrase("Rotated HUMAN decision passphrase", confirm=True)
            refreshed = _seal(
                original, fresh, magic=MAGIC_DECISIONS, max_plaintext=MAX_BOUND_DECISIONS
            )
            del fresh
            _require_current_original_ciphertext(args, source_binding)
            _atomic_private_publish(destination, refreshed)
            print("Created NEW private encrypted HUMAN choice artifact with unchanged choices.")
            print("Unsigned ciphertext SHA256:", hashlib.sha256(refreshed).hexdigest())
        else:
            # Private original IDs/titles and self-declared source identities will
            # become plaintext ONLY after a distinct explicit recipient approval.
            _require_current_original_ciphertext(args, source_binding)
            _atomic_private_publish(destination, original[BINDING_SIZE:])
            print("Created NEW UNENCRYPTED PRIVATE source-bound HUMAN choices JSON.")
            print("Manually verify storage and recipient; no source or plan was changed.")

        print(
            "DRAFT/HOLD: human-only coordination, NOT verified evidence, fixes, "
            "true client identity, consent, grants or permission to assess."
        )
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        # Original IDs, client labels, private notes and secrets are deliberately
        # excluded from error strings and automatic logging.
        print(
            "PRIVATE HUMAN decision custody HOLD: source, ciphertext, "
            "recipient acknowledgment or destination not admissible.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
