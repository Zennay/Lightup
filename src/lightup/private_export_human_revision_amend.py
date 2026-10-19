"""Amend exact-original-source HUMAN choices entirely within a private terminal.

Loads one v2 encrypted .lud using the original encrypted source triple and
original HUMAN workplan. The operator must review each five-column-identical
original record before a distinct NEW .lud ciphertext is published. No
plaintext decision sheet, HTML or original plan is written to disk.
"""
from __future__ import annotations

import argparse
import hashlib
import sys

from .private_export_encrypted import _passphrase, _seal
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_human_revision_vault import (
    DECISION_EXTENSION, MAGIC_DECISIONS, MAX_BOUND_DECISIONS,
    BINDING_SIZE, _current_source, _read_decisions, _reconcile,
)


def _review(document: dict) -> tuple[dict, int]:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("private interactive review terminal required")
    changed = 0
    for index, row in enumerate(document["decisions"], start=1):
        if row["source_change"] != "five_column_identical":
            # These may never contain copied HUMAN data, regardless of prior file.
            if row["copy_owner_and_note"] or row["copy_stage_and_due"]:
                raise ValueError("changed original finding had unauthorized carry decision")
            continue
        before = (row["copy_owner_and_note"], row["copy_stage_and_due"])
        print("\nPrivate original finding", index, "of", len(document["decisions"]), file=sys.stderr)
        print("Original finding ID:", row["finding_id"], file=sys.stderr)
        print("Original title:", row["title"], file=sys.stderr)
        print("Source-declared severity:", row["severity"], file=sys.stderr)
        print("Current unverified HUMAN carry:",
              "owner/note" if before[0] else "none",
              "+ proposed stage/date" if before[1] else "", file=sys.stderr)
        print("The five exported columns are identical; original underlying evidence is NOT proven unchanged.",
              file=sys.stderr)
        try:
            selection = input(
                "Choose KEEP, SKIP, OWNER, OWNER_AND_STAGE or QUIT: "
            )
        except (EOFError, KeyboardInterrupt):
            raise ValueError("operator cancelled complete HUMAN amendment") from None
        if selection == "QUIT":
            raise ValueError("operator cancelled before encrypted publication")
        if selection not in ("KEEP", "SKIP", "OWNER", "OWNER_AND_STAGE"):
            raise ValueError("invalid per-finding HUMAN choice, no output")
        if selection != "KEEP":
            row["copy_owner_and_note"] = selection in ("OWNER", "OWNER_AND_STAGE")
            row["copy_stage_and_due"] = selection == "OWNER_AND_STAGE"
        if (row["copy_owner_and_note"], row["copy_stage_and_due"]) != before:
            changed += 1
    return document, changed


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Amend original-source encrypted HUMAN decisions in a private foreground terminal; DRAFT/HOLD"
    )
    parser.add_argument("earlier_source")
    parser.add_argument("earlier_plan")
    parser.add_argument("later_source")
    parser.add_argument("--encrypted-choices", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--ack-private-handling", action="store_true")
    parser.add_argument("--ack-same-real-client", action="store_true")
    parser.add_argument("--ack-manual-human-review", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not all((
            args.ack_private_handling, args.ack_same_real_client,
            args.ack_manual_human_review
        )):
            raise ValueError("independent original source and private HUMAN review required")
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValueError("interactive owner-private terminal is mandatory")
        destination = _output_path(args.output, DECISION_EXTENSION)

        # Full original source admission and exact-ciphertext triplet binding
        # from the unchanged original-source readers and the existing v2 vault.
        expected, template, new_rows, new_meta, source_binding = _current_source(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        secret = _passphrase("Current encrypted HUMAN choices passphrase")
        document, _ = _read_decisions(args.encrypted_choices, secret, source_binding)
        del secret
        _reconcile(document, expected, template, new_meta, new_rows)

        reviewed, changed = _review(document)
        if not changed:
            raise ValueError("no changed HUMAN choices; use inspect or rotate instead")
        # Re-apply the whole selected set against the unchanged original newer
        # source before ANY encrypted file is published.
        _prepared_plan, summary = _reconcile(
            reviewed, expected, template, new_meta, new_rows
        )
        import json
        plain = json.dumps(
            reviewed, ensure_ascii=False, separators=(",", ":"),
            allow_nan=False,
        ).encode("utf-8", "strict")
        from .private_export_human_revision_choices import MAX_CHOICES
        if len(plain) > MAX_CHOICES:
            raise ValueError("reviewed decision document exceeds original bound")
        signed_plain = source_binding + plain
        if len(signed_plain) > MAX_BOUND_DECISIONS or len(source_binding) != BINDING_SIZE:
            raise ValueError("encrypted original-ciphertext binding is malformed")
        new_secret = _passphrase("NEW amended HUMAN choice passphrase", confirm=True)
        ciphertext = _seal(
            signed_plain, new_secret,
            magic=MAGIC_DECISIONS, max_plaintext=MAX_BOUND_DECISIONS
        )
        del new_secret
        _atomic_private_publish(destination, ciphertext)
        print("Created NEW 0600 v2 original-source-ciphertext-bound HUMAN decisions .lud.")
        print("Original encrypted decisions and sources remain untouched.")
        print("HUMAN decisions changed:", changed)
        for key, value in summary.items():
            print(key + ":", value)
        print("Unsigned local ciphertext SHA256:", hashlib.sha256(ciphertext).hexdigest())
        print("HOLD: no verified security fix, consent, evidence equivalence, retest or authority.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print(
            "PRIVATE HUMAN decision amendment HOLD: review, source or output denied.",
            file=sys.stderr,
        )
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
