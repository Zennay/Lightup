"""Foreground-only selective original-source HUMAN workplan migration.

Unlike the editable PRIVATE JSON handoff, decisions are made individually on
a trusted operator terminal, in RAM, without any intermediate plaintext file.
No source, domain, grant, finding or prior encrypted plan is modified.
"""
from __future__ import annotations

import argparse
import hashlib
import sys

from .private_export_encrypted import _passphrase, _seal
from .private_export_encrypted_notes import MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_human_revision import _read_inputs, _review_revision
from .private_export_human_revision_choices import _make_choices, _apply_choices
from .private_export_workdesk import MAX_PLAN


def _decisions(expected: dict, earlier_notes: dict) -> dict:
    if not sys.stdin.isatty() or not sys.stderr.isatty():
        raise ValueError("private HUMAN review requires interactive terminal")
    rows = expected["decisions"]
    number = len(rows)
    for index, row in enumerate(rows, start=1):
        if row["source_change"] != "five_column_identical":
            continue
        prior = earlier_notes[row["finding_id"]]
        print("\nHUMAN original source review", index, "of", number, file=sys.stderr)
        print("Original ID:", row["finding_id"], file=sys.stderr)
        print("Source-declared title:", row["title"], file=sys.stderr)
        print("Source-declared severity:", row["severity"], file=sys.stderr)
        print("Previous UNVERIFIED human stage:", prior["stage"], file=sys.stderr)
        print("Previous HUMAN note:", "present" if prior["human_note"] else "none",
              file=sys.stderr)
        print(
            "Five original exported columns match; underlying evidence, asset "
            "and authentic consent UNKNOWN.", file=sys.stderr
        )
        try:
            choice = input(
                "Explicit HUMAN choice [SKIP / OWNER / OWNER_AND_STAGE / QUIT]: "
            )
        except (EOFError, KeyboardInterrupt):
            raise ValueError("human abandoned revision review") from None
        if choice == "QUIT":
            raise ValueError("human cancelled complete revision carry")
        if choice not in ("SKIP", "OWNER", "OWNER_AND_STAGE"):
            raise ValueError("unrecognized human choice; no file published")
        row["copy_owner_and_note"] = choice in ("OWNER", "OWNER_AND_STAGE")
        row["copy_stage_and_due"] = choice == "OWNER_AND_STAGE"
    return expected


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Foreground per-finding selective encrypted HUMAN source migration; DRAFT/HOLD"
    )
    parser.add_argument("earlier_source")
    parser.add_argument("earlier_plan")
    parser.add_argument("later_source")
    parser.add_argument("--output", required=True)
    parser.add_argument("--ack-private-terminal", action="store_true")
    parser.add_argument("--ack-same-real-client", action="store_true")
    parser.add_argument("--ack-human-decisions", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not (args.ack_private_terminal and args.ack_same_real_client
                and args.ack_human_decisions):
            raise ValueError("independent original-source HUMAN review acknowledgments required")
        if not sys.stdin.isatty() or not sys.stderr.isatty():
            raise ValueError("private HUMAN interactive terminal required")
        destination = _output_path(args.output, ".lun")
        before, original, earlier_notes, later, current = _read_inputs(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        decisions = _make_choices(before, original, earlier_notes, later, current)
        print(
            "\nDRAFT/HOLD: Source labels, IDs and original five exported columns "
            "do NOT authenticate client/consent, prove unchanged underlying evidence "
            "or authorize any active remediation/retest.", file=sys.stderr
        )
        approved = _decisions(decisions, earlier_notes)
        candidate, _ = _review_revision(
            before, original, earlier_notes, later, current, carry_stage=True
        )
        blob, summary = _apply_choices(approved, decisions, candidate, later, current)
        passphrase = _passphrase("NEW encrypted HUMAN plan passphrase", confirm=True)
        envelope = _seal(blob, passphrase, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN)
        del passphrase
        _atomic_private_publish(destination, envelope)
        print("NEW encrypted, source-bound HUMAN draft created without any plaintext decisions.")
        for key, value in summary.items():
            print(key + ":", value)
        print("Unsigned local ciphertext SHA-256:", hashlib.sha256(envelope).hexdigest())
        print("HOLD: No client identity, consent, verified remediation or retest established.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("HUMAN guided revision HOLD: no output or only previously published output.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
