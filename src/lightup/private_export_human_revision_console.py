"""Foreground menu for offline, human-approved original encrypted source revision carry.

Separate from active original source-owner export console; only handles original
.lue/.lun files already supplied by the operator. No background access.
"""
from __future__ import annotations

import sys

from . import private_export_human_revision, private_export_human_revision_workqueue


def _ask(label: str) -> str:
    try:
        value = input(label + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        raise ValueError("operator cancelled") from None
    if not value or len(value) > 1024:
        raise ValueError("empty or overlong private input")
    return value


def _confirm(message: str) -> None:
    print("\n" + message)
    if _ask("Type YES to acknowledge") != "YES":
        raise ValueError("no explicit human acknowledgment")


def main() -> int:
    print(
        "\nLIGHTUP · PRIVATE HUMAN SOURCE REVISION DESK\n"
        "INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT-HOLD\n"
        "Original five-column export equality does NOT establish equality of\n"
        "missing underlying evidence, client authentication or verified fixes.\n"
        "No live target, authority, consent, scanner or persisted finding change.\n"
    )
    print(
        "1. Preview carry eligibility (counts only, no output)\n"
        "2. Prepare a PRIVATE unencrypted ID-free local HTML review brief\n"
        "3. Create encrypted NEW source-bound HUMAN plan (owner/note carry only)\n"
        "4. Create encrypted NEW plan including old HUMAN stage/due (explicit opt-in)\n"
        "5. PRIVATE original-ID/title source change workqueue (unencrypted HTML)\n"
        "0. Exit"
    )
    try:
        choice = _ask("Choose 0-5")
        if choice == "0":
            return 0
        if choice not in ("1", "2", "3", "4", "5"):
            raise ValueError("unknown option")
        before = _ask("Earlier authenticated encrypted original source .lue")
        plan = _ask("Earlier exact-source encrypted HUMAN plan .lun")
        after = _ask("Later authenticated encrypted original source .lue")
        if not before.lower().endswith(".lue") or not after.lower().endswith(".lue"):
            raise ValueError("both original sources must use .lue")
        if not plan.lower().endswith(".lun"):
            raise ValueError("original HUMAN plan must use .lun")
        _confirm(
            "I have independently verified the SAME REAL client/engagement for "
            "both sources. Self-declared source IDs or digests cannot establish this."
        )
        _confirm(
            "This is a PRIVATE human-only local action. I will separately confirm "
            "storage, actual recipient and approved transport; no output establishes "
            "consent, verified fixes or permission to test."
        )
        if choice == "5":
            destination = _ask("NEW PRIVATE original-ID workqueue .html")
            if not destination.lower().endswith(".html"):
                raise ValueError("new workqueue must end with .html")
            _confirm(
                "This HTML is UNENCRYPTED and contains original private finding "
                "IDs and titles (but not notes, aliases, remedies or target data). "
                "I have independently approved its precise storage and recipient."
            )
            return private_export_human_revision_workqueue.main([
                before, plan, after, "--output", destination,
                "--ack-private-handling", "--ack-same-real-client",
                "--ack-original-ids-plaintext",
            ])
        action = "preview" if choice in ("1", "2") else "carry"
        args = [
            action, before, plan, after,
            "--ack-private-handling", "--ack-same-real-client",
        ]
        if choice in ("2", "3", "4"):
            output = _ask(
                "NEW local PRIVATE report .html" if choice == "2"
                else "NEW encrypted HUMAN plan .lun"
            )
            extension = ".html" if choice == "2" else ".lun"
            if not output.lower().endswith(extension):
                raise ValueError("invalid new output extension")
            args.extend(["--output", output])
        if choice == "2":
            _confirm(
                "Output is UNENCRYPTED HTML and may disclose small-count "
                "information. I have approved its exact local storage and recipient."
            )
            args.append("--ack-plaintext-html")
        if choice in ("3", "4"):
            _confirm(
                "Copy only original HUMAN coordination for rows with identical "
                "five original exported columns. A row match does not prove unchanged "
                "underlying evidence. All changed/absent identities require human review."
            )
            args.append("--ack-human-carryover")
        if choice == "4":
            _confirm(
                "In addition to HUMAN owner/note, I approve transferring unverified "
                "HUMAN stage and proposed date for exact five-column matches only. "
                "This is NOT remediation or retest verification."
            )
            args.extend(["--carry-stage", "--ack-human-stage-carryover"])
        return private_export_human_revision.main(args)
    except (ValueError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN revision desk HOLD: input or acknowledgment rejected.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
