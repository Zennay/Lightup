"""Foreground menu for offline, human-approved original encrypted source revision carry.

Separate from active original source-owner export console; only handles original
.lue/.lun files already supplied by the operator. No background access.
"""
from __future__ import annotations

import sys

from . import private_export_human_revision, private_export_human_revision_workqueue, private_export_human_revision_choices, private_export_human_revision_guided, private_export_human_revision_editor, private_export_human_revision_vault, private_export_human_revision_amend


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
        "6. Export FALSE-by-default private per-finding decision sheet (JSON)\n"
        "7. Import verified HUMAN decisions into NEW encrypted source-bound plan\n"
        "8. Guided per-finding terminal approval, directly to NEW encrypted plan\n"
        "9. PRIVATE offline browser editor for per-finding selection (HTML)\n"
        "10. Seal reviewed PRIVATE JSON choices to new encrypted .lud\n"
        "11. Apply encrypted .lud to a NEW encrypted original .lun\n"
        "12. Inspect encrypted original-source HUMAN decisions privately\n"
        "13. Rotate encrypted HUMAN decision passphrase into NEW .lud\n"
        "14. Open encrypted HUMAN choices as NEW UNENCRYPTED private JSON\n"
        "15. Amend encrypted HUMAN choices in PRIVATE guided terminal (no plaintext)\n"
        "0. Exit"
    )
    try:
        choice = _ask("Choose 0-15")
        if choice == "0":
            return 0
        if choice not in tuple(str(i) for i in range(1, 16)):
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
        if choice == "15":
            existing = _ask("Existing PRIVATE encrypted HUMAN choices .lud")
            if not existing.lower().endswith(".lud"):
                raise ValueError("existing encrypted decisions must end in .lud")
            destination = _ask("NEW encrypted amended HUMAN choices .lud")
            if not destination.lower().endswith(".lud"):
                raise ValueError("amended decisions must end in .lud")
            _confirm(
                "I will review every eligible original finding personally in a "
                "PRIVATE trusted terminal. This is solely HUMAN note coordination. "
                "No original security finding, actual client consent or fix is approved."
            )
            return private_export_human_revision_amend.main([
                before, plan, after, "--encrypted-choices", existing,
                "--output", destination, "--ack-private-handling",
                "--ack-same-real-client", "--ack-manual-human-review",
            ])
        if choice in ("10", "11", "12", "13", "14"):
            action = {
                "10": "seal", "11": "apply", "12": "inspect",
                "13": "rotate", "14": "open",
            }[choice]
            params = [
                action, before, plan, after,
                "--ack-private-handling", "--ack-same-real-client",
            ]
            if action == "seal":
                selection = _ask("Previously reviewed original PRIVATE JSON choice file (0600)")
                if not selection.lower().endswith(".json"):
                    raise ValueError("plaintext original decisions must end in .json")
                _confirm(
                    "I have manually reviewed the entire source-bound HUMAN-only "
                    "decision sheet and approved PRIVATE encryption and secure storage."
                )
                params.extend(["--choices", selection, "--ack-human-decisions"])
            else:
                selection = _ask("Encrypted original-source PRIVATE choice file .lud (0600)")
                if not selection.lower().endswith(".lud"):
                    raise ValueError("encrypted original decisions must end in .lud")
                params.extend(["--encrypted-choices", selection])
                if action == "apply":
                    _confirm(
                        "I independently verified the real reviewer and original source "
                        "and authorize local HUMAN coordination carry only; this does "
                        "not prove findings, fixes or active assessment consent."
                    )
                    params.append("--ack-human-decisions")
            if action != "inspect":
                extension = "lun" if action == "apply" else "json" if action == "open" else "lud"
                output = _ask("NEW PRIVATE output ." + extension)
                if not output.lower().endswith("." + extension):
                    raise ValueError("wrong output file extension")
                params.extend(["--output", output])
                if action == "open":
                    _confirm(
                        "This will write an UNENCRYPTED copy of original private IDs, "
                        "titles and source labels. I verified exact recipient and "
                        "owner-private storage independently."
                    )
                    params.append("--ack-unencrypted-original-ids")
            return private_export_human_revision_vault.main(params)
        if choice == "9":
            destination = _ask("NEW PRIVATE offline browser editor .html")
            if not destination.lower().endswith(".html"):
                raise ValueError("editor output must be .html")
            _confirm(
                "The offline HTML embeds original private finding IDs, titles, "
                "source labels and digests as UNENCRYPTED data. I have independently "
                "approved its local storage, trusted device and eventual recipient. "
                "No browser choice can approve scans, client consent or security fixes."
            )
            return private_export_human_revision_editor.main([
                before, plan, after, "--output", destination,
                "--ack-private-handling", "--ack-same-real-client",
                "--ack-plaintext-original-ids",
            ])
        if choice == "8":
            destination = _ask("NEW encrypted source-bound HUMAN plan .lun")
            if not destination.lower().endswith(".lun"):
                raise ValueError("new plan must end with .lun")
            _confirm(
                "I have a PRIVATE interactive terminal and will review EVERY "
                "eligible finding ID individually. This is HUMAN coordination "
                "only, not evidence equality, real consent, a verified fix or retest."
            )
            return private_export_human_revision_guided.main([
                before, plan, after, "--output", destination,
                "--ack-private-terminal", "--ack-same-real-client",
                "--ack-human-decisions",
            ])
        if choice in ("6", "7"):
            if choice == "6":
                destination = _ask("NEW private, UNENCRYPTED original-ID choice sheet .json")
                if not destination.lower().endswith(".json"):
                    raise ValueError("selection sheet must end in .json")
                _confirm(
                    "The selection sheet contains original PRIVATE finding IDs, titles, "
                    "severity and record hashes as PLAINTEXT. All approvals begin FALSE. "
                    "I separately approve recipient and storage."
                )
                return private_export_human_revision_choices.main([
                    "prepare", before, plan, after, "--output", destination,
                    "--ack-private-handling", "--ack-same-real-client",
                    "--ack-plaintext-original-ids",
                ])
            selection = _ask("Operator-reviewed owner-private decision sheet .json (0600)")
            if not selection.lower().endswith(".json"):
                raise ValueError("selection sheet must end in .json")
            destination = _ask("NEW encrypted source-bound HUMAN plan .lun")
            if not destination.lower().endswith(".lun"):
                raise ValueError("new plan must end in .lun")
            _confirm(
                "I have PERSONALLY reviewed every private per-finding source-row "
                "choice. TRUE only means copying unverified HUMAN coordination "
                "from five-column-identical sources, NEVER verified evidence, "
                "fix, active authorization, genuine recipient identity or consent."
            )
            return private_export_human_revision_choices.main([
                "apply", before, plan, after, "--choices", selection,
                "--output", destination, "--ack-private-handling",
                "--ack-same-real-client", "--ack-manual-human-decisions",
            ])
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
