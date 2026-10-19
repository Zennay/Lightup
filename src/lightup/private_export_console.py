"""Operator-led local PRIVATE finding handoff console.

This is a foreground menu over the original guarded source-bound commands,
not a new authentication or authorization boundary. It does not persist inputs,
start targets, automatically upload evidence, or invoke any external service.
"""
from __future__ import annotations

import sys

from . import private_export_continuity, private_export_handoff, private_export_workdesk

TITLE = "LightUp PRIVATE HUMAN Export & Remediation Desk"
NOTICE = (
    "INCUBATE / DRAFT-HOLD / PLAN-LAB ONLY.\n"
    "Original export authentication remains mandatory. Offline ZIP, HTML and\n"
    "HUMAN JSON contain private, UNENCRYPTED customer-related information.\n"
    "No saved file proves client identity, consent, findings, fixes or retests.\n"
    "Do not share outside independently verified and approved secure channels."
)
OPTIONS = (
    ("1", "Authenticated original tenant finding export", "create"),
    ("2", "Inspect a local PRIVATE source ZIP", "inspect"),
    ("3", "Produce an ID-free human aggregate brief", "aggregate"),
    ("4", "Create original finding HUMAN Workdesk", "workdesk"),
    ("5", "Resume exact-source PRIVATE HUMAN workplan", "resume"),
    ("6", "Compare two original source ZIP snapshots", "continuity"),
    ("7", "Carry HUMAN annotations only for source-identical findings", "migrate"),
    ("0", "Exit (no data or state written)", "exit"),
)


def _ask(question: str, *, optional: bool = False) -> str | None:
    try:
        value = input(question + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        raise ValueError("operator cancelled") from None
    if not value:
        if optional:
            return None
        raise ValueError("a required value was not supplied")
    if len(value) > 1024:
        raise ValueError("operator input is too long")
    return value


def _confirm(statement: str) -> None:
    print(statement)
    if _ask("Type YES to explicitly acknowledge") != "YES":
        raise ValueError("operator did not explicitly acknowledge this action")


def _output(label: str, extension: str) -> str:
    value = _ask(label + " (new ." + extension + ", no overwrite)")
    if not value.lower().endswith("." + extension):
        raise ValueError("output must be a ." + extension + " file")
    return value


def _private() -> None:
    _confirm(
        "The output will be UNENCRYPTED and locally PRIVATE. I have verified "
        "the intended recipient and approved secure storage/transport myself."
    )


def _original() -> None:
    _confirm(
        "This operation exposes ORIGINAL source finding IDs, titles and "
        "remediation claims locally. I accept responsibility for recipient "
        "privacy and no-authorization restrictions."
    )


def _same_real_client() -> None:
    _confirm(
        "I have INDEPENDENTLY confirmed these sources belong to the SAME REAL "
        "client and engagement. Matching self-declared ZIP labels alone "
        "does not establish identity, consent or permission."
    )


def _perform(action: str) -> int:
    if action == "create":
        database = _ask("Existing local DomainStore database path")
        email = _ask("Existing operator/client account email")
        client = _ask("Existing authorized client ID")
        engagement = _ask("Specific existing engagement ID", optional=True)
        dest = _output("PRIVATE original source ZIP path", "zip")
        _private()
        command = ["create", "--db", database, "--email", email, "--client-id",
                   client, "--output", dest, "--ack-private-plaintext"]
        if engagement is not None:
            command.extend(["--engagement-id", engagement])
        print("Original DomainStore will prompt for a password on this terminal.")
        return private_export_handoff.main(command)

    if action == "inspect":
        return private_export_handoff.main(["inspect", _ask("Existing private ZIP path")])

    if action == "aggregate":
        archive = _ask("Existing private ZIP path")
        output = _output("PRIVATE ID-free aggregate HTML", "html")
        _private()
        return private_export_handoff.main(
            ["report", archive, "--output", output, "--ack-private-plaintext"]
        )

    if action in ("workdesk", "resume"):
        archive = _ask("Current original PRIVATE ZIP path")
        draft = _ask("Exact-source previous PRIVATE HUMAN JSON", optional=True) if action == "resume" else None
        if action == "resume" and not draft:
            raise ValueError("resume requires a previous original HUMAN JSON")
        output = _output("New original findings PRIVATE HTML Workdesk", "html")
        _original()
        _private()
        command = [archive, "--output", output, "--ack-private-plaintext",
                   "--ack-original-identifiers"]
        if draft:
            command.extend(["--resume", draft])
        return private_export_workdesk.main(command)

    if action == "continuity":
        old = _ask("Earlier original PRIVATE ZIP")
        new = _ask("Later original PRIVATE ZIP")
        output = _output("New PRIVATE anonymous source continuity HTML", "html")
        _same_real_client()
        _private()
        return private_export_continuity.main(
            [old, new, "--output", output, "--acknowledge-same-client",
             "--ack-private-plaintext"]
        )

    if action == "migrate":
        old = _ask("Earlier original PRIVATE source ZIP")
        prior = _ask("Earlier source-bound PRIVATE HUMAN JSON workplan")
        new = _ask("New ORIGINAL PRIVATE source ZIP")
        output = _output("New PRIVATE HUMAN Workdesk HTML", "html")
        _same_real_client()
        _original()
        _private()
        _confirm(
            "ONLY exactly source-identical original five-column finding records "
            "will carry HUMAN notes. Changed/new records reset; absent does NOT "
            "mean fixed. This action never reauthenticates source identity."
        )
        return private_export_workdesk.main(
            [new, "--output", output, "--carry-forward-from", old,
             "--carry-forward-plan", prior, "--ack-same-real-client",
             "--ack-review-carryover", "--ack-original-identifiers",
             "--ack-private-plaintext"]
        )
    raise ValueError("invalid console option")


def main() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Foreground interactive terminal required; no background execution.",
              file=sys.stderr)
        return 2
    print("\n" + TITLE)
    print(NOTICE)
    while True:
        print("\nOriginal guarded source operations")
        for key, description, _action in OPTIONS:
            print(" " + key + " — " + description)
        try:
            choice = _ask("Choose a menu action")
            selected = next((action for key, _name, action in OPTIONS if key == choice), None)
            if selected is None:
                print("Unknown choice. No file or service changed.")
                continue
            if selected == "exit":
                print("Closed local console; no background process.")
                return 0
            result = _perform(selected)
            if result:
                print("HUMAN HOLD: operation declined or source validation failed.")
            else:
                print("Local artifact workflow completed. Review content and private handling.")
        except ValueError:
            print("HUMAN HOLD: operator cancelled, refused or gave invalid input.")
        except (EOFError, KeyboardInterrupt):
            print("\nExited local console.")
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
