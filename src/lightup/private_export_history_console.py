"""Foreground interactive operator UI for PRIVATE encrypted HUMAN history.

This independent menu does not modify the concurrently owned original
LightUp operator console; no background agents, network or saved passwords.
"""
from __future__ import annotations

import sys

from . import private_export_history, private_export_history_vault, private_export_history_calendar

OPTIONS = (
    ("1", "ID-free offline HUMAN history HTML", "html"),
    ("2", "Explicit PRIVATE original-ID/owner HUMAN attention HTML", "private-html"),
    ("3", "ID-free offline HUMAN history JSON for local aggregation", "json"),
    ("4", "Compile HUMAN history directly to encrypted .luh", "encrypted"),
    ("5", "Inspect encrypted HUMAN history without writing plaintext", "inspect"),
    ("6", "Open encrypted HUMAN history into new PRIVATE HTML", "open"),
    ("7", "Rotate encrypted HUMAN history passphrase", "rotate"),
    ("8", "ID-free proposed HUMAN follow-up calendar (.ics)", "calendar"),
    ("9", "Explicit PRIVATE original finding/owner calendar (.ics)", "private-calendar"),
    ("10", "Rebuild encrypted HUMAN timeline from exact original source+plans", "verify"),
    ("0", "Exit foreground local menu", "exit"),
)
WARNING = (
    "LightUp · PRIVATE HUMAN PLAN HISTORY · INCUBATE DRAFT/HOLD.\n"
    "All findings, owner aliases, due dates and HUMAN notes are unverified\n"
    "source-bound coordination claims, NOT permission, original identity,\n"
    "verified remediation, retest results or real recipient authentication.\n"
    "The HTML/JSON option writes UNENCRYPTED 0600 private files. The .luh\n"
    "option writes only AES-GCM ciphertext; key/recipient care is separate."
)


def _ask(prompt: str, optional: bool = False) -> str | None:
    try:
        value = input(prompt + ": ").strip()
    except (EOFError, KeyboardInterrupt):
        raise ValueError("operator cancelled") from None
    if len(value) > 1024:
        raise ValueError("operator input exceeds local limit")
    if not value:
        if optional:
            return None
        raise ValueError("required HUMAN selection missing")
    return value


def _agree(message: str) -> None:
    print(message)
    if _ask("Type YES to accept this local PRIVATE action") != "YES":
        raise ValueError("HUMAN private acknowledgment declined")


def _out(ext: str) -> str:
    dest = _ask("New PRIVATE output filename (." + ext + ", no overwrite)")
    if not dest.lower().endswith("." + ext):
        raise ValueError("invalid private output extension")
    return dest


def _source_plans() -> tuple[str, list[str], str | None]:
    source = _ask("Original encrypted LightUp finding source .lue")
    if not source.endswith(".lue"):
        raise ValueError("original encrypted .lue required")
    paths = []
    for i in range(12):
        path = _ask("Original-source HUMAN snapshot " + str(i + 1) +
                    " encrypted .lun (blank to finish)", optional=True)
        if path is None:
            break
        if not path.endswith(".lun"):
            raise ValueError("only original encrypted .lun plans supported")
        paths.append(path)
    if not paths:
        raise ValueError("at least one encrypted HUMAN plan required")
    as_of = _ask("UTC as-of YYYY-MM-DD (blank = current UTC day)",
                 optional=True)
    return source, paths, as_of


def _perform(option: str) -> int:
    if option == "verify":
        vault = _ask("Encrypted private HUMAN timeline .luh")
        if not vault.endswith(".luh"):
            raise ValueError("encrypted history .luh required")
        source, plans, _unused_asof = _source_plans()
        _agree(
            "This action decrypts the original PRIVATE finding source and every "
            "HUMAN snapshot to independently reconstruct the local report. "
            "Exact SHA/labels and identical HTML bytes are NOT real-world "
            "client/owner authenticity, consent, remediated findings or fixes."
        )
        return private_export_history_vault.main(
            ["verify", vault, source] + plans + ["--ack-private-handling"]
        )

    if option in ("calendar", "private-calendar"):
        source = _ask("Original encrypted finding source .lue")
        plan = _ask("Latest exact-original-source encrypted HUMAN plan .lun")
        if not source.endswith(".lue") or not plan.endswith(".lun"):
            raise ValueError("original encrypted source and HUMAN plan required")
        private = option == "private-calendar"
        if private:
            _agree(
                "This calendar includes ORIGINAL finding IDs, titles and self-declared "
                "owner aliases in plaintext calendar events. I have independently "
                "verified the actual recipient and approved private calendar storage."
            )
        _agree(
            "The .ics is UNENCRYPTED and contains only proposed HUMAN follow-up "
            "dates, NOT approved security fix/change windows. Calendar import is "
            "manual; repeated imports may duplicate events. I accept the storage risk."
        )
        output = _out("ics")
        command = [source, plan, "--output", output, "--ack-unencrypted-calendar"]
        if private:
            command += ["--include-private-events", "--ack-private-records"]
        return private_export_history_calendar.main(command)

    if option in ("html", "private-html", "json", "encrypted"):
        source, snapshots, as_of = _source_plans()
        private = option == "private-html"
        if private:
            _agree(
                "The report will include ORIGINAL source IDs, titles and self-"
                "declared HUMAN owner aliases in an UNENCRYPTED PRIVATE HTML. "
                "I separately verified its real recipient and safe storage."
            )
        if option != "encrypted":
            _agree(
                "The human summary is UNENCRYPTED; even anonymous small cohorts "
                "may reveal a client. I have independently reviewed the "
                "recipient and local private storage/transport."
            )
        else:
            _agree(
                "The report will be AES-GCM encrypted in a separate .luh format, "
                "not the existing browser Handoff Vault. It remains a HUMAN "
                "draft, not authenticated original ownership or consent."
            )
        extension = "luh" if option == "encrypted" else (
            "json" if option == "json" else "html"
        )
        output = _out(extension)
        common = ["--output", output, "--ack-private-original-data",
                  "--ack-plaintext-destination"]
        if option == "encrypted":
            args = ["create", source] + snapshots + ["--output", output,
                    "--ack-private-handling"]
            if as_of:
                args += ["--as-of", as_of]
            return private_export_history_vault.main(args)
        args = [source] + snapshots + common + [
            "--format", "json" if option == "json" else "html"
        ]
        if private:
            args += ["--include-private-actions", "--ack-private-attention-ids"]
        if as_of:
            args += ["--as-of", as_of]
        return private_export_history.main(args)

    vault = _ask("Existing encrypted HUMAN timeline .luh")
    if not vault.endswith(".luh"):
        raise ValueError("encrypted .luh required")
    if option == "inspect":
        _agree("Review only ID-free anonymous counts from locally decrypted ciphertext.")
        return private_export_history_vault.main(
            ["inspect", vault, "--ack-private-handling"]
        )
    if option == "open":
        _agree(
            "Decrypted PRIVATE history HTML will be UNENCRYPTED and may include "
            "original IDs/aliases selected when the vault was created. "
            "I have verified actual recipient and secure local storage."
        )
        output = _out("html")
        return private_export_history_vault.main(
            ["open", vault, "--output", output, "--ack-private-handling",
             "--ack-plaintext-html"]
        )
    if option == "rotate":
        _agree(
            "The old encrypted vault will not be deleted or overwritten. "
            "I will separately protect the old copy and communicate the new "
            "passphrase only via independently approved secure channels."
        )
        output = _out("luh")
        return private_export_history_vault.main(
            ["rotate", vault, "--output", output, "--ack-private-handling"]
        )
    raise ValueError("unknown option")


def main() -> int:
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        print("Interactive local terminal required, no background operation.",
              file=sys.stderr)
        return 2
    print(WARNING)
    while True:
        print("\nOriginal-source PRIVATE HUMAN history")
        for key, label, _ in OPTIONS:
            print(" " + key + " — " + label)
        try:
            selection = _ask("Select one local action")
            action = next((action for key, _label, action in OPTIONS
                           if selection == key), None)
            if action is None:
                print("Unknown action: no source or output was changed.")
                continue
            if action == "exit":
                print("Exited local HUMAN history console; no background work remains.")
                return 0
            result = _perform(action)
            if result:
                print("HUMAN HOLD: action declined or source/envelope rejected.")
            else:
                print("Offline HUMAN action finished. Verify privacy, client and recipient.")
        except ValueError:
            print("HUMAN HOLD: incomplete, cancelled or unapproved local selection.")
        except KeyboardInterrupt:
            print("\nExited local console.")
            return 2


if __name__ == "__main__":
    raise SystemExit(main())
