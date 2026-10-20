#!/usr/bin/env python3
"""Offline PRIVATE HUMAN remediation operator launcher.

This is an intentional interface to the existing native source-admitting CLIs.
It cannot run scans, obtain grants, authenticate consent, or mark fixes verified.
"""
from __future__ import annotations

import argparse
import os
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent
WARNING = ("INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD. Local HUMAN plans, "
           "unsigned hashes, and encrypted packets are NOT authority, genuine "
           "provenance, consent, verified findings, fixes, or HUMAN GO.")

# Exact fixed native modules and literal argument names. No shell or arbitrary
# programs can be selected through this launcher.
OPERATIONS = {
    "owner": ("workflow.py", ("owner-start",), (
        ("--input-dir", "Original PRIVATE ledger directory (repeatable)", True, False),
        ("--bundle", "Original PRIVATE evidence bundle (optional, repeatable)", True, False),
        ("--output-dir", "NEW owner-private workroom directory", False, True),
    ), "Original evidence stays with owner; separate source-free HUMAN handoff."),
    "owner-package": ("workflow.py", ("owner-start",), (
        ("--input-dir", "Original PRIVATE ledger (repeatable)", True, False),
        ("--bundle", "Original PRIVATE bundle (repeatable)", True, False),
        ("--output-dir", "NEW private owner workroom", False, True),
        ("--output-file", "NEW separate unsigned .luhz archive (NOT sent)", False, True),
    ), "One native owner workroom and a separate original source-free packet."),
    "recipient": ("workflow.py", ("recipient-start",), (
        ("--cockpit", "Received original source-free Cockpit (1–12)", True, True),
        ("--output-dir", "NEW private HUMAN review directory", False, True),
    ), "One packet gets a single HUMAN reviewer; 2–12 use original comparisons."),
    "archives": ("archive_workflow.py", (), (
        ("--archive", "Source-free original .luhz archive (repeatable)", True, False),
        ("--encrypted-archive", "Private .luhx encrypted archive (repeatable)", True, False),
        ("--output-dir", "NEW private review directory", False, True),
    ), "Use ONLY actually received packets; no synthetic moment or identity."),
    "pack": ("portable_cockpit.py", ("pack",), (
        ("--cockpit", "Exact original source-free Cockpit directory", False, True),
        ("--output-file", "NEW unsigned .luhz file", False, True),
    ), "Unsigned, unencrypted packet. Separate genuine disclosure approval required."),
    "unpack": ("portable_cockpit.py", ("unpack",), (
        ("--archive", "Original received unsigned .luhz", False, True),
        ("--output-dir", "NEW private recipient directory", False, True),
    ), "Fail-closed original source-free archive admission."),
    "review": ("single_review.py", ("start",), (
        ("--cockpit", "One exact original source-free Cockpit", False, True),
        ("--output-dir", "NEW private HUMAN reviewer", False, True),
    ), "One source moment only; never a fabricated longitudinal comparison."),
    "continue-review": ("single_review.py", ("resume",), (
        ("--cockpit", "Same exact original source-free Cockpit", False, True),
        ("--journal", "Original source-bound PRIVATE HUMAN journal JSON", False, True),
        ("--output-dir", "NEW private reviewer directory", False, True),
    ), "Resume only originally saved HUMAN answers on the same original source."),
    "brief": ("single_brief.py", (), (
        ("--cockpit", "Same original source-free Cockpit", False, True),
        ("--journal", "Actual original-bound HUMAN journal JSON", False, True),
        ("--output-dir", "NEW private scriptless HUMAN briefing directory", False, True),
    ), "Plaintext HUMAN answers remain sensitive; no technical remediation proof."),
    "seal-journal": ("journal_vault.py", ("seal",), (
        ("--cockpit", "Original source-free Cockpit", False, True),
        ("--journal", "Original HUMAN journal JSON", False, True),
        ("--output-file", "NEW encrypted .luhj destination", False, True),
    ), "Passphrase requested by original vault at private interactive terminal."),
    "open-journal": ("journal_vault.py", ("resume",), (
        ("--cockpit", "Same original source-free Cockpit", False, True),
        ("--vault", "Existing source-bound encrypted .luhj", False, True),
        ("--output-dir", "NEW private unsealed HUMAN reviewer", False, True),
    ), "Unsealed HUMAN notes appear in owner-private output; no silent disclosure."),
    "rekey-journal": ("journal_vault.py", ("rekey",), (
        ("--cockpit", "Same original source-free Cockpit", False, True),
        ("--vault", "Existing encrypted original .luhj", False, True),
        ("--output-file", "NEW encrypted .luhj (old vault retained)", False, True),
    ), "Old ciphertext is retained; no claim of secure erasure or revocation."),
    "encrypt-cockpit": ("encrypted_cockpit.py", ("encrypt",), (
        ("--cockpit", "Original source-free Cockpit", False, True),
        ("--output-file", "NEW locally encrypted .luhx", False, True),
    ), "Encryption does not authenticate the sender or grant disclosure."),
    "decrypt-cockpit": ("encrypted_cockpit.py", ("decrypt",), (
        ("--archive", "Existing encrypted .luhx archive", False, True),
        ("--output-dir", "NEW private decrypted directory", False, True),
    ), "Original native admission; no plaintext intermediate ZIP."),
    "pack-review": ("review_package.py", ("create",), (
        ("--cockpit", "Original source-free Cockpit", False, True),
        ("--journal", "Source-bound plaintext HUMAN journal (alternative)", False, False),
        ("--journal-vault", "Source-bound encrypted HUMAN journal (alternative)", False, False),
        ("--output-file", "NEW source-free HUMAN review packet .luhp", False, True),
    ), "Use one native journal form, never both. No client identity or authority."),
    "receive-review": ("review_package.py", ("receive",), (
        ("--archive", "Existing source-free HUMAN review package .luhp", False, True),
        ("--output-dir", "NEW source-bound PRIVATE reviewer directory", False, True),
    ), "No original-source, sender, consent or verified-fix authentication."),
    "install": ("install.py", ("build",), (
        ("--output-dir", "NEW owner-private software-only suite", False, True),
    ), "Copies original pinned software only; NEVER client data."),
    "receive-software": ("install.py", ("receive",), (
        ("--archive", "Original software-only ZIP", False, True),
        ("--output-dir", "NEW owner-private software installation", False, True),
    ), "Original-byte admission without producer identity claim."),
    "inspect-software": ("install.py", ("inspect",), (
        ("--workspace", "Existing private software-only suite", False, True),
    ), "Local consistency inspection only; not CI/release approval."),
}

def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        description="LightUp native offline PRIVATE HUMAN operations. " + WARNING,
        formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="action", required=True)
    sub.add_parser("menu", help="Interactive HUMAN-only selector (private terminal)")
    sub.add_parser("list", help="Show every available original bounded operation")
    for name, (_, _, options, description) in OPERATIONS.items():
        cmd = sub.add_parser(name, help=description, description=description + "\n" + WARNING)
        for flag, helptext, repeat, required in options:
            cmd.add_argument(flag, action="append" if repeat else "store",
                             required=required, help=helptext)
    return p

def present() -> None:
    print(WARNING)
    print("\nAllowed native PRIVATE operations:")
    for i, (name, (_, _, _, purpose)) in enumerate(OPERATIONS.items(), 1):
        print(f"  {i:2d}. {name:18s} {purpose}")
    print("\nNo operation is automatically approved or executed.")

def menu():
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        raise ValueError("Interactive selection requires a private TTY")
    present()
    index = input("\nSelect native operation number (blank cancels): ").strip()
    if not index:
        return None
    if not index.isdecimal() or not 1 <= int(index) <= len(OPERATIONS):
        raise ValueError("Unknown operation number")
    name = list(OPERATIONS)[int(index) - 1]
    _, _, options, purpose = OPERATIONS[name]
    print("\n" + purpose)
    values = {}
    for flag, label, repeat, required in options:
        if repeat:
            found = []
            while True:
                entered = input(f"{label} (blank ends list): ").strip()
                if not entered:
                    break
                found.append(entered)
            if required and not found:
                raise ValueError("Required original input missing: " + flag)
            values[flag] = found
        else:
            entered = input(f"{label}{' [required]' if required else ' [optional]'}: ").strip()
            if required and not entered:
                raise ValueError("Required original input missing: " + flag)
            values[flag] = entered or None
    print("\nAction:", name, "\n" + WARNING)
    if input("Start native offline action now? Type YES: ").strip() != "YES":
        print("Cancelled; no original file changed.")
        return None
    return name, values

def dispatch(name: str, values: dict) -> None:
    module, prefix, options, _ = OPERATIONS[name]
    arguments = [str(ROOT / module), *prefix]
    for flag, _, repeat, required in options:
        raw = values.get(flag)
        items = (raw or []) if repeat else ([raw] if raw else [])
        if required and not items:
            raise ValueError("Missing required original input: " + flag)
        for item in items:
            if not item or "\x00" in item or "\n" in item or "\r" in item:
                raise ValueError("Invalid path input")
            path = Path(item).expanduser()
            if not path.is_absolute():
                raise ValueError("Use a literal absolute path: " + flag)
            arguments.extend((flag, str(path)))
    if name in ("owner", "owner-package") and not (values.get("--input-dir") or values.get("--bundle")):
        raise ValueError("Select actual original private evidence inputs")
    if name == "archives" and not (values.get("--archive") or values.get("--encrypted-archive")):
        raise ValueError("Select actual received original archive(s)")
    if name == "pack-review" and bool(values.get("--journal")) == bool(values.get("--journal-vault")):
        raise ValueError("Choose exactly one original source-bound HUMAN journal form")
    if name == "owner-package":
        # Explicit composition of two ORIGINAL bounded source admissions.
        from workflow import owner_start
        from portable_cockpit import pack as native_pack
        owner_dest = Path(values["--output-dir"])
        packet_dest = Path(values["--output-file"])
        if packet_dest == owner_dest or owner_dest in packet_dest.parents:
            raise ValueError("SOURCE-FREE packet must remain OUTSIDE ORIGINAL owner evidence")
        print("Preparing private ORIGINAL owner workroom. No packet transmitted.", flush=True)
        owner_start([Path(x) for x in values.get("--input-dir", [])],
                    [Path(x) for x in values.get("--bundle", [])], owner_dest)
        print("Re-admitting the separate native SOURCE-FREE folder.", flush=True)
        native_pack(owner_dest / "source-free-recipient", packet_dest)
        print("REVIEW_ONLY: packet is unsigned; disclosure requires separate approval.")
        return 2
    if not (ROOT / module).is_file():
        raise ValueError("Pinned native module missing from PRIVATE software")
    print("Delegating to original native source checks. " + WARNING, flush=True)
    # Passphrases are NEVER command arguments or environment variables.
    # Native vault modules use their own secure interactive TTY handling.
    os.execv(sys.executable, [sys.executable, *arguments])

def main() -> int:
    p = parser()
    args = p.parse_args()
    try:
        if args.action == "list":
            present()
            return 2  # REVIEW_ONLY, not authority
        if args.action == "menu":
            chosen = menu()
            if chosen is None:
                return 2
            name, values = chosen
        else:
            name = args.action
            values = {flag: getattr(args, flag.lstrip("-").replace("-", "_"))
                      for flag, _, _, _ in OPERATIONS[name][2]}
        result = dispatch(name, values)
        return result if result is not None else 3  # execv never returns on success
    except (ValueError, OSError) as exc:
        print("HOLD:", exc, file=sys.stderr)
        return 3

if __name__ == "__main__":
    raise SystemExit(main())
