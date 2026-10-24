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

# The HUMAN launcher may dispatch a read-only source inspection. Importing
# the shared original path policy must not create Python bytecode caches in
# the trusted checkout before the native no-write inspector is executed.
if __name__ == "__main__":
    sys.dont_write_bytecode = True

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
    "owner-encrypted": ("workflow.py", ("owner-start",), (
        ("--input-dir", "Original PRIVATE ledger (repeatable)", True, False),
        ("--bundle", "Original PRIVATE bundle (repeatable)", True, False),
        ("--output-dir", "NEW private ORIGINAL owner workroom", False, True),
        ("--output-file", "NEW encrypted source-free .luhx (NOT sent)", False, True),
    ), "Build original owner workroom and locally encrypt source-free transfer in memory."),
    "owner-encrypted-receipt": ("workflow.py", ("owner-start",), (
        ("--input-dir", "Original PRIVATE ledger(s), repeatable", True, False),
        ("--bundle", "Original PRIVATE bundle(s), repeatable", True, False),
        ("--output-dir", "NEW PRIVATE original owner workroom", False, True),
        ("--output-file", "NEW source-free encrypted .luhx (not sent)", False, True),
        ("--receipt-file", "NEW separate PRIVATE unsigned .json fingerprint receipt", False, True),
    ), "Create encrypted source-free packet AND separate unsigned local byte receipt in one owner action."),
    "recipient": ("workflow.py", ("recipient-start",), (
        ("--cockpit", "Received original source-free Cockpit (1–12)", True, True),
        ("--output-dir", "NEW private HUMAN review directory", False, True),
    ), "One packet gets a single HUMAN reviewer; 2–12 use original comparisons."),
    "archives": ("archive_workflow.py", (), (
        ("--archive", "Source-free original .luhz archive (repeatable)", True, False),
        ("--encrypted-archive", "Private .luhx encrypted archive (repeatable)", True, False),
        ("--receipt", "Optional original PRIVATE UNSIGNED byte receipt (check BEFORE decrypt)", False, False),
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
    "fingerprint-create": ("packet_fingerprint.py", ("create",), (
        ("--packet", "Original locally selected source-free .luhx/.luhz/.luhp packet(s)", True, True),
        ("--output-file", "NEW private unsigned SHA-256 JSON receipt", False, True),
    ), "Native 0600 source-free byte receipt; hash only, no contents or signature."),
    "fingerprint-compare": ("packet_fingerprint.py", ("compare",), (
        ("--packet", "Actually received PRIVATE packet(s), SAME ordinal order", True, True),
        ("--receipt", "Separately authorized original unsigned PRIVATE JSON hashreceipt", False, True),
        ("--output-dir", "Optional NEW scriptless PRIVATE HUMAN review report directory", False, False),
    ), "Fail closed on changed original bytes; optional local PRIVATE HTML report."),
    "install": ("install.py", ("build",), (
        ("--output-dir", "NEW owner-private software-only suite", False, True),
    ), "Copies original pinned software only; NEVER client data."),
    "inspect-archive": ("install.py", ("inspect-archive",), (
        ("--archive", "Existing PRIVATE owner-only source-only ZIP", False, True),
        ("--expected-sha256-file", "Optional SEPARATELY obtained PRIVATE 0600 exact ZIP SHA-256 fingerprint file", False, False),
        ("--planned-output-dir", "Optional NEW owner-only receive destination, checked without creation", False, False),
        ("--planned-checksum-file", "Optional NEW separate PRIVATE 0600 checksum path, checked without writing", False, False),
    ), "No-write original ZIP check plus optional checksum and planned recipient path admission."),
    "fingerprint-archive": ("install.py", ("fingerprint-archive",), (
        ("--archive", "Existing admitted private source-only software ZIP", False, True),
        ("--output-file", "NEW private 0600 ASCII SHA-256+LF receipt outside software directory", False, True),
    ), "Save an original exact-byte local ZIP fingerprint; separate HUMAN disclosure approval is required."),
    "receive-software": ("install.py", ("receive",), (
        ("--archive", "Original software-only ZIP", False, True),
        ("--output-dir", "NEW owner-private software installation", False, True),
        ("--expected-sha256-file", "Optional SEPARATELY obtained PRIVATE 0600 exact ZIP SHA-256 fingerprint file", False, False),
    ), "Pinned source admission plus optional separately supplied transfer hash, no identity claim."),
    "inspect-software": ("install.py", ("inspect",), (
        ("--workspace", "Existing private software-only suite", False, True),
    ), "Local consistency inspection only; not CI/release approval."),
    "inspect-checkout": ("install.py", ("inspect", "--compare-checkout"), (
        ("--workspace", "Existing private software-only suite", False, True),
        ("--report-dir", "NEW owner-only reproducibility passport directory", False, True),
    ), "Verify source/ZIP parity and publish PRIVATE HUMAN-only HTML/JSON passport."),
    "reopen-passport": ("install.py", ("inspect", "--compare-checkout"), (
        ("--workspace", "Existing original PRIVATE software-only suite", False, True),
        ("--passport-dir", "Existing original PRIVATE reproducibility passport", False, True),
    ), "Re-admit native PRIVATE passport HTML/JSON byte-for-byte against its installed software."),
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
                entered = input(f"{label} (blank ends list): ")
                # Never rewrite literal private paths. Whitespace-only input
                # is not an explicit empty terminator and a changed path is
                # not authorized evidence.
                if entered != entered.strip():
                    raise ValueError("Original HUMAN path has leading/trailing whitespace: " + flag)
                if not entered:
                    break
                found.append(entered)
            if required and not found:
                raise ValueError("Required original input missing: " + flag)
            values[flag] = found
        else:
            entered = input(f"{label}{' [required]' if required else ' [optional]'}: ")
            if entered != entered.strip():
                raise ValueError("Original HUMAN path has leading/trailing whitespace: " + flag)
            if required and not entered:
                raise ValueError("Required original input missing: " + flag)
            values[flag] = entered or None
    print("\nAction:", name, "\n" + WARNING)
    if input("Start native offline action now? Type YES: ").strip() != "YES":
        print("Cancelled; no original file changed.")
        return None
    return name, values

def dispatch(name: str, values: dict) -> None:
    # Apply the same native Unicode/bidi/terminal-control HOLD to ALL HUMAN
    # source and output paths, including non-software offline operations,
    # before any original producer operation or private side effect starts.
    from install import require_operator_path
    module, prefix, options, _ = OPERATIONS[name]
    arguments = [str(ROOT / module), *prefix]
    for flag, _, repeat, required in options:
        raw = values.get(flag)
        items = (raw or []) if repeat else ([raw] if raw else [])
        if required and not items:
            raise ValueError("Missing required original input: " + flag)
        for item in items:
            # Validate the HUMAN's literal spelling BEFORE pathlib can
            # normalize /./ or the implementation-defined leading //.
            # Do not silently pass a changed path to native source admission.
            if (type(item) is not str or not item.startswith("/") or
                    item.startswith("//") or
                    any(segment in (".", "..") for segment in item.split("/"))):
                raise ValueError("Use one literal absolute path without . or ..: " + flag)
            path = Path(item)
            require_operator_path(path)
            arguments.extend((flag, item))
    if name in ("owner", "owner-package", "owner-encrypted", "owner-encrypted-receipt") and not (values.get("--input-dir") or values.get("--bundle")):
        raise ValueError("Select actual original private evidence inputs")
    if name == "archives" and not (values.get("--archive") or values.get("--encrypted-archive")):
        raise ValueError("Select actual received original archive(s)")
    if name == "archives" and bool(values.get("--archive")) == bool(values.get("--encrypted-archive")):
        raise ValueError("Choose exactly one original source-free archive type; original native CLI rejects mixed modes")
    if name in ("fingerprint-create", "fingerprint-compare"):
        packets = values.get("--packet") or []
        if not 1 <= len(packets) <= 8 or len(set(packets)) != len(packets):
            raise ValueError("Choose 1–8 distinct original PRIVATE packet files")
    if name == "pack-review" and bool(values.get("--journal")) == bool(values.get("--journal-vault")):
        raise ValueError("Choose exactly one original source-bound HUMAN journal form")
    if name in ("owner-package", "owner-encrypted", "owner-encrypted-receipt"):
        # Explicit composition of two ORIGINAL bounded source admissions.
        from workflow import owner_start
        from portable_cockpit import pack as native_pack
        if name in ("owner-encrypted", "owner-encrypted-receipt"):
            if not sys.stdin.isatty():
                raise ValueError("Encrypted HUMAN owner handoff requires a PRIVATE interactive terminal")
            try:
                from cryptography.hazmat.primitives.ciphers.aead import AESGCM
            except ImportError as exc:
                raise ValueError("Optional native AES-GCM dependency is missing") from exc
        owner_dest = Path(values["--output-dir"])
        packet_dest = Path(values["--output-file"])
        # Reject confusing plaintext/encrypted filename identities before any
        # private owner output is created. Existing native file gates remain.
        expected_suffix = ".luhx" if name in ("owner-encrypted", "owner-encrypted-receipt") else ".luhz"
        if packet_dest.suffix != expected_suffix:
            raise ValueError("Separate source-free packet must use " + expected_suffix)
        if name == "owner-encrypted-receipt":
            receipt_dest = Path(values["--receipt-file"])
            if (receipt_dest.suffix != ".json" or receipt_dest == packet_dest
                    or receipt_dest == owner_dest or owner_dest in receipt_dest.parents):
                raise ValueError("Unsigned JSON fingerprint receipt must be NEW, separate and outside original owner workroom")
            if (receipt_dest.exists() or receipt_dest.is_symlink()
                    or receipt_dest.parent != receipt_dest.parent.resolve(strict=True)):
                raise ValueError("Choose a NEW literal private receipt path, not a symlink")
        original_dirs = [Path(x) for x in values.get("--input-dir", [])]
        original_bundles = [Path(x) for x in values.get("--bundle", [])]
        original_sources = [*original_dirs, *original_bundles]
        if packet_dest == owner_dest or owner_dest in packet_dest.parents:
            raise ValueError("SOURCE-FREE packet must remain OUTSIDE ORIGINAL owner evidence")
        if any(packet_dest == source or source in packet_dest.parents
               or packet_dest in source.parents for source in original_sources):
            raise ValueError("SOURCE-FREE packet cannot overwrite or enter original PRIVATE input evidence")
        # Check the separate native destination BEFORE original-owner creation.
        # This avoids creating a complete owner workroom when the intended
        # transfer destination was already occupied or is not owner-private.
        from install import owner_dir as original_owner_dir
        if packet_dest.exists() or packet_dest.is_symlink():
            raise ValueError("Choose a NEW, nonexistent private recipient packet path")
        if packet_dest.parent != packet_dest.parent.resolve(strict=True):
            raise ValueError("Recipient output parent must be literal, not a symlink")
        original_owner_dir(packet_dest.parent)
        if name == "owner-encrypted-receipt":
            if any(receipt_dest == source or source in receipt_dest.parents
                   or receipt_dest in source.parents for source in original_sources):
                raise ValueError("Unsigned byte receipt cannot enter or replace original PRIVATE evidence")
            original_owner_dir(receipt_dest.parent)
        print("Preparing private ORIGINAL owner workroom. No packet transmitted.", flush=True)
        owner_start(original_dirs, original_bundles, owner_dest)
        print("Re-admitting the separate native SOURCE-FREE folder.", flush=True)
        if name in ("owner-encrypted", "owner-encrypted-receipt"):
            from encrypted_cockpit import encrypt as native_encrypt
            native_encrypt(owner_dest / "source-free-recipient", packet_dest)
            if name == "owner-encrypted-receipt":
                import packet_fingerprint
                receipt_items = packet_fingerprint.fresh([packet_dest])
                packet_fingerprint.single_review.review.private_publish(
                    receipt_dest,
                    packet_fingerprint.install.canonical(packet_fingerprint.document(receipt_items)))
                print("REVIEW_ONLY: separate PRIVATE unsigned exact-byte SHA-256 receipt created.")
                print("Both files require real separate operator/client disclosure consent before transfer.")
            print("REVIEW_ONLY: encrypted source-free packet created WITHOUT plaintext ZIP.")
        else:
            native_pack(owner_dest / "source-free-recipient", packet_dest)
            print("REVIEW_ONLY: unsigned unencrypted packet, do not disclose without approval.")
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
