#!/usr/bin/env python3
"""Offline full PRIVATE source-free recipient intake with HUMAN schedule.

Only unchanged native LightUp archive/crypto/source-free admission is used.
Neither this tool nor source-free counts prove sender, consent, findings,
remediation, client identity or any authorization to perform assessment.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import shutil
import sys
import zipfile

import schedule
import single_review

sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import archive_workflow
import encrypted_cockpit
import install
import journal_vault
import portable_cockpit
import workflow

review = single_review.review
MAX_SOURCES = schedule.MAX_SOURCES
WARNING = (
    "PRIVATE offline original source-free HUMAN follow-up and manual scheduling. "
    "This is NOT an authenticated source/client, verified finding, consent, "
    "actual remediation or retest, grant, approval, authorized disclosure, "
    "or chronology; INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD."
)


def require(condition: bool, explanation: str) -> None:
    review.require(condition, explanation)


def original_archive(path: Path, encrypted: bool) -> bytes:
    require(path.is_absolute() and not path.is_symlink()
            and path.parent == path.parent.resolve(strict=True),
            "Private original archive needs an absolute literal path")
    install.owner_dir(path.parent)
    raw = (encrypted_cockpit.private_envelope(path)
           if encrypted else install.read_owner_file(path))
    bound = (encrypted_cockpit.MAX_ENVELOPE if encrypted
             else portable_cockpit.MAX_ZIP)
    require(0 < len(raw) <= bound, "Original source-free private transfer exceeds bound")
    return raw


def human_sources(received: list[Path], journals: list[str],
                  vaults: list[str]) -> tuple[list[dict], list[dict]]:
    paths = [str(path) for path in received]
    if journals:
        return schedule.source_records(paths, journals)
    sources, tasks = schedule.source_records(paths, [])
    if vaults:
        for index, (cockpit, name) in enumerate(zip(received, vaults), 1):
            if name == "-":
                continue
            require(Path(name).is_absolute(), "Encrypted HUMAN vault requires absolute path")
            raw = journal_vault.unseal(cockpit, Path(name))  # Native AES-GCM, memory only.
            original, source_key, _, _ = single_review.original(cockpit)
            require(sources[index - 1]["source_sha256"] == source_key,
                    "Original source-free packet changed after encrypted HUMAN admission")
            restored = single_review.admit_journal(raw, original, source_key)
            updates = {(row["slot"], row["reason"], row["count"]): row
                       for row in restored}
            for task in tasks:
                if task["packet"] == index:
                    row = updates[(task["slot"], task["reason"], task["count"])]
                    task["stage"] = row["stage"]
                    task["human_note"] = row["note"]
    return sources, tasks


def prepare(archives: list[Path], dest: Path, encrypted: bool,
            journals: list[str], vaults: list[str]) -> None:
    require(1 <= len(archives) <= MAX_SOURCES
            and len(set(archives)) == len(archives),
            "Require 1–12 distinct complete original native source-free archives")
    require(not (journals and vaults)
            and (not journals or len(journals) == len(archives))
            and (not vaults or len(vaults) == len(archives)),
            "One corresponding native HUMAN journal/vault or '-' per source-free archive")
    require(dest.is_absolute() and dest.parent == dest.parent.resolve(strict=True)
            and not dest.exists() and not dest.is_symlink(),
            "Recipient destination must be a new literal absolute directory")
    install.owner_dir(dest.parent)
    input_files = archives + [Path(p) for p in journals + vaults if p != "-"]
    require(all(p.is_absolute() and p != dest and
                p.parent != dest and dest not in p.parents and
                p not in dest.parents for p in input_files),
            "Private input and destination locations cannot overlap")
    before: list[bytes] = []
    seen: set[bytes] = set()
    for path in archives:
        raw = original_archive(path, encrypted)
        digest = hashlib.sha256(raw).digest()
        require(digest not in seen, "Identical private archive cannot represent another revision")
        seen.add(digest)
        before.append(digest)

    stage = dest.parent / (".lightup-recipient-plan-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        received: list[Path] = []
        for i, file in enumerate(archives, 1):
            target = stage / f"original-sourcefree-{i:02d}"
            if encrypted:
                encrypted_cockpit.decrypt(file, target)
            else:
                portable_cockpit.unpack(file, target)
            received.append(target)
        sources, tasks = human_sources(received, journals, vaults)

        # Create the complete ORIGINAL pre-existing recipient experience,
        # separately from our new editable human schedule. No source owner edits.
        workflow.recipient_start(received, stage / "original-human-review")

        browser = stage / "human-scheduler"
        os.mkdir(browser, 0o700)
        page = schedule.render(sources, tasks)
        schedule.private_write(browser, "index.html", page)
        schedule.private_write(browser, "README.txt",
            (WARNING + "\nEncrypted .lurp or printable agenda remain PRIVATE. "
             "The original received source-free Cockpit and imported HUMAN notes "
             "do not prove permission to share or remediate.\n").encode("utf-8"))

        # Do not copy any full source packet identifiers or HUMAN notes to
        # the top-level report or index; the scheduler itself is PRIVATE.
        summary = {
            "kind": "lightup.private_sourcefree_human_schedule_intake",
            "version": 1,
            "disposition": "REVIEW_ONLY_DRAFT_HOLD",
            "authority_granted": False,
            "consent_verified": False,
            "remediation_verified": False,
            "authenticated_sender": False,
            "archive_order": "HUMAN_SELECTED_NOT_AUTHENTICATED",
            "private_sourcefree_packets": len(sources),
            "private_human_reason_groups": len(tasks),
            "original_journal_imports": sum(x != "-" for x in journals),
            "encrypted_journal_imports": sum(x != "-" for x in vaults),
            "warning": WARNING,
        }
        schedule.private_write(stage, "private-summary.json", schedule.canonical(summary))
        index = workflow.page(
            "PRIVATE native source-free recipient review and HUMAN schedule",
            [
                ("Open source-free HUMAN scheduling dashboard",
                 "human-scheduler/index.html",
                 "Owner, stage, tentative deadlines, selected-only HUMAN plan, "
                 "encrypted private checkpoint and agenda."),
                ("Open unchanged original native HUMAN reviewer",
                 "original-human-review/index.html",
                 "Original whole source-free Cockpit admission, original HUMAN "
                 "source-free review and anonymous series."),
                ("Open first unmodified received source-free Cockpit",
                 "original-sourcefree-01/index.html",
                 "Original full native source-free packet, not verified evidence."),
            ],
            WARNING + " The scheduler can contain PRIVATE human names and notes; "
            "neither the entire folder nor screenshots are shareable without "
            "separate real recipient permission."
        )
        install.write_file(stage / "index.html", index)
        for p, previous in zip(archives, before):
            require(hashlib.sha256(original_archive(p, encrypted)).digest() == previous,
                    "Original encrypted/source-free archive changed during PRIVATE intake")
        # Concurrent pre-existing destination must never be overwritten.
        require(not dest.exists(), "Output appeared during private source admission")
        workflow.workspace.exclusive_dir_publish(stage, dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)

    print("REVIEW_ONLY: new PRIVATE integrated recipient scheduler:", dest / "index.html")
    print("Original source-free Cockpit packets:", len(archives))
    print("Human-only source-free reason groups:", len(tasks))
    print("No consent, authority, verified finding, remediation or release was asserted.")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--archive", action="append", type=Path,
                       help="Native unencrypted source-free .luhz in owner-only directory; repeat")
    group.add_argument("--encrypted-archive", action="append", type=Path,
                       help="Native encrypted source-free .luhx; prompts locally for passphrase")
    human = parser.add_mutually_exclusive_group()
    human.add_argument("--journal", action="append", default=[],
                       help="Native original source-bound HUMAN JSON; one per archive or '-'")
    human.add_argument("--journal-vault", action="append", default=[],
                       help="Native original source-bound encrypted .luhj; one per archive or '-'")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh absolute private destination under existing 0700 parent")
    a = parser.parse_args()
    try:
        prepare(a.encrypted_archive or a.archive, a.output_dir,
                a.encrypted_archive is not None, a.journal, a.journal_vault)
        return 2
    except (review.Hold, install.Hold, OSError, ValueError, TypeError, KeyError,
            zipfile.BadZipFile, ImportError, RuntimeError, EOFError, UnicodeError) as exc:
        print("HOLD: PRIVATE source-free archive/schedule admission refused: " +
              str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
