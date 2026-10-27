#!/usr/bin/env python3
"""Complete encrypted native .luhp HUMAN handoff -> integrated PRIVATE planner.

Consume ORIGINAL review_package encrypted source-free Cockpit + exact bound
HUMAN journal, with no unencrypted ZIP or journal intermediate. Never accept
client source evidence, invent lineage, grant authority or access any network.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import sys
import zipfile

import schedule
import single_review

sys.path.insert(0, str(schedule.PARENT / "remediation-integrated-workspace"))
import install
import portable_cockpit
import review_package
import workflow
import journal_vault

review = single_review.review
WARNING = (
    "PRIVATE HUMAN-only original source-free review. Encrypted transport does not "
    "authenticate sender/client, historical source order, current independent "
    "consent, recipient permission, real finding, fix, retest, release or grant. "
    "INCUBATE M3/M7 PLAN/LAB ONLY DRAFT/HOLD."
)


def require(condition: bool, explanation: str) -> None:
    review.require(condition, explanation)


def prepare(archives: list[Path], output: Path) -> None:
    require(1 <= len(archives) <= schedule.MAX_SOURCES and
            len(set(archives)) == len(archives),
            "Require 1–12 distinct native encrypted original review packages")
    require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
            and not output.exists() and not output.is_symlink(),
            "Choose a fresh literal absolute owner-private output folder")
    install.owner_dir(output.parent)
    originals: list[bytes] = []
    seen: set[bytes] = set()
    for path in archives:
        require(path.is_absolute() and
                path.parent == path.parent.resolve(strict=True) and
                path != output and path.parent != output and
                output not in path.parents and path not in output.parents,
                "Encrypted original handoff may not overlap private destination")
        raw = review_package.incoming(path)
        fingerprint = hashlib.sha256(raw).digest()
        require(fingerprint not in seen,
                "Repeated identical encrypted package cannot create another HUMAN record")
        seen.add(fingerprint)
        originals.append(raw)

    stage = output.parent / (".lightup-complete-human-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        packets: list[Path] = []
        journals: list[bytes] = []
        source_keys: set[str] = set()
        for index, (path, encrypted) in enumerate(zip(archives, originals), 1):
            # Use the exact ORIGINAL authenticated-encryption and nested native
            # source-free validators. No plaintext original ZIP is ever written.
            phrase = review_package.crypto.password(False)
            source_zip, human_json = review_package.unpack_inner(
                review_package.open_sealed(encrypted, phrase))
            native = stage / f"original-sourcefree-{index:02d}"
            portable_cockpit.unpack_bytes(
                source_zip, native,
                lambda path=path, encrypted=encrypted:
                    review_package.incoming(path) == encrypted)
            journal_vault.original(native, human_json)
            rows, key, _, _ = single_review.original(native)
            single_review.admit_journal(human_json, rows, key)
            require(key not in source_keys,
                    "Duplicate source-free original packet cannot fabricate chronology")
            source_keys.add(key)
            packets.append(native)
            journals.append(human_json)

        sources, tasks = schedule.source_records([str(p) for p in packets], [])
        for ordinal, (packet, native_journal) in enumerate(zip(packets, journals), 1):
            raw_rows, source_key, _, _ = single_review.original(packet)
            original = single_review.admit_journal(native_journal, raw_rows, source_key)
            prior = {(r["slot"], r["reason"], r["count"]):r for r in original}
            for task in tasks:
                if task["packet"] == ordinal:
                    record = prior[(task["slot"], task["reason"], task["count"])]
                    task["stage"] = record["stage"]
                    task["human_note"] = record["note"]

        # Original source-free HUMAN reviewer kept independent and unchanged.
        workflow.recipient_start(packets, stage / "original-human-review")
        # For every real original encrypted package, also expose the unchanged
        # source-bound one-Cockpit reviewer, including its native HUMAN notes.
        for i, (packet, human_json) in enumerate(zip(packets, journals), 1):
            single_review.publish(
                packet, stage / f"original-human-journal-{i:02d}",
                None, journal_bytes=human_json)

        browser = stage / "human-scheduler"
        os.mkdir(browser, 0o700)
        schedule.private_write(browser, "index.html", schedule.render(sources, tasks))
        schedule.private_write(browser, "README.txt", (
            WARNING + "\nOriginal source-free per-packet HUMAN journals are "
            "separately displayed in private source-bound original reviewers. "
            "DO NOT transmit recipient folders without separate real disclosure permission.\n"
        ).encode("utf-8"))

        # Landing page contains only static software navigation. No original
        # source hashes, recipient identities, comments or raw sensitive notes.
        links = [
            ("Open source-bound HUMAN task planner",
             "human-scheduler/index.html",
             "Private HUMAN owner/queue/deadline board, encrypted local checkpoint."),
            ("Open unchanged original native HUMAN recipient view",
             "original-human-review/index.html",
             "Complete original source-free ordinal HUMAN reviewer."),
        ]
        for i in range(1,len(packets)+1):
            links.append((
                f"Open original source-bound HUMAN journal {i:02d}",
                f"original-human-journal-{i:02d}/index.html",
                "Private HUMAN notes for exactly one original source-free packet; no verified fix."))
        links.append((
            "View first received original source-free Cockpit",
            "original-sourcefree-01/index.html",
            "Original source-free counts only, not verified evidence."))
        install.write_file(stage / "index.html", workflow.page(
            "PRIVATE source-free original HUMAN review + scheduling",
            links,
            WARNING + " The owner-private output contains decrypted HUMAN notes "
            "in plaintext 0600 files. Do not forward without actual independently "
            "verified recipient permission."))
        schedule.private_write(stage, "private-summary.json",
            schedule.canonical({
                "kind": "lightup.private_complete_human_scheduler",
                "version": 1, "disposition": "HUMAN_ONLY_DRAFT_HOLD",
                "authority_granted": False, "consent_verified": False,
                "remediation_verified": False, "authenticated_sender": False,
                "authenticated_time_order": False,
                "original_complete_handoff_count": len(packets),
                "original_sourcefree_human_groups": len(tasks),
                "decrypted_human_notes_present": True,
                "warning": WARNING,
            }))
        # Recheck every original ciphertext immediately before private publish.
        require(all(review_package.incoming(p) == raw
                    for p,raw in zip(archives, originals)),
                "Native encrypted complete source-free handoff changed during intake")
        require(not output.exists(), "Independent recipient output appeared")
        workflow.workspace.exclusive_dir_publish(stage, output)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("REVIEW_ONLY: complete original encrypted HUMAN handoff scheduler:",output)
    print("Original source-free packets:", len(packets))
    print("HUMAN-only reason groups:", len(tasks))
    print("Output includes PRIVATE decrypted HUMAN text; no consent or remediation authority.")


def main() -> int:
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--review-package", type=Path, action="append", required=True,
                        help="Native encrypted .luhp with exact source-bound HUMAN journal; repeat 1–12")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="New absolute owner-only folder below existing private 0700 parent")
    a=parser.parse_args()
    try:
        prepare(a.review_package, a.output_dir)
        return 2
    except (review.Hold, install.Hold, ValueError, OSError, TypeError,
            KeyError, zipfile.BadZipFile, EOFError, ImportError,
            UnicodeError, RuntimeError) as exc:
        print("HOLD: original complete PRIVATE source-free HUMAN handoff:",exc,
              file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
