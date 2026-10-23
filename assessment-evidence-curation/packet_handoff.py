#!/usr/bin/env python3
"""Package one PRIVATE HUMAN priority question sheet without the full lab dossier.

This is local filesystem preparation, not disclosure, recipient authentication,
source trust, client/operator consent, or remediation. All hashes are UNSIGNED.
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import os
from pathlib import Path
import stat
import sys

from curate import Hold, PRIORITIES, UNVERIFIED, digest, json_bytes
from packet_open import MAX_JSON, json_private, read_private, reopen as admit_original
from briefing import CSS, h, publish_new

SCHEMA = "lightup.private_minimum_necessary_human_handoff.v1"
RECEIPT = "PRIVATE-priority-handoff-receipt.json"
GUIDE = "OPEN-PRIVATE-handoff.html"
QUESTIONS = "PRIVATE-selected-HUMAN-questions.html"
TEMPLATE = "PRIVATE-recipient-HUMAN-reply-template.csv"
STUDIO = "PRIVATE-HUMAN-reply-studio.html"
FLAGS = {
    "recipient_authenticated": False,
    "disclosure_authorized": False,
    "actually_disclosed": False,
    **UNVERIFIED,
}


def require(ok: bool) -> None:
    if not ok:
        raise Hold("HOLD: selected PRIVATE HUMAN handoff refused")


def guide(priority: str, count: int) -> bytes:
    css_pin = base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + css_pin +
           "'; script-src 'none'; connect-src 'none'; img-src 'none'; "
           "object-src 'none'; form-action 'none'; base-uri 'none'")
    result = (
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>" +
        '<meta http-equiv="Content-Security-Policy" content="' + h(csp) + '">' +
        "<meta name='viewport' content='width=device-width,initial-scale=1'>" +
        "<title>PRIVATE HUMAN priority handoff</title><style>" + CSS +
        "</style></head><body><header><h1>LightUp · PRIVATE HUMAN priority handoff</h1>" +
        "<p class='notice'>HOLD / REVIEW ONLY · INCUBATE M3/M7 PLAN/LAB ONLY. "
        "This is a copied human question sheet, not a source authentication, "
        "verified finding, valid scope, remediation, consent, authorization, "
        "human-recipient identity or actual dispatch.</p>" +
        "<p>Chosen HUMAN priority: <strong>" + h(priority) +
        "</strong>; questions in this group: " + str(count) + ".</p>" +
         "<p><a href='" + STUDIO + "'>Open the fully offline PRIVATE HUMAN reply editor</a> "
        "to prepare the complete exact-source CSV locally, without uploading it.</p>" +
        "<p>Download the PRIVATE reply CSV next to this guide; preserve the "
        "five original HUMAN question columns and edit only recipient stage, "
        "reply and next question. Returned files still require native source-"
        "bound review. The CSV never contains original target or evidence.</p>" +
        "<p>This package deliberately does NOT contain the full original "
        "finding report, original target data, other priorities, original "
        "source or private parent directory. Its questions and count STILL "
        "may reveal private customer information. It is not public-safe.</p>" +
        "<p><a href='" + QUESTIONS +
        "'>Open only the selected PRIVATE HUMAN question sheet</a>.</p>" +
        "<p>Independent human recipient verification and current disclosure "
        "authorization are mandatory before separately sending anything. "
        "The unsigned receipt checks local bytes only. No recipient was contacted.</p>" +
        "</header></body></html>\n"
    )
    return result.encode("utf-8")


def prepare(source_dir: str, priority: str, output_dir: str) -> int:
    require(priority in PRIORITIES)
    require(not Path(source_dir).is_symlink())
    source_real = Path(source_dir).resolve(strict=True)
    output_real = Path(output_dir).resolve(strict=False)
    require(output_real != source_real and not output_real.is_relative_to(source_real))
    # Original source has already been built; reopen does no scanner/model/network work.
    admit_original(str(source_real))
    fd = -1
    try:
        fd = os.open(source_real, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        metadata = os.fstat(fd)
        require(stat.S_ISDIR(metadata.st_mode) and metadata.st_uid == os.getuid() and
                stat.S_IMODE(metadata.st_mode) == 0o700)
        original_raw = read_private(fd, "PRIVATE-curation-receipt.json", MAX_JSON)
        original_receipt = json_private(original_raw)
        counts = json_private(read_private(fd, "anonymous-counts-PRIVATE.json", MAX_JSON))
        require(counts["schema"] == "lightup.private_curated_lab_aggregate.v1")
        count = counts["human_selected_priority_counts"][priority]
        require(type(count) is int and count > 0 and count <= 64)
        source_filename = "PRIVATE-HUMAN-" + priority + "-priority.html"
        question_bytes = read_private(fd, source_filename)
        require(digest(question_bytes) ==
                original_receipt["private_priority_handoff_sha256_unsigned"][priority])
        template_name = "PRIVATE-HUMAN-" + priority + "-reply-template.csv"
        template_bytes = read_private(fd, template_name)
        require(digest(template_bytes) ==
                original_receipt["private_priority_reply_template_sha256_unsigned"][priority])
        from priority_reply_studio import render as render_reply_studio
        studio_bytes = render_reply_studio(template_bytes)
        guide_bytes = guide(priority, count)
        receipt = {
            "schema": SCHEMA,
            "status": "REVIEW_ONLY",
            "original_private_packet_receipt_sha256_unsigned": digest(original_raw),
            "source_human_priority": priority,
            "selected_human_question_count": count,
            "private_selected_handoff_sha256_unsigned": digest(question_bytes),
            "private_reply_template_sha256_unsigned": digest(template_bytes),
            "private_reply_studio_sha256_unsigned": digest(studio_bytes),
            "private_guide_sha256_unsigned": digest(guide_bytes),
            **FLAGS,
        }
        # Exclusivity and private modes are enforced by original publish_new.
        publish_new(output_dir, {
            GUIDE: guide_bytes,
            QUESTIONS: question_bytes,
            TEMPLATE: template_bytes,
            STUDIO: studio_bytes,
            RECEIPT: json_bytes(receipt),
        })
        return count
    finally:
        if fd >= 0:
            os.close(fd)


def reopen(source_dir: str) -> int:
    fd = -1
    try:
        fd = os.open(source_dir, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                     getattr(os, "O_NOFOLLOW", 0))
        before = os.fstat(fd)
        require(stat.S_ISDIR(before.st_mode) and before.st_uid == os.getuid() and
                stat.S_IMODE(before.st_mode) == 0o700)
        require(set(os.listdir(fd)) == {GUIDE, QUESTIONS, TEMPLATE, STUDIO, RECEIPT})
        raw = read_private(fd, RECEIPT, MAX_JSON)
        receipt = json_private(raw)
        expected = {
            "schema", "status", "original_private_packet_receipt_sha256_unsigned",
            "source_human_priority", "selected_human_question_count",
            "private_selected_handoff_sha256_unsigned",
            "private_guide_sha256_unsigned",
            "private_reply_template_sha256_unsigned",
            "private_reply_studio_sha256_unsigned", *FLAGS,
        }
        require(type(receipt) is dict and set(receipt) == expected and
                receipt["schema"] == SCHEMA and receipt["status"] == "REVIEW_ONLY" and
                all(receipt[k] is False for k in FLAGS))
        require(receipt["source_human_priority"] in PRIORITIES)
        count = receipt["selected_human_question_count"]
        require(type(count) is int and 1 <= count <= 64)
        for key in ("original_private_packet_receipt_sha256_unsigned",
                    "private_selected_handoff_sha256_unsigned",
                    "private_guide_sha256_unsigned",
                    "private_reply_template_sha256_unsigned",
                    "private_reply_studio_sha256_unsigned"):
            sha = receipt[key]
            require(type(sha) is str and len(sha) == 64 and
                    all(c in "0123456789abcdef" for c in sha))
        require(digest(read_private(fd, GUIDE)) ==
                receipt["private_guide_sha256_unsigned"])
        require(digest(read_private(fd, QUESTIONS)) ==
                receipt["private_selected_handoff_sha256_unsigned"])
        require(digest(read_private(fd, TEMPLATE)) ==
                receipt["private_reply_template_sha256_unsigned"])
        require(digest(read_private(fd, STUDIO)) ==
                receipt["private_reply_studio_sha256_unsigned"])
        return count
    finally:
        if fd >= 0:
            os.close(fd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Private single-priority HUMAN question handoff; never sends or authorizes")
    sub = parser.add_subparsers(dest="action", required=True)
    prepare_cmd = sub.add_parser("prepare", help="make new owner-private question-only handoff")
    prepare_cmd.add_argument("--private-dir", required=True, help="existing entire curated packet")
    prepare_cmd.add_argument("--priority", required=True, choices=PRIORITIES)
    prepare_cmd.add_argument("--output-dir", required=True, help="NEW output folder, no overwrite")
    read_cmd = sub.add_parser("reopen", help="check newly prepared handoff's local bytes")
    read_cmd.add_argument("--private-dir", required=True, help="existing selected handoff")
    args = parser.parse_args()
    try:
        if args.action == "prepare":
            amount = prepare(args.private_dir, args.priority, args.output_dir)
        else:
            amount = reopen(args.private_dir)
    except (Hold, ValueError, TypeError, KeyError, OSError, UnicodeError,
            OverflowError, RecursionError, MemoryError):
        print("HOLD: PRIVATE handoff refused; neither authorization nor validation", file=sys.stderr)
        return 3
    print("PRIVATE local human handoff REVIEW_ONLY, count: " + str(amount) +
          ". NO source authentication, recipient approval, consent, dispatch or scan.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
