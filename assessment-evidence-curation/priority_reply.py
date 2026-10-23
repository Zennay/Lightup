#!/usr/bin/env python3
"""Offline HUMAN return of exactly one PRIVATE minimum-necessary priority packet.

No recipient identity check, target action, original assessment, release, real
consent, dispatch, remediation claim or privileged file mutation occurs.
"""
from __future__ import annotations

import argparse
import csv
import io
import os
import stat
import sys

from briefing import h, json_bytes, publish_new
from curate import Hold, digest, human_text_ok
from human_return import read_limited_file
from packet_handoff import RECEIPT, TEMPLATE, reopen as admit_handoff
from packet_open import MAX_JSON, json_private, read_private
from response import HEADER, STAGES
from revision import private_frame

MAX_RETURN_BYTES = 64 * 1024
REPORT = "PRIVATE-HUMAN-recipient-return.html"
RECEIPT_OUT = "PRIVATE-HUMAN-recipient-return-receipt.json"
COUNTS = "PRIVATE-HUMAN-recipient-return-counts.json"
UNTRUSTED_FLAGS = {
    "source_authenticated": False, "recipient_authenticated": False,
    "client_consent_verified": False, "operator_consent_verified": False,
    "finding_verified": False, "remediation_verified": False,
    "disclosure_authorized": False, "actually_disclosed": False,
}


def require(condition: bool) -> None:
    if not condition:
        raise Hold("HOLD: PRIVATE HUMAN return source-bound admission refused")


def admit_rows(template: bytes, returned: bytes) -> list[dict]:
    def parse(raw: bytes) -> list[list[str]]:
        try:
            text = raw.decode("utf-8-sig")
            require("\x00" not in text and "\r" not in text.replace("\r\n", ""))
            reader = csv.reader(io.StringIO(text, newline=""), strict=True)
            require(tuple(next(reader)) == HEADER)
            rows = list(reader)
            require(1 <= len(rows) <= 64)
            require(all(len(row) == len(HEADER) for row in rows))
            return rows
        except (csv.Error, StopIteration, UnicodeDecodeError):
            raise Hold("HOLD: invalid PRIVATE recipient CSV") from None

    original = parse(template)
    actual = parse(returned)
    require(len(original) == len(actual))
    final = []
    for base, current in zip(original, actual):
        require(base[:5] == current[:5] and not any(base[5:]))
        require(current[5] in STAGES and
                human_text_ok(current[6]) and human_text_ok(current[7]))
        if current[5] == "":
            require(current[6] == current[7] == "")
        elif current[5] == "responded_claimed":
            require(bool(current[6].strip()))
        else:
            require(bool(current[6].strip()) or bool(current[7].strip()))
        final.append({
            "ordinal": current[0], "source_severity": current[1],
            "source_reference_count": current[2],
            "human_priority": current[3], "question": current[4],
            "recipient_stage": current[5] or "no_human_response",
            "recipient_reply": current[6], "recipient_next_question": current[7],
        })
    return final


def printable(rows: list[dict]) -> bytes:
    cards = []
    for row in rows:
        blocks = (
            ("Source reported severity (UNVERIFIED)", row["source_severity"]),
            ("Source evidence reference count", row["source_reference_count"]),
            ("HUMAN priority", row["human_priority"]),
            ("Original PRIVATE HUMAN question", row["question"]),
            ("Recipient self-reported stage (UNVERIFIED)", row["recipient_stage"]),
            ("Recipient HUMAN reply (UNVERIFIED)", row["recipient_reply"]),
            ("Recipient HUMAN next question", row["recipient_next_question"]),
        )
        cells = "".join("<dt>" + h(label) + "</dt><dd><pre>" + h(value) +
                        "</pre></dd>" for label, value in blocks)
        cards.append("<article><h2>Original ordinal #" + h(row["ordinal"]) +
                     "</h2><dl>" + cells + "</dl></article>")
    return private_frame(
        "PRIVATE priority recipient HUMAN return — unverified",
        "<header><h1>LightUp · PRIVATE priority HUMAN return</h1>"
        "<p class='notice'>REVIEW ONLY / HOLD. Recipient statements, identities, "
        "original findings, producer, consent, scope, remediation, disclosure "
        "approval and independent evidence have NOT been verified. The file was "
        "read offline; no response was sent to the original sender or target.</p>"
        "<p>Only the selected priority's original question rows and HUMAN "
        "responses are included. Human questions/replies may identify a client "
        "and need separately authenticated disclosure approval.</p>"
        "<p>Signed identity proof: NONE. Original source and exact "
        "client/operator consent must be independently verified outside this "
        "offline tool before any consequential action.</p></header>" + "".join(cards)
    )


def receive(private_handoff: str, returned_csv: str, output_dir: str) -> int:
    require(not os.path.samefile(private_handoff, output_dir)
            if os.path.exists(output_dir) else True)
    # Admission of all prior local 0600 bytes and exact inventory happens first.
    count = admit_handoff(private_handoff)
    dfd = -1
    try:
        dfd = os.open(private_handoff, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) |
                      getattr(os, "O_NOFOLLOW", 0))
        info = os.fstat(dfd)
        require(stat.S_ISDIR(info.st_mode) and info.st_uid == os.getuid() and
                stat.S_IMODE(info.st_mode) == 0o700)
        old_receipt = read_private(dfd, RECEIPT, MAX_JSON)
        handoff = json_private(old_receipt)
        source_template = read_private(dfd, TEMPLATE, MAX_RETURN_BYTES)
        incoming = read_limited_file(returned_csv, MAX_RETURN_BYTES)
        require(digest(source_template) == handoff["private_reply_template_sha256_unsigned"])
        rows = admit_rows(source_template, incoming)
        require(len(rows) == count)
        require(all(row["human_priority"] == handoff["source_human_priority"] for row in rows))
        report = printable(rows)
        numbers = {
            "schema": "lightup.private_priority_human_return_counts.v1",
            "status": "REVIEW_ONLY",
            "human_reply_row_count": count,
            "human_recipient_stage_counts": {
                stage or "no_human_response":
                    sum(row["recipient_stage"] == (stage or "no_human_response") for row in rows)
                for stage in STAGES
            },
            **UNTRUSTED_FLAGS,
        }
        receipt = {
            "schema": "lightup.private_priority_human_return.v1",
            "status": "REVIEW_ONLY",
            "original_handoff_receipt_sha256_unsigned": digest(old_receipt),
            "original_blank_response_template_sha256_unsigned": digest(source_template),
            "human_returned_csv_sha256_unsigned": digest(incoming),
            "private_human_report_sha256_unsigned": digest(report),
            "private_human_counts_sha256_unsigned": digest(json_bytes(numbers)),
            "human_reply_row_count": count,
            **UNTRUSTED_FLAGS,
        }
        publish_new(output_dir, {
            REPORT: report, COUNTS: json_bytes(numbers),
            RECEIPT_OUT: json_bytes(receipt),
        })
        return count
    finally:
        if dfd >= 0:
            os.close(dfd)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE one-priority HUMAN return; does NOT verify consent or dispatch")
    parser.add_argument("--private-handoff", required=True, help="original saved private priority packet")
    parser.add_argument("--returned-csv", required=True, help="complete HUMAN recipient reply CSV")
    parser.add_argument("--output-dir", required=True, help="NEW owner-only output, no overwrite")
    args = parser.parse_args()
    try:
        count = receive(args.private_handoff, args.returned_csv, args.output_dir)
    except (Hold, ValueError, TypeError, KeyError, OSError, UnicodeError,
            RecursionError, OverflowError, MemoryError):
        print("HOLD: PRIVATE HUMAN response refused; nothing approved", file=sys.stderr)
        return 3
    print("PRIVATE HUMAN-only response packet created for " + str(count) +
          " original question rows; no permission, dispatch, verified remediation or consent.")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
