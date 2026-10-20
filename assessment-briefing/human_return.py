#!/usr/bin/env python3
"""Source-bound PRIVATE HUMAN follow-up reconciliation; no finding/consent verdict."""
from __future__ import annotations

import argparse
import csv
import hashlib
import html
import io
import json
import os
import stat
import sys

from briefing import (CSS, DENIAL_FLAGS, Hold, SEVERITIES, h, json_bytes,
                      open_source, publish_new, require, text_value)

MAX_CSV_BYTES = 1024 * 1024
MAX_MANIFEST_BYTES = 8192
HEADER = ("original_ordinal", "source_reported_severity", "evidence_reference_count",
          "human_stage", "human_owner_group", "human_next_action", "human_blocker")
STAGES = ("", "needs_review", "discussing", "blocked", "documented")


def read_limited_file(path: str, maximum: int) -> bytes:
    fd = -1
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0) |
                     getattr(os, "O_NONBLOCK", 0))
        mode = os.fstat(fd)
        require(stat.S_ISREG(mode.st_mode) and 0 < mode.st_size <= maximum)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            result = stream.read(maximum + 1)
        require(0 < len(result) <= maximum)
        return result
    except (OSError, OverflowError, ValueError, MemoryError):
        raise Hold("PRIVATE review file rejected (HOLD)") from None
    finally:
        if fd >= 0:
            os.close(fd)


def source_manifest(raw: bytes, digest: str, source: dict) -> None:
    try:
        manifest = json.loads(raw.decode("utf-8"),
                              object_pairs_hook=__import__("briefing").strict_pairs,
                              parse_constant=lambda _: require(False))
        require(type(manifest) is dict and
                manifest.get("schema") == "lightup.private_lab_briefing.v1" and
                manifest.get("status") == "REVIEW_ONLY" and
                manifest.get("source_authenticated") is False and
                manifest.get("authorization_granted") is False and
                manifest.get("dispatch_allowed") is False and
                manifest.get("release_allowed") is False)
        require(manifest.get("original_source_sha256_unsigned") == digest)
        require(type(manifest.get("declared_finding_count")) is int and
                manifest["declared_finding_count"] == len(source["findings"]))
        require(type(manifest.get("declared_endpoint_count")) is int and
                manifest["declared_endpoint_count"] == len(source["targets"]))
    except (ValueError, UnicodeError, OverflowError, RecursionError, TypeError):
        raise Hold("PRIVATE source binding rejected (HOLD)") from None


def read_human_csv(raw: bytes, source: dict) -> list[dict]:
    try:
        decoded = raw.decode("utf-8-sig")
        require("\x00" not in decoded)
        reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
        require(tuple(next(reader)) == HEADER)
        rows = list(reader)
        require(len(rows) == len(source["findings"]))
        out = []
        for ordinal, (row, finding) in enumerate(zip(rows, source["findings"]), 1):
            require(len(row) == len(HEADER))
            require(row[0] == str(ordinal))
            require(row[1] == finding["severity"])
            require(row[2] == str(len(finding["evidence_ids"])))
            require(row[3] in STAGES)
            require(text_value(row[4], 120) and text_value(row[5], 600) and
                    text_value(row[6], 600))
            require(len(row[3]) + len(row[4]) + len(row[5]) + len(row[6]) <= 1400)
            out.append({"stage": row[3] or "needs_review",
                        "owner": row[4], "action": row[5], "blocker": row[6]})
        return out
    except (csv.Error, StopIteration, ValueError, UnicodeError, OverflowError,
            MemoryError, RecursionError, TypeError):
        raise Hold("PRIVATE human worksheet rejected (HOLD)") from None


def review_page(source: dict, sha: str, notes: list[dict]) -> str:
    from briefing import render
    base = render(source, sha)
    # Retain original source display exactly as in the already-produced
    # briefing, but render a distinct immutable human report, not mutate source.
    bodies = []
    progress = {s: sum(n["stage"] == s for n in notes) for s in STAGES[1:]}
    for ordinal, (f, n) in enumerate(zip(source["findings"], notes), 1):
        human = ("<article><h3>Original finding #" + str(ordinal) +
                 " · <span class='sev " + h(f["severity"]) + "'>" +
                 h(f["severity"]) + "</span></h3>" +
                 "<p>" + h(f["finding"]) + "</p>" +
                 "<p class='muted'>PRIVATE original check: " + h(f["check_id"]) +
                 " · evidence references: " + str(len(f["evidence_ids"])) + "</p>" +
                 "<dl><dt>Human-reported stage</dt><dd>" + h(n["stage"]) +
                 "</dd><dt>Human owner/group label (NOT authenticated)</dt><dd>" +
                 h(n["owner"] or "Not recorded") +
                 "</dd><dt>Human-proposed action</dt><dd><pre>" +
                 h(n["action"] or "Not recorded") +
                 "</pre></dd><dt>Human blocker</dt><dd><pre>" +
                 h(n["blocker"] or "Not recorded") + "</pre></dd></dl>" +
                 "<details><summary>PRIVATE unchanged original source details</summary>" +
                 "<dl><dt>Original target</dt><dd>" + h(f["target"]) +
                 "</dd><dt>Original impact</dt><dd>" + h(f["impact"]) +
                 "</dd><dt>Original suggested fix</dt><dd>" + h(f["fix"]) +
                 "</dd><dt>Original suggested retest</dt><dd>" + h(f["retest"]) +
                 "</dd><dt>Original evidence summary</dt><dd>" + h(f["evidence_summary"]) +
                 "</dd></dl></details></article>")
        bodies.append(human)
    summary = "".join("<section class='card'><h3>" + h(k) + "</h3><div class='value'>" +
                      str(v) + "</div></section>" for k, v in progress.items())
    # Reuse the existing pinned CSP stylesheet and full source without DOM/scripts.
    prefix = base.split("<body>", 1)[0]
    return (prefix + "<body><header><h1>LightUp · PRIVATE HUMAN follow-up return</h1>" +
            "<p class='notice'>REVIEW ONLY — original source and HUMAN input NOT " +
            "independently authenticated. Human labels are NOT actual approvals, " +
            "retests, remediation, verified findings, current consent or authority.</p>" +
            "<p>Unsigned original source SHA-256: <code>" + sha + "</code></p>" +
            "<p>Follow-up stages are self-reported and never modify original results.</p>" +
            "</header><div class='grid'>" + summary + "</div>" +
            "".join(bodies) + "</body></html>\n")


def create(source_path: str, manifest_path: str, worksheet: str, destination: str) -> None:
    source, _, digest = open_source(source_path)
    source_manifest(read_limited_file(manifest_path, MAX_MANIFEST_BYTES), digest, source)
    notes = read_human_csv(read_limited_file(worksheet, MAX_CSV_BYTES), source)
    page = review_page(source, digest, notes).encode("utf-8")
    counts = {s: sum(note["stage"] == s for note in notes) for s in STAGES[1:]}
    summary = {
        "schema": "lightup.private_lab_human_return.v1",
        "status": "REVIEW_ONLY", "original_source_sha256_unsigned": digest,
        "original_finding_count": len(notes), "human_self_reported_stage_counts": counts,
        "private_review_sha256_unsigned": hashlib.sha256(page).hexdigest(),
        "source_authenticated": False, "human_identity_authenticated": False,
        "human_followup_verified": False, "client_consent_verified": False,
        "operator_consent_verified": False, **DENIAL_FLAGS,
    }
    publish_new(destination, {"private-human-return.html": page,
                              "private-human-summary.json": json_bytes(summary)})


def main() -> int:
    p = argparse.ArgumentParser(description="Source-bound PRIVATE HUMAN follow-up return")
    p.add_argument("--source", required=True, help="unchanged original private lab JSON")
    p.add_argument("--manifest", required=True, help="briefing/manifest.json")
    p.add_argument("--worksheet", required=True, help="human-filled original follow-up CSV")
    p.add_argument("--output-dir", required=True, help="NEW private output directory")
    args = p.parse_args()
    try:
        create(args.source, args.manifest, args.worksheet, args.output_dir)
    except Hold as exc:
        print(str(exc), file=sys.stderr)
        return 3
    print("PRIVATE source-bound HUMAN review returned; REVIEW ONLY")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
