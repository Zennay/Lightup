#!/usr/bin/env python3
"""Offline PRIVATE manifest + original HUMAN source-bound workspace admission.

Checks self-declared local consistency only, never source authenticity or authority.
"""
from __future__ import annotations
import argparse
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys

# Use the unmodified original owner-pinned product interfaces (held PR #1660).
sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "remediation-evidence-reuse"))
import focus
import review
import triage
import workspace

FILES = frozenset(("index.html", "fingerprints.html", "attention.html",
                  "inbox.html", "counts.json", "questions.json",
                  "current.json", "session.json"))
FIELDS = frozenset(("kind", "schema_version", "disposition", "source_contract",
                    "source_sha256", "source_packet_sha256", "previous_packet_sha256",
                    "local_human_session_sha256", "client_reference",
                    "engagement_reference", "files", "warning", *review.FLAGS))
MAX_BYTES = 4 * 1024 * 1024

def sha(b: bytes) -> str:
    return hashlib.sha256(b).hexdigest()

def json_obj(b: bytes) -> dict:
    review.require(len(b) <= MAX_BYTES, "PRIVATE input exceeds upper bound")
    try:
        obj = json.loads(b.decode("utf-8"), object_pairs_hook=review.pairs,
                         parse_constant=review.reject_constant)
    except (UnicodeError, ValueError, RecursionError) as exc:
        raise review.Hold("Malformed PRIVATE input") from exc
    review.require(type(obj) is dict, "Expected PRIVATE JSON object")
    return obj

def inspect(folder: Path) -> tuple[dict, dict[str, bytes]]:
    review.require(folder.is_absolute() and folder.parent == folder.parent.resolve(strict=True)
                   and not folder.is_symlink(), "PRIVATE workspace requires literal directory")
    mode = folder.stat(follow_symlinks=False)
    review.require(stat.S_ISDIR(mode.st_mode) and mode.st_uid == os.getuid() and
                   mode.st_mode & 0o077 == 0, "Not an owner-private 0700 directory")
    raw_manifest = review.private_read(folder / "manifest.json")
    m = json_obj(raw_manifest)
    review.require(set(m) == FIELDS and
                   m.get("kind") == "lightup.private_evidence_relationship_operator_bundle" and
                   type(m.get("schema_version")) is int and m["schema_version"] == 1 and
                   m.get("disposition") == "PRIVATE_UNVERIFIED_HUMAN_DESK_ONLY",
                   "Unknown PRIVATE source workdesk manifest")
    review.require(all(m.get(flag) is False for flag in review.FLAGS),
                   "Forbidden authority claim")
    review.exact_string(m.get("warning"), 2000, "manifest warning", True)
    prev_sha = m.get("previous_packet_sha256")
    review.require(prev_sha is None or
                   (type(prev_sha) is str and review.HEX.fullmatch(prev_sha) is not None),
                   "Malformed previous packet digest")
    filenames = set(FILES) | ({"previous.json"} if prev_sha is not None else set())
    review.require(type(m.get("files")) is dict and set(m["files"]) == filenames,
                   "Incomplete workspace manifest")
    review.require({f.name for f in folder.iterdir()} == filenames | {"manifest.json"},
                   "Untracked or missing PRIVATE workspace objects")
    contents = {}
    for name in sorted(filenames):
        desc = m["files"][name]
        review.require(type(desc) is dict and set(desc) == {"sha256", "bytes"} and
                       type(desc["sha256"]) is str and
                       review.HEX.fullmatch(desc["sha256"]) is not None and
                       type(desc["bytes"]) is int and 0 <= desc["bytes"] <= MAX_BYTES,
                       "Invalid PRIVATE file descriptor")
        b = review.private_read(folder / name)
        review.require(len(b) == desc["bytes"] and sha(b) == desc["sha256"],
                       "PRIVATE file differs from original local manifest")
        contents[name] = b
    current = contents["current.json"]
    previous = contents.get("previous.json")
    source = review.parse_packet_data(current)
    old = review.parse_packet_data(previous) if previous is not None else None
    analysis = review.analyze(source, old)
    original_session = triage.make_session(source, old, current, previous)
    session = triage.admit_session(contents["session.json"], original_session)
    for key in ("source_contract", "source_sha256", "client_reference", "engagement_reference"):
        review.require(m.get(key) == source[key], "Manifest differs from original PRIVATE source")
    review.require(m.get("source_packet_sha256") == sha(current) and
                   prev_sha == (sha(previous) if previous is not None else None) and
                   m.get("local_human_session_sha256") == sha(contents["session.json"]),
                   "Original PRIVATE source or HUMAN session digest mismatch")
    review.require(contents["questions.json"] ==
                   workspace.pretty(review.proposed_actions(source, analysis)),
                   "Question handoff does not match original source+proposal")
    counts = {"kind": "lightup.anonymous_private_human_relationship_desk_counts",
              "schema_version": 1, "disposition": "HUMAN_ONLY_NO_AUTHORITY",
              "fingerprints": review.anonymous(analysis),
              "human_inbox": triage.anonymous(session),
              "attention": focus.summarize(session)}
    review.require(contents["counts.json"] == workspace.pretty(counts),
                   "Counts do not match original source-bound HUMAN state")
    # A file swapped during local inspection must never generate a current report.
    review.require(review.private_read(folder / "manifest.json") == raw_manifest,
                   "Manifest changed during local reading")
    for name, b in contents.items():
        review.require(sha(review.private_read(folder / name)) == sha(b),
                       "PRIVATE workspace changed during local reading")
    return ({"file_count": len(contents), "local_links": analysis["local_links"],
             "shared_fingerprints": len(analysis["shared_groups"]),
             "conflicting_groups": len(analysis["attention_groups"]),
             "human_questions": len(session["records"]),
             "human_stage_counts": triage.anonymous(session)["stage_counts"],
             "has_previous": previous is not None}, contents)

def render_html(s: dict) -> bytes:
    escape = lambda v: html.escape(str(v), quote=True)
    stages = "".join("<tr><th>" + escape(k.replace("_", " ")) +
                     "</th><td>" + str(v) + "</td></tr>"
                     for k, v in s["human_stage_counts"].items())
    return ("<!doctype html><html lang='en'><meta charset='utf-8'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; "
            "img-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<title>LightUp PRIVATE bundle integrity desk</title>"
            "<style>body{font:16px system-ui;max-width:760px;margin:3rem auto;"
            "padding:0 1rem;background:#f6f7fb;color:#233349}"
            "section,aside{background:white;padding:1rem;margin:1rem 0;border-radius:8px}"
            "aside{border-left:5px solid #986000}th{text-align:left}td{padding:.4rem}"
            "table{width:100%}</style><main><h1>PRIVATE bundle integrity desk</h1>"
            "<aside><strong>LOCAL BYTES CONSISTENT — NOT AUTHENTICATED.</strong> "
            "An unkeyed local SHA-256 manifest cannot prove who prepared files, "
            "client consent, original evidence provenance, security findings, fixes "
            "or authority. INCUBATE M3/M7 · DRAFT/HOLD · HUMAN ONLY. No scan, "
            "grant, native Apply or verified retest.</aside>"
            "<section><h2>Local source-bound workspace</h2><p>" +
            str(s["file_count"]) + " private files admitted; " +
            str(s["local_links"]) + " local artifact links; " +
            str(s["shared_fingerprints"]) + " shared SHA groups; " +
            str(s["conflicting_groups"]) + " HUMAN attention groups; " +
            str(s["human_questions"]) + " source-bound proposed HUMAN questions.</p>"
            "<p>Earlier self-declared source packet: " +
            ("present" if s["has_previous"] else "not included") +
            ". No authenticated chronology or original file-byte inspection.</p></section>"
            "<section><h2>Local HUMAN stage distribution</h2><table>" + stages +
            "</table><p>Locally answered does not mean fixed or approved. "
            "Use the original owner-private Evidence Relationship Desk to modify "
            "HUMAN notes. This report never edits source state.</p></section>"
            "<p>Keep source folder and report on a trusted owner-private machine; "
            "never publish PRIVATE source material or the HTML.</p></main></html>\n"
            ).encode("utf-8")

def main() -> int:
    p = argparse.ArgumentParser(description="Inspect private original evidence workspace consistency offline")
    p.add_argument("--bundle", type=Path, required=True,
                   help="Absolute 0700 original Evidence Relationship Desk folder")
    p.add_argument("--report", type=Path,
                   help="New PRIVATE 0600 scriptless HTML in separate 0700 parent directory")
    args = p.parse_args()
    try:
        if args.report is not None:
            review.require(args.report.parent != args.bundle, "Report cannot modify source workspace")
            triage.private_parent(args.report)
        summary, _ = inspect(args.bundle)
        if args.report is not None:
            review.private_publish(args.report, render_html(summary))
            print("PRIVATE local HTML summary created.")
        print("REVIEW_ONLY: local bundle consistent; not authenticated source, consent, security or release.")
        print("Files " + str(summary["file_count"]) + "; HUMAN questions " +
              str(summary["human_questions"]) + "; local links " + str(summary["local_links"]))
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: PRIVATE bundle/source admission failed; no output issued.", file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
