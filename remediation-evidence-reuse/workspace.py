#!/usr/bin/env python3
"""One-command, source-bound PRIVATE offline evidence relationship operator workspace.

Creates a complete owner-private directory atomically, reusing admitted original
ledger and HUMAN review functions. Never calls real LightUp Apply, scan or grant.
Linux renameat2(RENAME_NOREPLACE) is required: fail closed on unsupported hosts.
"""
from __future__ import annotations

import argparse
from contextlib import nullcontext
import ctypes
import errno
import hashlib
import html
import json
import os
from pathlib import Path
import secrets
import sys

import focus
import review
import triage


KIND = "lightup.private_evidence_relationship_operator_bundle"
HELP = {
    "fingerprints.html": ("Evidence fingerprint relationships",
                          "Original finding-to-SHA reuse, claimed byte-length contradictions and optional local snapshot drift."),
    "attention.html": ("HUMAN attention board",
                       "Grouped original HUMAN follow-up reasons and current local status without private free-text notes."),
    "inbox.html": ("PRIVATE HUMAN local inbox",
                   "A read-only view of current local HUMAN stages and PRIVATE notes. Restrict access."),
    "counts.json": ("Counts without source identifiers",
                    "Combined aggregate-only local HUMAN review numbers; never a verified security verdict."),
    "questions.json": ("PRIVATE suggested HUMAN questions",
                       "The original finding IDs and local evidence SHA references for manual review; not an executable request."),
}


def digest(contents: bytes) -> str:
    return hashlib.sha256(contents).hexdigest()


def pretty(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2,
                       allow_nan=False) + "\n").encode("utf-8")


def operator_portal(source: dict, results: dict, session: dict) -> bytes:
    escape = lambda s: html.escape(str(s), quote=True)
    links = []
    for name, (title, description) in HELP.items():
        links.append("<li><h2><a href='" + name + "'>" + escape(title) +
                     "</a></h2><p>" + escape(description) + "</p></li>")
    local_total = len(session["records"])
    attention = sum(r["stage"] != "answered_human" for r in session["records"])
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; script-src 'none'; img-src 'none'; "
        "connect-src 'none'; form-action 'none'; base-uri 'none'\">"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<title>LightUp PRIVATE Evidence Relationship Desk</title>"
        "<style>body{font:16px system-ui;max-width:900px;margin:2rem auto;padding:0 1rem;"
        "background:#f4f6fa;color:#18263b}h1{font-size:2rem}"
        "aside{background:#fff2d3;padding:1rem;border-left:4px solid #aa7000}"
        "ul{padding:0;list-style:none}li{padding:1rem;margin:1rem 0;border-radius:8px;"
        "background:white;border:1px solid #dde3ea}li h2{margin:.2rem 0;font-size:1.1rem}"
        "a{color:#164989}code{overflow-wrap:anywhere}</style><main>"
        "<h1>PRIVATE HUMAN Evidence Relationship Desk</h1>"
        "<aside><strong>INCUBATE · DRAFT/HOLD · HUMAN ONLY.</strong> Offline, local "
        "operator workspace. Original source labels and file SHA values are "
        "unverified claims, not independently authenticated client/evidence "
        "identity. No real LightUp grant, authorization, scan, native Apply, "
        "security verdict, retest, signed approval or remediation result. "
        "Do not upload this PRIVATE folder to cloud sync, public GitHub, CI or "
        "a shared host. Browser links stay inside this local folder.</aside>"
        "<p>Claimed original finding-source digest: <code>" +
        escape(source["source_sha256"]) + "</code></p>"
        "<p>Self-declared client / engagement: " +
        escape(source["client_reference"]) + " / " +
        escape(source["engagement_reference"]) + "</p>"
        "<p><strong>" + str(local_total) + "</strong> HUMAN proposed questions · <strong>" +
        str(attention) + "</strong> not locally answered · <strong>" +
        str(results["local_links"]) + "</strong> local attachment references. "
        "Even a locally answered question is NOT a verified fix.</p>"
        "<ul>" + "".join(links) + "</ul>"
        "<p>Each output file has a SHA-256 checksum in PRIVATE manifest.json "
        "for accidental modification detection. Manifest checksums are not "
        "cryptographic signatures or proof of original source authenticity.</p>"
        "<p>This owner-private folder contains <code>current.json</code>, optional "
        "<code>previous.json</code>, and <code>session.json</code> original "
        "metadata/HUMAN-only copies. From a trusted local terminal call "
        "<code>desk.py inbox mark --current /ABSOLUTE/FOLDER/current.json "
        "--session /ABSOLUTE/FOLDER/session.json</code> (also specify previous "
        "when present). These are PRIVATE source claims, not evidence-file bytes. "
        "The browser HTML cannot edit any files. After local changes, publish a "
        "NEW workspace directory; existing HTML and checksums show a prior "
        "point-in-time snapshot.</p></main></html>\n"
    ).encode("utf-8")


def exclusive_dir_publish(temporary: Path, destination: Path) -> None:
    # Linux-specific atomic publication of the entire prepared private folder.
    libc = ctypes.CDLL(None, use_errno=True)
    operation = getattr(libc, "renameat2", None)
    review.require(operation is not None,
                   "Atomic exclusive directory publication is unavailable (Linux renameat2 required)")
    operation.argtypes = [ctypes.c_int, ctypes.c_char_p, ctypes.c_int,
                          ctypes.c_char_p, ctypes.c_uint]
    operation.restype = ctypes.c_int
    at_fdcwd = getattr(os, "AT_FDCWD", -100)
    result = operation(at_fdcwd, os.fsencode(temporary),
                       at_fdcwd, os.fsencode(destination), 1)
    if result != 0:
        code = ctypes.get_errno()
        raise OSError(code, os.strerror(code), str(destination))
    fd = os.open(destination.parent, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def publish_bundle(target: Path, files: dict[str, bytes], manifest: bytes) -> None:
    parent = triage.private_parent(target)
    review.require(not target.exists() and not target.is_symlink(),
                   "PRIVATE operator directory name must be entirely unused")
    temporary = parent / (".lightup-private-pending-" + secrets.token_hex(12))
    os.mkdir(temporary, mode=0o700)
    complete = False
    try:
        for name, contents in {**files, "manifest.json": manifest}.items():
            review.private_publish(temporary / name, contents)
        temp_dirfd = os.open(temporary, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(temp_dirfd)
        finally:
            os.close(temp_dirfd)
        exclusive_dir_publish(temporary, target)
        complete = True
    finally:
        if not complete and temporary.exists():
            # Never clean a caller-owned destination; only our own random staging dir.
            for item in temporary.iterdir():
                item.unlink()
            temporary.rmdir()


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Create one complete immutable, owner-private offline HUMAN relationship desk folder")
    parser.add_argument("--current", type=Path, required=True, help="Original owner-private Evidence Ledger export")
    parser.add_argument("--previous", type=Path, help="Earlier exact same-source PRIVATE original export")
    parser.add_argument("--session", type=Path,
                        help="Optional existing PRIVATE HUMAN triage session; otherwise create new local inbox")
    parser.add_argument("--output-dir", type=Path, required=True, help="NEW absolute owner-private output directory")
    args = parser.parse_args()
    try:
        review.require(args.output_dir not in (args.current, args.previous, args.session),
                       "Output directory must not be a PRIVATE input")
        source, previous, current_bytes, previous_bytes = triage.selected_sources(args.current, args.previous)
        results = review.analyze(source, previous)
        expected = triage.make_session(source, previous, current_bytes, previous_bytes)
        with (triage.single_host_lock(args.session) if args.session is not None else nullcontext()):
            if args.session is None:
                session = expected
                session_bytes = triage.canonical(session)
            else:
                session_bytes = review.private_read(args.session)
                session = triage.admit_session(session_bytes, expected)
            files = {
                "fingerprints.html": review.render(source, results).encode("utf-8"),
                "attention.html": focus.render(session),
                "inbox.html": triage.private_report(session),
                "counts.json": pretty({
                    "kind": "lightup.anonymous_private_human_relationship_desk_counts",
                    "schema_version": 1,
                    "disposition": "HUMAN_ONLY_NO_AUTHORITY",
                    "fingerprints": review.anonymous(results),
                    "human_inbox": triage.anonymous(session),
                    "attention": focus.summarize(session),
                }),
                "questions.json": pretty(review.proposed_actions(source, results)),
            }
            files["index.html"] = operator_portal(source, results, session)
            # Portable original HUMAN metadata/session copies, without evidence file bytes.
            files["current.json"] = current_bytes
            if previous_bytes is not None:
                files["previous.json"] = previous_bytes
            files["session.json"] = session_bytes
            manifest = {
                "kind": KIND, "schema_version": 1,
                "disposition": "PRIVATE_UNVERIFIED_HUMAN_DESK_ONLY",
                "source_contract": source["source_contract"],
                "source_sha256": source["source_sha256"],
                "source_packet_sha256": digest(current_bytes),
                "previous_packet_sha256": digest(previous_bytes) if previous_bytes is not None else None,
                "local_human_session_sha256": digest(session_bytes),
                "client_reference": source["client_reference"],
                "engagement_reference": source["engagement_reference"],
                **{key: False for key in review.FLAGS},
                "files": {key: {"sha256": digest(payload), "bytes": len(payload)}
                          for key, payload in sorted(files.items())},
                "warning": "Self-declared PRIVATE original source, local HUMAN notes only. Checksums are not signatures, grants, consent, evidence proofs or security verdicts.",
            }
            triage.fresh_original_bytes(args, current_bytes, previous_bytes)
            if args.session is not None:
                review.require(review.private_read(args.session) == session_bytes,
                               "HUMAN session changed during private bundle preparation")
            publish_bundle(args.output_dir, files, pretty(manifest))
            print("PRIVATE offline HUMAN workspace published: " + str(args.output_dir))
            print("Open index.html only in a trusted LOCAL browser; all inputs unchanged.")
        return 2
    except (review.Hold, OSError, ValueError) as exc:
        print("HOLD: " + str(exc), file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
