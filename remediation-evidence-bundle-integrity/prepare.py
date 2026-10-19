#!/usr/bin/env python3
"""Produce original PRIVATE desks and the source-free HUMAN cockpit in one atomic package.

Consumes existing local ledger export files and optional HUMAN sessions only.
No scan, network, subprocess, grant, claim of provenance or native Apply.
"""
from __future__ import annotations

import argparse
import hashlib
import os
from pathlib import Path
import secrets
import shutil
import sys

import board
import verify
import workroom_actions

review = verify.review
triage = verify.triage
workspace = verify.workspace
focus = verify.focus

INPUT = frozenset(("current.json", "previous.json", "session.json"))
DESCRIPTION = (
    "Original source/HUMAN contents remain PRIVATE and self-declared. "
    "HUMAN reviewer notes, stage labels and local SHA references are not "
    "consent, authenticated client identity, evidence proof, fix, scan "
    "permission, signed approval, native Apply or verified retest."
)

def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()

def input_folder(path: Path) -> None:
    # Parent's secure descriptor reader enforces literal absolute path,
    # owner/private 0700 folder, 0600 one-link regular files and nofollow.
    review.require(path.is_absolute() and not path.is_symlink() and
                   path.parent == path.parent.resolve(strict=True),
                   "Input folder must be absolute literal owner-private location")
    names = {x.name for x in path.iterdir()}
    review.require("current.json" in names and names <= INPUT,
                   "Raw input must contain only current.json, optional previous.json "
                   "and optional session.json. For complete prior bundles use board.py.")
    review.private_read(path / "current.json")
    if "previous.json" in names:
        review.private_read(path / "previous.json")
    if "session.json" in names:
        review.private_read(path / "session.json")

def source_files(folder: Path) -> tuple[dict[str, bytes], bytes]:
    input_folder(folder)
    current_path = folder / "current.json"
    previous_path = (folder / "previous.json") if (folder / "previous.json").exists() else None
    session_path = (folder / "session.json") if (folder / "session.json").exists() else None
    current, prior, cb, pb = triage.selected_sources(current_path, previous_path)
    analysis = review.analyze(current, prior)
    expected = triage.make_session(current, prior, cb, pb)
    if session_path is None:
        session = expected
        session_bytes = triage.canonical(expected)
    else:
        session_bytes = review.private_read(session_path)
        session = triage.admit_session(session_bytes, expected)
    payloads = {
        "fingerprints.html": review.render(current, analysis).encode("utf-8"),
        "attention.html": focus.render(session),
        "inbox.html": triage.private_report(session),
        "counts.json": workspace.pretty({
            "kind": "lightup.anonymous_private_human_relationship_desk_counts",
            "schema_version": 1, "disposition": "HUMAN_ONLY_NO_AUTHORITY",
            "fingerprints": review.anonymous(analysis),
            "human_inbox": triage.anonymous(session),
            "attention": focus.summarize(session),
        }),
        "questions.json": workspace.pretty(review.proposed_actions(current, analysis)),
        "index.html": workspace.operator_portal(current, analysis, session),
        "current.json": cb,
        "session.json": session_bytes,
    }
    if pb is not None:
        payloads["previous.json"] = pb
    manifest = {
        "kind": workspace.KIND, "schema_version": 1,
        "disposition": "PRIVATE_UNVERIFIED_HUMAN_DESK_ONLY",
        "source_contract": current["source_contract"],
        "source_sha256": current["source_sha256"],
        "source_packet_sha256": sha(cb),
        "previous_packet_sha256": sha(pb) if pb is not None else None,
        "local_human_session_sha256": sha(session_bytes),
        "client_reference": current["client_reference"],
        "engagement_reference": current["engagement_reference"],
        **{flag: False for flag in review.FLAGS},
        "files": {name: {"sha256": sha(payload), "bytes": len(payload)}
                  for name, payload in sorted(payloads.items())},
        "warning": "Self-declared PRIVATE original source, local HUMAN notes only. "
                   "Checksums are not signatures, grants, consent, evidence proofs or security verdicts.",
    }
    # Bind every delivered source file to the exact original bytes still on disk
    # before writing an independently admitted private original desk.
    review.require(review.private_read(current_path) == cb,
                   "Original current source changed during PRIVATE composition")
    if previous_path is not None:
        review.require(review.private_read(previous_path) == pb,
                       "Original previous source changed during PRIVATE composition")
    if session_path is not None:
        review.require(review.private_read(session_path) == session_bytes,
                       "Original HUMAN session changed during PRIVATE composition")
    input_folder(folder)
    return payloads, workspace.pretty(manifest)

def local_home(number: int) -> bytes:
    links = ["<li><a href='cockpit/index.html'>Combined PRIVATE HUMAN cockpit</a>"
             " (aggregate-only receiver export: copy cockpit/ alone)</li>",
             "<li><a href='tasks.html'>Original PRIVATE record-level HUMAN action queue</a>"
             " (finding IDs / fingerprint references; source-owner machine ONLY)</li>"]
    for idx in range(1, number + 1):
        slot = f"original-{idx:02}"
        links.append("<li><a href='" + slot + "/index.html'>Original PRIVATE workdesk slot " +
                     str(idx) + "</a> (contains original source claims and private HUMAN notes;"
                     " never share this directory)</li>")
    return (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'unsafe-inline'; script-src 'none'; connect-src 'none';"
        "form-action 'none'; base-uri 'none'\">"
        "<meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<title>LightUp PRIVATE Evidence Workroom</title>"
        "<style>body{font:16px system-ui;background:#f5f7fb;color:#17283d;"
        "max-width:900px;margin:2rem auto;padding:1rem}section,aside{background:white;"
        "border-radius:12px;padding:1.4rem;margin:1rem 0}"
        "aside{border-left:5px solid #b17e16}li{padding:.7rem}"
        "a{color:#1260a3}</style><main><h1>PRIVATE evidence workroom</h1>"
        "<aside><strong>INCUBATE M3/M7 · DRAFT/HOLD · HUMAN ONLY.</strong> "
        + DESCRIPTION + "</aside><section><h2>Start here</h2>"
        "<p>" + str(number) + " self-declared private original source slot(s). "
        "Open the cockpit for aggregate HUMAN follow-up, or return to an exact "
        "original source workdesk for private record-level context. "
        "These are locally generated snapshots, not an authenticated timeline.</p>"
        "<ul>" + "".join(links) + "</ul></section>"
        "<section><h2>Safe sharing boundary</h2><p>To share only source-free "
        "PRIVATE HUMAN workload, copy <code>cockpit/</code> alone to an already "
        "authorized private receiver. Use <code>read_cockpit.py</code> there. "
        "Keep <code>original-XX/</code> and this workroom at the source-owner "
        "location. No part of this product authenticates consent, findings or fixes."
        "</p></section></main></html>\n").encode("utf-8")

def publish(input_paths: list[Path], output: Path) -> dict:
    review.require(1 <= len(input_paths) <= 12 and len(set(input_paths)) == len(input_paths),
                   "Require 1–12 distinct original PRIVATE input directories")
    review.require(output.is_absolute() and output.parent == output.parent.resolve(strict=True)
                   and not output.exists() and not output.is_symlink(),
                   "Output is a completely NEW absolute literal PRIVATE directory")
    for original in input_paths:
        review.require(original != output and original not in output.parents and
                       output not in original.parents, "Output must not enter original input directory")
        input_folder(original)
    parent = triage.private_parent(output)
    stage = parent / (".lightup-private-workroom-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    published = False
    try:
        originals = []
        input_snapshots = []
        for index, folder in enumerate(input_paths, 1):
            files, manifest = source_files(folder)
            target = stage / f"original-{index:02}"
            workspace.publish_bundle(target, files, manifest)
            verify.inspect(target)  # direct native source product admission, not QA suite
            originals.append(target)
            input_snapshots.append(
                (folder, {key: review.private_read(folder / key)
                          for key in sorted({item.name for item in folder.iterdir()})}))
        summary = board.publish(originals, stage / "cockpit")
        actions = workroom_actions.collect(originals)
        review.private_publish(stage / "tasks.html", workroom_actions.render(actions))
        review.private_publish(stage / "index.html", local_home(len(originals)))
        # Abort the entire atomic publication if any input was changed concurrently.
        for folder, admitted in input_snapshots:
            review.require({item.name for item in folder.iterdir()} == set(admitted),
                           "Original input directory changed before PRIVATE publish")
            for filename, prior_data in admitted.items():
                review.require(review.private_read(folder / filename) == prior_data,
                               "Original source/HUMAN bytes changed before PRIVATE publish")
        dirfd = os.open(stage, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(dirfd)
        finally:
            os.close(dirfd)
        workspace.exclusive_dir_publish(stage, output)
        published = True
        return {"source_slots": len(originals), "cockpit_files": summary["private_files"],
                "human_pending": summary["locally_pending"],
                "same_source_history": summary["history_included"]}
    finally:
        if not published and stage.exists():
            # Only the tool's privately minted, exclusively owned staging path.
            # No existing user-supplied directory is deleted or modified.
            shutil.rmtree(stage)

def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Build a PRIVATE source-owner workroom and separate source-free cockpit "
        "atomically from preexisting local original ledger/HUMAN input folders"))
    parser.add_argument("--input-dir", type=Path, action="append", required=True,
                        help="Owner-only 0700 directory containing current.json, optional "
                             "previous.json and optional session.json (1–12)")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="NEW absolute workroom directory inside owner-only 0700 parent")
    args = parser.parse_args()
    try:
        summary = publish(args.input_dir, args.output_dir)
        print("PRIVATE original + HUMAN workroom published atomically.")
        print("Original slots: " + str(summary["source_slots"]) +
              "; locally pending proposed questions: " + str(summary["human_pending"]) +
              "; cockpit files: " + str(summary["cockpit_files"]) + ".")
        print("Open index.html locally. Copy ONLY cockpit/ for a source-free private receipt.")
        print("DRAFT/HOLD: no authenticated source identity, permission, scan or remediation.")
        return 2
    except (review.Hold, OSError, ValueError):
        print("HOLD: original PRIVATE intake rejected; no successful workroom published.",
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
