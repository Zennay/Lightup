#!/usr/bin/env python3
"""Original-source owner and source-free recipient HUMAN workflow.

Composes unchanged original native producers in a fresh owner-private staging
directory. Complete workflows publish once, atomically, with no execution,
real-target contact, consent authority, or source modification.
"""
from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import secrets
import shutil
import sys

import install

ROOT = Path(__file__).resolve().parent.parent
EVIDENCE = ROOT / "remediation-evidence-bundle-integrity"
RECIPIENT = ROOT / "remediation-recipient-trend"
sys.path.insert(0, str(EVIDENCE))
import prepare
import handoff
import read_cockpit
sys.path.insert(0, str(RECIPIENT))
import trend
import recipient_workload_series
import recipient_studio
import single_review

review = prepare.review
workspace = prepare.workspace

WARNING = (
    "OFFLINE HUMAN ONLY. No source identity, current client/operator consent, "
    "grant, scan, proof of fix or retest. INCUBATE M3/M7 - DRAFT/HOLD."
)

def require(ok: bool, why: str) -> None:
    review.require(ok, why)

def private_sources(inputs: list[Path], dest: Path) -> None:
    require(dest.is_absolute() and dest.parent == dest.parent.resolve(strict=True)
            and not dest.exists() and not dest.is_symlink(),
            "Output must be a NEW literal absolute directory")
    install.owner_dir(dest.parent)
    require(1 <= len(inputs) <= 12 and len(set(inputs)) == len(inputs),
            "Require 1-12 distinct native PRIVATE source folders")
    for folder in inputs:
        require(folder.is_absolute() and folder != dest
                and folder not in dest.parents and dest not in folder.parents
                and not folder.is_symlink()
                and folder.parent == folder.parent.resolve(strict=True),
                "Source and output paths cannot overlap or use aliases")
        install.owner_dir(folder)

def page(title: str, blocks: list[tuple[str, str, str]], caution: str) -> bytes:
    def escaped(x: str) -> str:
        return html.escape(x, quote=True)
    parts = "".join(
        "<article><h2><a href='" + escaped(link) + "'>" + escaped(name) +
        "</a></h2><p>" + escaped(description) + "</p></article>"
        for name, link, description in blocks
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'none'; connect-src 'none'; img-src 'none'; form-action 'none'; base-uri 'none'">
<title>""" + escaped(title) + """</title>
<style>body{font:16px system-ui;background:#f1f5f9;color:#14283e;margin:0;line-height:1.5}
main{max-width:880px;margin:3rem auto;padding:1rem}
article,aside{background:white;border:1px solid #d9e2eb;border-radius:12px;padding:1.2rem;margin:1rem 0}
aside{border-left:6px solid #b47917}a{color:#004d93}</style>
<main><h1>""" + escaped(title) + """</h1><aside><strong>""" +
            escaped(WARNING) + "</strong><p>" + escaped(caution) +
            "</p></aside>" + parts +
            "<p>Unsigned hashes and local case/question counts establish neither actual "
            "identity nor approval. This workspace never sends files or performs actions."
            "</p></main></html>\n").encode("utf-8")

def native_workspace_owner(inputs: list[Path], bundles: list[Path], stage: Path) -> dict:
    original = stage / "original"
    source_free = stage / "source-free-recipient"
    receipt = prepare.publish(inputs, original, bundles)
    result = handoff.prepare(original, source_free)
    read_cockpit.inspect(source_free)
    return {"source_slots": receipt["source_slots"],
            "pending_human_questions": receipt["human_pending"],
            "source_free_files": result["only_source_free_files"]}

def owner_start(inputs: list[Path], bundles: list[Path], dest: Path) -> None:
    private_sources([*inputs, *bundles], dest)
    stage = dest.parent / (".lightup-owner-stage-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        result = native_workspace_owner(inputs, bundles, stage)
        portal = page(
            "PRIVATE original evidence and HUMAN handoff",
            [
                ("Original full PRIVATE workroom", "original/index.html",
                 "Only the authorized original source owner opens this view: original metadata and HUMAN notes may be present."),
                ("Separate source-free receiving handoff", "source-free-recipient/index.html",
                 "Only independently authorized recipients receive the entire source-free-recipient folder, never the original folder."),
            ],
            "OWNER MACHINE ONLY. This parent directory contains original private evidence "
            "metadata as well as a separately prepared recipient handoff. Never share the parent folder."
        )
        install.write_file(stage / "index.html", portal)
        summary = {"kind": "lightup.human_only_original_owner_workflow",
                   "version": 1, "disposition": "DRAFT_HOLD_HUMAN_ONLY",
                   "authority_granted": False, "consent_verified": False,
                   "remediation_verified": False,
                   "warning": WARNING, **result}
        install.write_file(stage / "human-summary.json", install.canonical(summary))
        require(not dest.exists(), "Destination appeared during PRIVATE source preparation")
        workspace.exclusive_dir_publish(stage, dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("PRIVATE original workroom + separate source-free recipient handoff:", dest)
    print("Original FULL owner folder (NEVER share):", dest / "original")
    print("Selected source-free folder (only with separate disclosure approval):",
          dest / "source-free-recipient")
    print("HUMAN pending (not verified fixes):", result["pending_human_questions"])

def recipient_start(cockpits: list[Path], dest: Path) -> None:
    private_sources(cockpits, dest)
    stage = dest.parent / (".lightup-recipient-stage-" + secrets.token_hex(12))
    os.mkdir(stage, 0o700)
    try:
        report = stage / "source-free-report"
        studio = stage / "human-studio"
        if len(cockpits) == 1:
            source_status = read_cockpit.inspect(cockpits[0])
            entries, _, _, _ = single_review.original(cockpits[0])
            single_review.publish(cockpits[0], studio, None)
            kind = "single"
            selected = 1
            last_pending = source_status["local_pending_human_questions_not_fixes"]
            studio_result = {"human_reason_groups": len(entries)}
        elif len(cockpits) == 2:
            result = trend.publish(cockpits[0], cockpits[1], report)
            kind = "compare"
            selected = 2
            last_pending = result["right_pending_human"]
        else:
            result = recipient_workload_series.publish(cockpits, report)
            kind = "series"
            selected = result["snapshot_count"]
            last_pending = result["last_pending"]
        if kind != "single":
            studio_result = recipient_studio.publish(report, kind, studio)
        links = (
            [("Single original source-free HUMAN reviewer", "human-studio/index.html",
              "One real original Cockpit, private HUMAN journal and local continuation. NO synthetic second snapshot.")]
            if kind == "single" else
            [("Native source-free count comparison", "source-free-report/index.html",
              "Operator-selected aggregate packet differences, NEVER verified source identity or time."),
             ("Editable source-free HUMAN follow-up", "human-studio/index.html",
              "Original recipient reviewer, local HUMAN journal and manual owner follow-up.")]
        )
        portal = page(
            "PRIVATE source-free HUMAN recipient follow-up", links,
            "RECIPIENT SOURCE-FREE MACHINE. Original client/evidence records remain at their owner. "
            "The number of human-selected packets cannot establish identical cohorts, "
            "security improvements, real chronology or actual consent."
        )
        install.write_file(stage / "index.html", portal)
        summary = {"kind": "lightup.human_only_source_free_recipient_workflow",
                   "version": 1, "disposition": "DRAFT_HOLD_HUMAN_ONLY",
                   "authority_granted": False, "consent_verified": False,
                   "remediation_verified": False, "cohort_identity": "UNKNOWN",
                   "packet_order": "HUMAN_SELECTED_NOT_AUTHENTICATED_TIME",
                   "warning": WARNING, "source_free_packets": selected,
                   "last_selected_pending_human": last_pending,
                   "human_reason_groups": studio_result["human_reason_groups"]}
        install.write_file(stage / "human-summary.json", install.canonical(summary))
        require(not dest.exists(), "Destination appeared during HUMAN recipient preparation")
        workspace.exclusive_dir_publish(stage, dest)
    finally:
        if stage.exists():
            shutil.rmtree(stage)
    print("PRIVATE source-free receipt + interactive HUMAN Studio:", dest)
    print("Open:", dest / "index.html")
    print("Selected last packet pending questions (not fixes):", last_pending)

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Original unchanged LightUp PRIVATE evidence → HUMAN recipient workflow")
    actions = parser.add_subparsers(dest="action", required=True)
    p = actions.add_parser("owner-start", help="Create original owner workroom AND separate source-free handoff")
    p.add_argument("--input-dir", action="append", type=Path, default=[],
                   help="Original owner-private raw packet folder, repeat up to 12")
    p.add_argument("--bundle", action="append", type=Path, default=[],
                   help="Previously completed original owner-private workdesk, repeat up to 12 total")
    p.add_argument("--output-dir", type=Path, required=True)
    p = actions.add_parser("recipient-start",
                           help="Create source-free comparison/series PLUS editable HUMAN reviewer studio")
    p.add_argument("--cockpit", action="append", type=Path, required=True,
                   help="Original complete source-free PRIVATE cockpit packet, repeat 1-12")
    p.add_argument("--output-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.action == "owner-start":
            owner_start(args.input_dir, args.bundle, args.output_dir)
        else:
            recipient_start(args.cockpit, args.output_dir)
        print("REVIEW_ONLY: this HUMAN workflow confers no permission, grant, verified fix or release.")
        return 2
    except (review.Hold, OSError, ValueError, TypeError, UnicodeError) as exc:
        print("HOLD: native PRIVATE HUMAN workflow rejected: " + str(exc),
              file=sys.stderr)
        return 3

if __name__ == "__main__":
    sys.exit(main())
