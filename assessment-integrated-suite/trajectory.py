#!/usr/bin/env python3
"""Compose PRIVATE original canonical benchmark sequences for unchanged offline studios.

Only original already-produced lab cohort files; no scanning, models or grants.
"""
from __future__ import annotations

import argparse
import csv
import io
import html
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile

from benchmark_room import original_compare
from suite import Hold, ROOT, parent_dir, read_safe, copy_app

ORIGINAL_STUDIOS = {
    "PRIVATE-original-trend-studio.html": ROOT / "assessment-trends/standalone.html",
    "PRIVATE-original-candidate-studio.html": ROOT / "assessment-candidates/standalone.html",
    "PRIVATE-original-review-desk.html": ROOT / "assessment-review/standalone.html",
}
FALSE = ("authorized", "consent_verified", "dispatch_allowed", "release_allowed")


def private_file(path: Path, data: bytes) -> None:
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as out:
        out.write(data)


def prepare(args: argparse.Namespace) -> int:
    if not 3 <= len(args.candidate) <= 12:
        raise Hold("HOLD: 3-12 original candidate cohorts required for native trends")
    parent = parent_dir(args.private_parent)
    candidates = [str(Path(p).absolute()) for p in args.candidate]
    if len(set(candidates)) != len(candidates):
        raise Hold("HOLD: repeated original source positions cannot represent a trajectory")
    for app in ORIGINAL_STUDIOS.values():
        read_safe(app, 2 * 1024 * 1024)

    # Admission is all-or-nothing, before publishing a single local file.
    rows = []
    baseline_sha = None
    candidate_shas = set()
    for index, source in enumerate(candidates, 1):
        output = original_compare(args.kind, args.baseline, source)
        source_sha = output["original_source_byte_hashes_unsigned"]
        if baseline_sha is None:
            baseline_sha = source_sha["baseline"]
        if source_sha["baseline"] != baseline_sha:
            raise Hold("HOLD: original baseline bytes changed during local review")
        if source_sha["candidate"] in candidate_shas:
            raise Hold("HOLD: duplicate candidate source bytes, not independent revisions")
        candidate_shas.add(source_sha["candidate"])
        if output["status"] not in ("HOLD", "REVIEW_ONLY"):
            raise Hold("HOLD: original comparator returned an unsupported state")
        native = output["original_canonical_output"]
        if type(native) is not dict or native["status"] != output["status"]:
            raise Hold("HOLD: original native format mismatch")
        for flag in FALSE:
            if native.get(flag) is not False:
                raise Hold("HOLD: original canonical authority fence failed")
        payload = (json.dumps(native, sort_keys=True, separators=(",", ":"),
                              ensure_ascii=False) + "\n").encode("utf-8")
        rows.append({
            "position": index, "status": output["status"],
            "scenarios": len(output["groups"]),
            "regressed_scenarios": sum(bool(s["regressions"]) for s in output["groups"]),
            "source_sha256_unsigned": source_sha["candidate"],
            "filename": f"PRIVATE-original-cohort-{index:02d}.json",
            "content": payload,
            "adverse_ordinals": [
                (ordinal, len(group["regressions"]))
                for ordinal, group in enumerate(output["groups"], 1)
                if group["regressions"]
            ],
        })

    if not rows or baseline_sha is None:
        raise Hold("HOLD: original source series is empty")
    kit = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-trajectory-", dir=parent))
    os.chmod(kit, 0o700)
    complete = False
    try:
        manifest_rows = []
        navigation = []
        for item in rows:
            private_file(kit / item["filename"], item["content"])
            manifest_rows.append({
                key: item[key] for key in
                ("position", "status", "scenarios", "regressed_scenarios",
                 "source_sha256_unsigned", "filename")
            })
            count_text = (
                f"{item['scenarios']} declared lab scenarios; "
                f"{item['regressed_scenarios']} with adverse primary observations"
            )
            navigation.append(
                "<li><a href='" + html.escape(item["filename"], quote=True) + "'>" +
                f"Original canonical cohort {item['position']:02d}</a> " +
                "<strong>" + html.escape(item["status"]) + "</strong> · " +
                html.escape(count_text) + "</li>"
            )
        followup = io.StringIO(newline="")
        writer = csv.writer(followup)
        writer.writerow((
            "baseline_original_sha256_unsigned", "candidate_original_sha256_unsigned",
            "candidate_ordinal", "source_scenario_ordinal",
            "source_declared_adverse_metric_count", "human_review_stage",
            "human_review_group", "human_next_question", "human_blocker",
        ))
        for item in rows:
            for ordinal, count in item["adverse_ordinals"]:
                writer.writerow((
                    baseline_sha, item["source_sha256_unsigned"],
                    item["position"], ordinal, count, "", "", "", "",
                ))
        private_file(kit / "PRIVATE-human-trajectory-followup.csv",
                     followup.getvalue().encode("utf-8"))
        for target, original in ORIGINAL_STUDIOS.items():
            copy_app(original, kit / target)
        receipt = {
            "schema": "lightup.private_assessment_trajectory_handoff.v1",
            "status": "HOLD" if any(i["status"] == "HOLD" for i in rows) else "REVIEW_ONLY",
            "kind": args.kind, "user_selected_order_not_verified_chronology": True,
            "original_source_authenticated": False,
            "original_baseline_sha256_unsigned": baseline_sha,
            "cohorts": manifest_rows,
            **{key: False for key in FALSE},
        }
        private_file(kit / "PRIVATE-trajectory-receipt.json",
                     (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8"))
        summary = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>LightUp PRIVATE original lab trajectory</title>
<style>:root{color-scheme:light;font:17px/1.6 system-ui;background:#eef2f6;color:#192a3c}
body{max-width:980px;margin:3rem auto;padding:0 20px}
main{background:#fff;border:1px solid #ccd9e4;border-radius:16px;padding:25px}
li{margin:.8rem 0}a{color:#145d89}strong{color:#8a3d1d}
.notice{font-weight:750;color:#8a3d1d}</style>
<main><h1>LightUp · original PRIVATE lab trajectory</h1>
<p class="notice">""" + html.escape(receipt["status"]) + """
 · PRIVATE · HUMAN-only · not a security clearance or release.</p>
<p>The original held comparator processed three to twelve separate already-produced
candidate cohort files against the same originally selected baseline. Original
source identity is unsigned; the operator-selected file order is not verified chronology.
The original input files are not copied to this kit.</p>
<h2>Open the original offline HUMAN tools</h2>
<ul><li><a href="PRIVATE-original-trend-studio.html">Original Lab Trajectory Studio</a>
 (select each numbered canonical cohort JSON below, in this order)</li>
<li><a href="PRIVATE-original-candidate-studio.html">Original Candidate Tradeoff Matrix</a>
 (import the same numbered canonical cohort JSON files)</li>
<li><a href="PRIVATE-original-review-desk.html">Original Benchmark HUMAN Review Desk</a>
 (triage original HOLD/review observations in any numbered canonical cohort)</li></ul>
<h2>Canonical original comparator results — selected order</h2>
<ol>""" + "".join(navigation) + """</ol>
<p><a href="PRIVATE-trajectory-receipt.json">PRIVATE unsigned source-byte receipt</a>;
<a href="PRIVATE-human-trajectory-followup.csv">SHA-bound blank HUMAN follow-up for adverse scenario positions</a>.</p>
<p>In each Studio, use its built-in local file chooser to import the numbered
canonical JSON files. Every original source parser still independently validates
the original schema. HUMAN stage, dates or model comparisons never become grants,
verified findings, verified fixes, access permissions, or scan schedules.</p>
<p>No network, model, assessment, grant, retest or deletion occurred.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></main></html>""")
        private_file(kit / "OPEN-PRIVATE.html", summary.encode("utf-8"))
        complete = True
        print("ORIGINAL TRAJECTORY: " + receipt["status"] +
              "; source-bound PRIVATE canonical cohort collection built.")
        print("OPEN LOCALLY: " + str(kit / "OPEN-PRIVATE.html"))
        return 3 if receipt["status"] == "HOLD" else 2
    finally:
        if not complete:
            shutil.rmtree(kit)


def main() -> int:
    cli = argparse.ArgumentParser(
        description="Private original benchmark cohort sequence → offline native HUMAN trend studios"
    )
    cli.add_argument("--kind", choices=("cohort", "scored"), default="cohort",
                     help="original cohort comparison or original scored ground-truth cohort")
    cli.add_argument("--baseline", required=True, help="unchanged original PRIVATE baseline cohort JSON")
    cli.add_argument("--candidate", action="append", required=True,
                     help="3-12 previously-produced PRIVATE candidate cohort JSON files in HUMAN-selected order")
    cli.add_argument("--private-parent", required=True,
                     help="existing owner-controlled 0700 PRIVATE directory")
    args = cli.parse_args()
    try:
        return prepare(args)
    except (Hold, OSError, ValueError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: original PRIVATE lab cohort sequence admission refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
