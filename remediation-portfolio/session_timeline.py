#!/usr/bin/env python3
"""Sequence 2–12 locally saved PRIVATE HUMAN numeric sessions; no real case matching.

Session order is explicitly supplied by the human. Ordinal 1..N is not a date,
audit event, longitudinal cohort, original evidence or verified remediation.
"""
from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

import portfolio
import session

KIND = "lightup.private_human_numeric_session_timeline"
WARNING = ("Separate local browser numeric sessions may contain different or "
           "repeated source-free packets. Differences in anonymous packet "
           "appearances are NOT matched cases, verified fixes, validated "
           "evidence, authenticated source, consent, actual progress or "
           "permission for active assessments. Ordinals are not timestamps.")
FIELDS = ("packets", "slots", "questions", "attention", "dated", "planned")
MAX = 12


def load_sessions(paths: list[Path]) -> dict:
    portfolio.require(2 <= len(paths) <= MAX)
    rows = []
    # Equal file bytes are one identical exported file, not two independent
    # snapshots. Do NOT collapse different files with identical numeric shapes.
    seen_bytes = set()
    for index, path in enumerate(paths, 1):
        raw = portfolio.read_private(path)
        digest = hashlib.sha256(raw).digest()
        portfolio.require(digest not in seen_bytes)
        seen_bytes.add(digest)
        sources, earlier = session.read_session(path)
        numeric, _ = session.current_aggregate(sources)
        row = {
            "human_selected_ordinal_not_date": index,
            "declared_prior_numeric_baseline_in_saved_session": earlier is not None,
            **{key: numeric[key] for key in FIELDS},
            "human_stage_appearances": numeric["stages"],
            "possibly_same_numeric_shape_appearances_not_duplicates":
                numeric["possible_same_numeric_shape_appearances"],
        }
        rows.append(row)
    changes = []
    for previous, current in zip(rows, rows[1:]):
        deltas = {key: current[key] - previous[key] for key in FIELDS}
        changes.append({
            "from_selected_ordinal": previous["human_selected_ordinal_not_date"],
            "to_selected_ordinal": current["human_selected_ordinal_not_date"],
            "reported_count_changes_not_verified_outcomes": deltas,
            "declared_packet_count_changed": previous["packets"] != current["packets"],
            "same_case_coverage_proven": False,
            "retest_or_remediation_verified": False,
        })
    return {
        "kind": KIND,
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_NUMBERED_SNAPSHOTS_ONLY_NO_SOURCE_AUTHORITY",
        "snapshot_count": len(rows),
        "snapshots": rows,
        "adjacent_counter_differences": changes,
        "warning": WARNING,
        **{flag: False for flag in portfolio.FLAGS},
    }


def series_csv(report: dict) -> bytes:
    headers = ("moment_ordinal_not_date", *FIELDS,
               "unassigned", "assigned", "waiting_human", "locally_answered",
               "possible_identical_numeric_profile_appearances_not_duplicates",
               "prior_baseline_declared")
    lines = [",".join(headers)]
    for row in report["snapshots"]:
        cells = [str(row["human_selected_ordinal_not_date"])]
        cells += [str(row[key]) for key in FIELDS]
        cells += [str(row["human_stage_appearances"][key])
                  for key in portfolio.STAGES]
        cells += [
            str(row["possibly_same_numeric_shape_appearances_not_duplicates"]),
            "1" if row["declared_prior_numeric_baseline_in_saved_session"] else "0",
        ]
        lines.append(",".join(cells))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def report_brief(report: dict) -> bytes:
    lines = ["LIGHTUP / PRIVATE SOURCE-FREE HUMAN WORKLOAD SEQUENCE",
             "Incubate M3/M7 PLAN-LAB ONLY / DRAFT HOLD",
             WARNING, "",
             f"User-ordered numeric moments: {report['snapshot_count']}",
             "MOMENT COVERAGE:"]
    for row in report["snapshots"]:
        lines.append(
            f"Moment {row['human_selected_ordinal_not_date']}: "
            f"{row['packets']} packet appearances / {row['slots']} slot "
            f"appearances / {row['questions']} pending HUMAN questions (not fixes)")
    lines += ["", "HUMAN FOLLOW-UP:",
              "Ask original authenticated source owner for a CURRENT native "
              "counts export and genuine source/consent confirmation.",
              "Do not interpret decreasing counts as a repaired finding.",
              "Every item may have different source coverage or repeated "
              "anonymous packets.",
              "No original identity, dates, retest or remediation status can "
              "be established from these files.", ""]
    for diff in report["adjacent_counter_differences"]:
        if diff["declared_packet_count_changed"]:
            lines.append(
                f"Coverage caution: numbered moments "
                f"{diff['from_selected_ordinal']} -> {diff['to_selected_ordinal']} "
                "report different packet counts. No cohort claim possible.")
    return "\n".join(lines).encode("ascii")


def svg_line(rows: list[dict], field: str, title: str) -> str:
    values = [r[field] for r in rows]
    top = max(1, max(values))
    miny, height = 30, 140
    coords = [(55 + int(i*700 / max(1, len(rows)-1)),
               miny + int(height*(1-value/top)))
              for i, value in enumerate(values)]
    points = " ".join(f"{x},{y}" for x,y in coords)
    marks = "".join(
        f'<circle cx="{x}" cy="{y}" r="5" fill="#a2f8db"/>'
        f'<text x="{x}" y="211" text-anchor="middle" fill="#d8e8ff"'
        f' font-size="12">{i+1}</text>'
        for i,(x,y) in enumerate(coords))
    return (f'<section class="card"><h2>{html.escape(title)}</h2>'
            f'<p>Source-free self-reported packet appearances; no verified trend.</p>'
            f'<svg viewBox="0 0 820 235" role="img" '
            f'aria-label="{html.escape(title, quote=True)} numbered moments '
            f'with numeric values {html.escape(", ".join(map(str, values)), quote=True)}">'
            f'<line x1="55" y1="170" x2="755" y2="170" stroke="#53647e"/>'
            f'<polyline fill="none" stroke="#6dd8b5" stroke-width="3"'
            f' points="{points}"/>{marks}'
            f'<text x="20" y="22" fill="#bfd8e3" font-size="12">'
            f'max {top}</text></svg></section>')


def html_page(report: dict) -> bytes:
    rows = "".join(
        "<tr><th>Moment %d</th><td>%d</td><td>%d</td><td>%d</td>"
        "<td>%d</td><td>%s</td></tr>" %
        (r["human_selected_ordinal_not_date"], r["packets"], r["slots"],
         r["questions"], r["attention"],
         "Declared earlier numeric" if r[
             "declared_prior_numeric_baseline_in_saved_session"]
         else "Not provided")
        for r in report["snapshots"])
    cautions = "".join(
        f"<li>Moments {diff['from_selected_ordinal']} and "
        f"{diff['to_selected_ordinal']} have different declared packet counts. "
        "Not the same proven cohort.</li>"
        for diff in report["adjacent_counter_differences"]
        if diff["declared_packet_count_changed"])
    metrics = (
        svg_line(report["snapshots"], "questions", "HUMAN question appearances"),
        svg_line(report["snapshots"], "slots", "Source-free slot appearances"),
        svg_line(report["snapshots"], "attention", "Declared planning attention"),
    )
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp | PRIVATE HUMAN numbered session timeline</title>
<style>:root{color-scheme:dark}body{margin:0;background:#101927;color:#edf7ff;
font:16px/1.6 system-ui;padding:clamp(16px,4vw,48px)}
main{max-width:1060px;margin:auto}h1{font-size:2.3rem}
p{color:#c2d0e0}.card{background:#1a2a3c;border-radius:14px;padding:18px;
margin:20px 0;border:1px solid #3b536b}svg{display:block;width:100%%;height:auto}
aside{padding:16px 22px;border-left:4px solid #f6cb84;background:#333039}
table{width:100%%;border-collapse:collapse;min-width:690px}th,td{padding:12px;
text-align:left;border-bottom:1px solid #475970}th{font-weight:700}
.scroll{overflow:auto}small{color:#a2f8db}</style></head><body><main>
<small>LIGHTUP / OFFLINE / PRIVATE / DRAFT HOLD</small>
<h1>HUMAN numbered review moments</h1>
<aside><strong>These are NOT real dated case histories.</strong>
<p>%s</p></aside>
<p>The order is exactly the human-selected input order. Dates, case identity,
consent and original evidence are absent. A decline cannot be claimed as
a verified security improvement.</p>
%s
<section class="card"><h2>All HUMAN numeric moments</h2><div class="scroll">
<table><thead><tr><th>Ordinal only</th><th>Packets</th><th>Slots</th>
<th>Questions</th><th>Planning attention</th><th>Prior baseline inside file</th>
</tr></thead><tbody>%s</tbody></table></div></section>
<section class="card"><h2>Coverage cautions</h2><ul>%s</ul>
<p>Equal packet counts still do not prove matching source work.</p></section>
<footer><p>Completely offline, no browser scripts, external files,
remote connections, targets, scans or original evidence.</p></footer>
</main></body></html>""" % (
        html.escape(WARNING), "".join(metrics), rows,
        cautions or "<li>No declared packet count changes. Case coverage still unknown.</li>")
    return page.encode("utf-8")


def build(files: list[Path], output: Path) -> dict:
    portfolio.require(output.is_absolute())
    portfolio.private_dir(output.parent)
    portfolio.require(not output.exists() and not output.is_symlink())
    result = load_sessions(files)  # All admitted before any output.
    stage = Path(tempfile.mkdtemp(dir=output.parent,
                                  prefix=".lightup-private-timeline-"))
    os.chmod(stage, 0o700)
    try:
        for name, raw in (
            ("index.html", html_page(result)),
            ("series.json", portfolio.serialize(result)),
            ("series.csv", series_csv(result)),
            ("human-followup.txt", report_brief(result)),
        ):
            portfolio.exclusive_write(stage / name, raw)
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        portfolio.publish(stage, output)
        fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="2-12 HUMAN-ordered browser numeric sessions; NO original case history.")
    parser.add_argument("--session", type=Path, action="append", required=True,
                        help="Repeat for 2-12 original 0600 locally saved browser session JSON files IN INTENDED ORDER")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="New exclusive 0700 owner-private offline output directory")
    args = parser.parse_args()
    try:
        result = build(args.session, args.output_dir)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no complete private source-free HUMAN sequence published.",
              file=sys.stderr)
        return 2
    print(f"Private HUMAN numbered sequence published for "
          f"{result['snapshot_count']} self-reported numeric moments. "
          "No case/consent/fix proof.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
