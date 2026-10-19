#!/usr/bin/env python3
"""Compare complete PRIVATE source-free HUMAN portfolios, with no case matching."""
from __future__ import annotations

import argparse
import html
from pathlib import Path
import shutil
import sys
import tempfile
import os

import portfolio

FIELDS = {"kind", "schema_version", "disposition", "packet_count",
          "source_free_slot_appearances_not_unique",
          "pending_human_questions_not_fixes",
          "packets_with_local_human_planning",
          "pending_local_human_attention_slot_appearances",
          "due_slot_appearances_with_local_dates", "stage_slot_appearances",
          "rows", "warning", *portfolio.FLAGS}
ROW = {"packet", "type", "source_free_slots_not_unique",
       "pending_human_questions_not_fixes", "planning"}
PLANNING = {"stages", "attention", "due"}
WARNING = ("LEFT and RIGHT are independent, self-reported packet sums. "
           "No stable customer/case identity, consistent sample, causal "
           "improvement, consent or verified remediation can be inferred. "
           "Lower apparent workload may mean omitted inputs, not fixed findings.")


def check_portfolio(root: Path) -> dict:
    """Recreate every generated source-free member; original source never opened."""
    portfolio.private_dir(root)
    portfolio.require({p.name for p in root.iterdir()} ==
                      {"index.html", "summary.json", "counts.csv",
                       "human-volume-queue.csv", "human-followup.txt"})
    raw = portfolio.read_private(root / "summary.json")
    summary = portfolio.parse(raw)
    portfolio.require(set(summary) == FIELDS
                      and summary.get("kind") == portfolio.PORTFOLIO_KIND
                      and summary.get("schema_version") == 1
                      and type(summary.get("rows")) is list
                      and 1 <= len(summary["rows"]) <= portfolio.MAX_FILES
                      and all(summary.get(flag) is False for flag in portfolio.FLAGS))
    prepared = []
    for i, row in enumerate(summary["rows"], 1):
        portfolio.require(type(row) is dict and set(row) == ROW
                          and type(row["packet"]) is int and row["packet"] == i
                          and row["type"] in ("inbox", "workroom"))
        slots = portfolio.nonnegative(row["source_free_slots_not_unique"], 12)
        portfolio.require(1 <= slots <= 12)
        questions = portfolio.nonnegative(
            row["pending_human_questions_not_fixes"])
        plan = row["planning"]
        if row["type"] == "inbox":
            portfolio.require(plan is None)
        else:
            portfolio.require(type(plan) is dict and set(plan) == PLANNING
                              and type(plan["stages"]) is dict
                              and set(plan["stages"]) == set(portfolio.STAGES))
            stage = {key: portfolio.nonnegative(plan["stages"][key], slots)
                     for key in portfolio.STAGES}
            portfolio.require(sum(stage.values()) == slots
                              and portfolio.nonnegative(plan["attention"], slots)
                                  == slots - stage["locally_answered"]
                              and portfolio.nonnegative(plan["due"], slots) <= slots)
            plan = {"stages": stage, "attention": plan["attention"],
                    "due": plan["due"]}
        prepared.append({"source": row["type"], "slots": slots,
                         "questions": questions, "planning": plan})
    expected = portfolio.aggregate(prepared)
    portfolio.require(summary == expected and raw == portfolio.serialize(expected))
    for filename, actual in (("index.html", portfolio.html_bytes(expected)),
                             ("counts.csv", portfolio.csv_bytes(expected)),
                             ("human-volume-queue.csv", portfolio.queue_bytes(expected)),
                             ("human-followup.txt", portfolio.brief_bytes(expected))):
        portfolio.require(portfolio.read_private(root / filename) == actual)
    return expected


def compare(earlier: dict, later: dict) -> dict:
    tracked = ("packet_count", "source_free_slot_appearances_not_unique",
               "pending_human_questions_not_fixes",
               "packets_with_local_human_planning",
               "pending_local_human_attention_slot_appearances",
               "due_slot_appearances_with_local_dates")
    metrics = {
        key: {"earlier": earlier[key], "later": later[key],
              "change_in_packet_appearances": later[key] - earlier[key]}
        for key in tracked
    }
    stages = {name: {
        "earlier": earlier["stage_slot_appearances"][name],
        "later": later["stage_slot_appearances"][name],
        "change_in_packet_appearances":
            later["stage_slot_appearances"][name]
            - earlier["stage_slot_appearances"][name]
    } for name in portfolio.STAGES}
    return {
        "kind": "lightup.private_human_portfolio_two_snapshot_comparison",
        "schema_version": 1,
        "disposition": "PRIVATE_HUMAN_SELF_REPORTED_PACKET_DELTA_NO_AUTHORITY",
        "metrics": metrics,
        "planning_stage_appearances": stages,
        "warning": WARNING,
        **{f: False for f in portfolio.FLAGS},
    }


def csv_bytes(report: dict) -> bytes:
    lines = ["counter,earlier,later,packet_appearance_change"]
    for name, row in list(report["metrics"].items()) + [
        ("stage_" + k, v) for k, v in report["planning_stage_appearances"].items()
    ]:
        lines.append(",".join((name, str(row["earlier"]),
                               str(row["later"]),
                               str(row["change_in_packet_appearances"]))))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def brief_bytes(report: dict) -> bytes:
    lines = ["LIGHTUP PRIVATE HUMAN TWO-SNAPSHOT COMPARISON",
             "LOCAL COUNTER DELTAS ONLY; NO VERIFIED FIX OR UNIQUE CUSTOMER",
             WARNING, "", "Earlier and later are manually selected packets.",
             "There is no claim that they represent the same exact case set.", ""]
    for name, row in report["metrics"].items():
        lines.append(f"{name}: {row['earlier']} -> {row['later']} "
                     f"(reported change {row['change_in_packet_appearances']:+d})")
    lines.extend(("", "HUMAN HANDOFF",
                  "Review missing/new source packet coverage and overlap privately.",
                  "Do not interpret a lower count as remediation, retest success "
                  "or verified security improvement.",
                  "Any next action remains in the original authorized HUMAN desk."))
    return ("\n".join(lines) + "\n").encode("ascii")


def html_bytes(report: dict) -> bytes:
    rows = []
    for name, entry in list(report["metrics"].items()) + [
        ("stage_" + k, v) for k, v in report["planning_stage_appearances"].items()
    ]:
        rows.append("<tr><th>%s</th><td>%d</td><td>%d</td><td>%+d</td></tr>" %
                    (html.escape(name.replace("_", " ")), entry["earlier"],
                     entry["later"], entry["change_in_packet_appearances"]))
    return ("""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp PRIVATE HUMAN | Two snapshots</title>
<style>:root{color-scheme:dark}body{font:16px system-ui;color:#eff5fe;background:#111c2a;
margin:0;padding:32px}main{max-width:940px;margin:auto}h1{font-size:2rem}
p{line-height:1.6;color:#c2cfdf}table{border-collapse:collapse;width:100%%}
td,th{padding:13px;text-align:left;border-bottom:1px solid #465570}
section{overflow-x:auto;background:#1b2b3e;padding:20px;border-radius:14px}
aside{background:#343036;border-left:3px solid #ebbf7d;padding:20px}
small{color:#b5cedd}</style></head><body><main>
<small>LIGHTUP / SOURCE-FREE / OFFLINE / DRAFT HOLD</small>
<h1>Two-snapshot HUMAN workload comparison</h1>
<p>Self-reported counts only. Earlier and later do not prove matching cases,
remediation, retest, risk reduction, authority, or release.</p>
<aside><strong>Do not call the difference progress.</strong><p>%s</p></aside>
<section><table><thead><tr><th>Human count</th><th>Earlier</th>
<th>Later</th><th>Change in appearances</th></tr></thead>
<tbody>%s</tbody></table></section>
<p>No names, original evidence, paths, private source identifiers, dates,
external scripts, network or active security operations.</p></main></body></html>
""" % (html.escape(WARNING), "".join(rows))).encode("utf-8")


def build(left: Path, right: Path, output: Path) -> None:
    portfolio.require(output.is_absolute())
    portfolio.private_dir(output.parent)
    portfolio.require(not output.exists() and not output.is_symlink())
    # Inputs fully regenerated and admitted before output is even staged.
    left_data = check_portfolio(left)
    right_data = check_portfolio(right)
    report = compare(left_data, right_data)
    stage = Path(tempfile.mkdtemp(prefix=".lightup-human-compare-",
                                  dir=output.parent))
    os.chmod(stage, 0o700)
    try:
        for name, data in (("index.html", html_bytes(report)),
                           ("comparison.json", portfolio.serialize(report)),
                           ("comparison.csv", csv_bytes(report)),
                           ("human-interpretation.txt", brief_bytes(report))):
            portfolio.exclusive_write(stage / name, data)
        dir_fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
        portfolio.publish(stage, output)
        parent_fd = os.open(output.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent_fd)
        finally:
            os.close(parent_fd)
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE local HUMAN portfolio snapshots; changes are not verified fixes")
    parser.add_argument("--earlier", required=True, type=Path,
                        help="Absolute complete PRIVATE portfolio directory")
    parser.add_argument("--later", required=True, type=Path,
                        help="Absolute complete PRIVATE portfolio directory")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="Fresh private comparison directory, no overwrite")
    args = parser.parse_args()
    try:
        build(args.earlier, args.later, args.output_dir)
    except (OSError, ValueError, portfolio.Hold):
        print("HOLD: no complete two-snapshot HUMAN comparison published",
              file=sys.stderr)
        return 2
    print("PRIVATE HUMAN comparison published; counter deltas are not fixes.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
