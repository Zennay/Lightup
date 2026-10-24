#!/usr/bin/env python3
"""Open a locally saved, UNVERIFIED source-free HUMAN browser session privately.

This is a separate self-declared HUMAN numeric session, NOT an original native
inbox, verified source or authenticated workroom. No client/security authority.
"""
from __future__ import annotations

import argparse
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

import portfolio

SESSION_KIND = "lightup.private_human_browser_numeric_session"
SESSION_DISPOSITION = "LOCAL_BROWSER_ONLY_NO_ORIGINAL_SOURCE_ATTESTATION"
SESSION_WARNING = ("Self-declared private HUMAN counts only; does not authenticate "
                   "original source, consent, findings, fixes, grants, or users.")
FIELDS = {"kind", "schema_version", "disposition", "packets",
          "earlier_numeric_aggregate", "warning", *portfolio.FLAGS}
PACKET = {"type", "slots", "questions", "plan"}
PLAN = {"attention", "dated", "stages"}
AGG = {"packets", "slots", "questions", "attention", "dated", "planned",
       "possible_same_numeric_shape_appearances", "stages"}
SUMMARY_KIND = "lightup.private_browser_session_human_numeric_preview"
WARNING = ("These numbers were restored from a self-declared LOCAL BROWSER "
           "numeric session, NOT from an authenticated original native source. "
           "No exact source, case/client identity, consent, verified fix, "
           "security finding, scan permission, or comparable cohort is proved.")


def require(ok: bool) -> None:
    portfolio.require(ok)


def stage_map(value: object, ceiling: int) -> dict:
    require(type(value) is dict and set(value) == set(portfolio.STAGES))
    return {name: portfolio.nonnegative(value[name], ceiling)
            for name in portfolio.STAGES}


def saved_plan(value: object, slots: int) -> dict:
    require(type(value) is dict and set(value) == PLAN)
    stages = stage_map(value["stages"], slots)
    require(sum(stages.values()) == slots)
    attention = portfolio.nonnegative(value["attention"], slots)
    require(attention == slots - stages["locally_answered"])
    return {"attention": attention, "due": portfolio.nonnegative(value["dated"], slots),
            "stages": stages}


def saved_aggregate(value: object) -> dict:
    require(type(value) is dict and set(value) == AGG)
    packets = portfolio.nonnegative(value["packets"], portfolio.MAX_FILES)
    slots = portfolio.nonnegative(value["slots"], 12 * portfolio.MAX_FILES)
    require(1 <= packets <= portfolio.MAX_FILES and packets <= slots <= 12 * packets)
    questions = portfolio.nonnegative(value["questions"],
                                      portfolio.MAX_FILES * portfolio.MAX_TOTAL)
    planned = portfolio.nonnegative(value["planned"], packets)
    attention = portfolio.nonnegative(value["attention"], slots)
    dated = portfolio.nonnegative(value["dated"], slots)
    overlap = portfolio.nonnegative(value["possible_same_numeric_shape_appearances"],
                                    packets)
    stages = stage_map(value["stages"], slots)
    require(sum(stages.values()) <= slots and
            (planned != 0 or (attention == 0 and dated == 0
                              and sum(stages.values()) == 0)))
    return {"packets": packets, "slots": slots, "questions": questions,
            "attention": attention, "dated": dated, "planned": planned,
            "possible_same_numeric_shape_appearances": overlap,
            "stages": stages}


def read_session(input_file: Path) -> tuple[list[dict], dict | None]:
    raw = portfolio.read_private(input_file)
    data = portfolio.parse(raw)
    portfolio.header(data, SESSION_KIND, FIELDS, SESSION_DISPOSITION)
    require(data["warning"] == SESSION_WARNING
            and type(data["packets"]) is list
            and 1 <= len(data["packets"]) <= portfolio.MAX_FILES)
    sources = []
    for item in data["packets"]:
        require(type(item) is dict and set(item) == PACKET
                and item["type"] in ("inbox", "workroom"))
        slots = portfolio.nonnegative(item["slots"], 12)
        require(1 <= slots <= 12)
        questions = portfolio.nonnegative(item["questions"])
        if item["type"] == "inbox":
            require(item["plan"] is None)
            planning = None
        else:
            planning = saved_plan(item["plan"], slots)
        sources.append({"source": item["type"], "slots": slots,
                        "questions": questions, "planning": planning})
    previous = (None if data["earlier_numeric_aggregate"] is None
                else saved_aggregate(data["earlier_numeric_aggregate"]))
    return sources, previous


def current_aggregate(sources: list[dict]) -> tuple[dict, dict]:
    detail = portfolio.aggregate(sources)
    stages = detail["stage_slot_appearances"]
    from collections import Counter
    shapes = Counter((row["type"], row["source_free_slots_not_unique"],
                      row["pending_human_questions_not_fixes"],
                      None if row["planning"] is None else (
                          row["planning"]["attention"], row["planning"]["due"],
                          *(row["planning"]["stages"][stage]
                            for stage in portfolio.STAGES)))
                     for row in detail["rows"])
    overlap = sum(n for n in shapes.values() if n > 1)
    numeric = {
        "packets": detail["packet_count"],
        "slots": detail["source_free_slot_appearances_not_unique"],
        "questions": detail["pending_human_questions_not_fixes"],
        "attention": detail["pending_local_human_attention_slot_appearances"],
        "dated": detail["due_slot_appearances_with_local_dates"],
        "planned": detail["packets_with_local_human_planning"],
        "possible_same_numeric_shape_appearances": overlap,
        "stages": stages,
    }
    return numeric, detail


def output_summary(sources: list[dict], previous: dict | None) -> dict:
    current, detail = current_aggregate(sources)
    differences = (None if previous is None else
                   {name: current[name] - previous[name] for name in
                    ("packets", "slots", "questions", "attention", "dated", "planned")})
    return {
        "kind": SUMMARY_KIND, "schema_version": 1,
        "disposition": "PRIVATE_BROWSER_NUMERIC_ONLY_NO_ORIGINAL_ATTESTATION",
        "current_numeric": current,
        "earlier_numeric": previous,
        "self_declared_counter_differences_not_fixes": differences,
        "packet_ordinal_counts_not_unique_cases": [
            {"packet": row["packet"], "source_type": row["type"],
             "slot_appearances": row["source_free_slots_not_unique"],
             "pending_human_questions_not_fixes":
                row["pending_human_questions_not_fixes"],
             "planning_provided": row["planning"] is not None}
            for row in detail["rows"]],
        "warning": WARNING,
        **{key: False for key in portfolio.FLAGS}
    }


def html_report(summary: dict, has_local_human_board: bool = False) -> bytes:
    cur = summary["current_numeric"]
    previous = summary["earlier_numeric"]
    rows = []
    for key in ("packets", "slots", "questions", "attention", "dated", "planned"):
        old = "Not supplied" if previous is None else str(previous[key])
        delta = ("Not comparable" if previous is None else
                 f"{cur[key] - previous[key]:+d} appearances")
        rows.append(f"<tr><th>{html.escape(key)}</th><td>{old}</td>"
                    f"<td>{cur[key]}</td><td>{delta}</td></tr>")
    stage_rows = "".join(
        f"<li><span>{html.escape(key.replace('_',' '))}</span>"
        f"<strong>{number}</strong></li>"
        for key, number in cur["stages"].items())
    human_actions_nav = (
        '<div class="card"><h2>Local HUMAN next-action desk</h2>'
        '<p>All local packet routing choices remain unverified. '
        'The selected board was compared with this anonymous numeric '
        'session, not with any original authenticated cases.</p>'
        '<p><a href="human-actions.html">Open the paired HUMAN action desk</a></p>'
        '</div>' if has_local_human_board else
        '<p>No separate HUMAN action desk attached.</p>')
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>LightUp | PRIVATE resumed HUMAN counts</title>
<style>:root{color-scheme:dark}body{margin:0;background:#0d1625;color:#eff6ff;
font:16px system-ui;padding:clamp(16px,4vw,48px)}main{max-width:960px;margin:auto}
p{line-height:1.6;color:#c9d5e8}h1{font-size:2.3rem}
.card{padding:20px;border-radius:14px;border:1px solid #38556a;background:#1a2b40}
table{width:100%%;min-width:620px;border-collapse:collapse}td,th{padding:12px;
text-align:left;border-bottom:1px solid #425971}aside{padding:16px;background:#342e35;
border-left:4px solid #f8ca88}ul{list-style:none;padding:0}li{padding:9px 0;
border-bottom:1px solid #425971;display:flex;justify-content:space-between}
.scroller{overflow-x:auto}small{color:#9bd7cc}a{color:#a6f1d1;font-weight:bold}</style></head><body><main>
<small>LIGHTUP · PRIVATE · SOURCE-FREE · DRAFT/HOLD</small>
<h1>Resumed HUMAN numeric session</h1>
<aside><strong>NOT original source verified.</strong><p>%s</p></aside>
<p>The current numbers and optional earlier baseline are self-reported browser
counters. A difference never demonstrates matched cases, a fix, permission,
or security progress.</p>
<div class="card"><div class="scroller"><table><thead><tr>
<th>Numeric counter</th><th>Earlier</th><th>Current</th>
<th>Difference (not verified fixes)</th></tr></thead><tbody>%s
</tbody></table></div></div>
<h2>Current locally entered planning stages</h2>
<div class="card"><ul>%s</ul></div>
%s
<p>This browser sheet is scriptless and standalone. No clients, source
artifacts, original fingerprints, notes, private dates, grant, or active target
work are included.</p></main></body></html>""" % (
        html.escape(WARNING), "".join(rows), stage_rows, human_actions_nav)
    return page.encode("utf-8")


def delta_csv(summary: dict) -> bytes:
    before = summary["earlier_numeric"]
    after = summary["current_numeric"]
    lines = ["counter,earlier,later,change_in_unverified_appearances"]
    for key in ("packets", "slots", "questions", "attention", "dated", "planned"):
        lines.append(",".join((key, "" if before is None else str(before[key]),
                               str(after[key]),
                               "" if before is None else str(after[key] - before[key]))))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def human_brief(summary: dict) -> bytes:
    cur = summary["current_numeric"]
    lines = [
        "LIGHTUP PRIVATE BROWSER HUMAN SESSION / NUMERIC ONLY",
        "INCUBATE M3/M7 PLAN-LAB ONLY - DRAFT/HOLD",
        WARNING,
        "",
        f"Packets (not unique original cases): {cur['packets']}",
        f"Slot appearances: {cur['slots']}",
        f"Unverified pending HUMAN questions: {cur['questions']}",
        f"Current HUMAN planning attention appearances: {cur['attention']}",
        f"Browser numeric earlier baseline present: {summary['earlier_numeric'] is not None}",
        "HUMAN FOLLOW-UP:",
        "Ask original source owners for a NEW authenticated source-bound export "
        "before taking any real action.",
        "Check original PRIVATE workroom assignments and date-bearing slots "
        "there; none can be reconstructed from this anonymous file.",
        "Do not interpret a smaller figure as remediation or test success.",
        "",
    ]
    return "\n".join(lines).encode("ascii")


def build(session_file: Path, destination: Path, board_file: Path | None = None) -> dict:
    require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    require(not destination.exists() and not destination.is_symlink())
    sources, previous = read_session(session_file)
    result = output_summary(sources, previous)
    # Optional exact numeric-session bound HUMAN-only routing, validated
    # before creating any new output. Never imbue session or board with grant.
    routing = None
    if board_file is not None:
        import action_board
        routing = action_board.summary(
            action_board.board_import(board_file, session_file))
    stage = Path(tempfile.mkdtemp(dir=destination.parent,
                                  prefix=".lightup-private-session-"))
    os.chmod(stage, 0o700)
    try:
        outputs = [
            ("index.html", html_report(result, routing is not None)),
            ("summary.json", portfolio.serialize(result)),
            ("continuity.csv", delta_csv(result)),
            ("human-followup.txt", human_brief(result)),
        ]
        if routing is not None:
            import action_board
            outputs.extend([
                ("human-actions.html", action_board.html_report(routing)),
                ("human-actions.json", portfolio.serialize(routing)),
                ("human-actions.csv", action_board.export_csv(routing)),
                ("human-actions-followup.txt", action_board.human_brief(routing)),
            ])
        for name, raw in outputs:
            portfolio.exclusive_write(stage / name, raw)
        fd = os.open(stage, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        portfolio.publish(stage, destination)
        fd = os.open(destination.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
        return result
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Make a new owner-private offline HUMAN numeric browser-session briefing. "
        "A resumed browser JSON never constitutes original source attestation."))
    parser.add_argument("--session", required=True, type=Path,
                        help="Absolute 0600 self-declared source-free browser session JSON")
    parser.add_argument("--output-dir", required=True, type=Path,
                        help="Fresh absolute 0700 private output directory")
    parser.add_argument("--board", type=Path,
                        help="Optional 0600 exact-numeric-match HUMAN routing JSON; "
                             "adds four private HUMAN-only action files")
    args = parser.parse_args()
    try:
        result = build(args.session, args.output_dir, args.board)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no complete PRIVATE HUMAN numeric session report published.",
              file=sys.stderr)
        return 2
    print(f"Private resumed HUMAN numeric report created: {args.output_dir.name}; "
          f"{result['current_numeric']['packets']} packet appearances; no authority.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
