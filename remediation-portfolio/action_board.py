#!/usr/bin/env python3
"""Source-free anonymous HUMAN routing board, exact numeric-session bound.

Self-declared local browser routing metadata only: not an original finding,
client record, authenticated export, assignment to a named person or authority.
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
import session

BOARD_KIND = "lightup.private_human_anonymous_followup_board"
BOARD_DISPOSITION = "LOCAL_HUMAN_FOLLOWUP_ONLY_NO_SOURCE_AUTHORITY"
BOARD_WARNING = ("Anonymous local HUMAN routing choices only. Not unique cases, "
                 "original source authentication, verified security findings, "
                 "consent, grant, remediation or action permission.")
FIELDS = {"kind", "schema_version", "disposition", "numeric_packets",
          "assignments", "warning", *portfolio.FLAGS}
PACKET_FIELDS = {"type", "slots", "questions", "plan"}
ASSIGNMENT_FIELDS = {"ordinal", "action", "state"}
ACTION_CODES = (
    "none",
    "request_fresh_source_export",
    "discuss_open_questions",
    "clarify_human_assignment",
    "reconcile_anonymous_coverage",
    "request_original_human_review",
)
STATE_CODES = ("not_triaged", "needs_human_followup", "waiting_original_owner",
               "locally_discussed")
DISPLAY = {
    "none": "No HUMAN next step chosen",
    "request_fresh_source_export": "Ask original owner for fresh source export",
    "discuss_open_questions": "Discuss unanswered HUMAN questions",
    "clarify_human_assignment": "Discuss local HUMAN slot assignment",
    "reconcile_anonymous_coverage": "Clarify possible packet coverage overlap",
    "request_original_human_review": "Ask original authorized HUMAN desk to review",
    "not_triaged": "Not triaged in this local browser",
    "needs_human_followup": "Needs HUMAN follow-up",
    "waiting_original_owner": "Waiting for original HUMAN source owner",
    "locally_discussed": "Locally discussed (not a verified fix)",
}
WARNING = ("This PRIVATE local routing board contains self-declared numeric "
           "packet appearances and HUMAN-only follow-up choices. Ordinals and "
           "identical counts do not identify cases, clients or security issues. "
           "Local routing state is NOT an original attestation, actual consent, "
           "verified remediation, audit verdict, scan authority or release.")


def require(condition: bool) -> None:
    portfolio.require(condition)


def native_packet(row: dict) -> dict:
    if row["planning"] is None:
        plan = None
    else:
        plan = {
            "attention": row["planning"]["attention"],
            "dated": row["planning"]["due"],
            "stages": {key: row["planning"]["stages"][key]
                       for key in portfolio.STAGES},
        }
    return {"type": row["source"], "slots": row["slots"],
            "questions": row["questions"], "plan": plan}


def board_import(board_path: Path, session_file: Path) -> list[dict]:
    # Private file admission and session schema are original standalone,
    # NEVER inferred from board claims.
    sources, _ = session.read_session(session_file)
    data = portfolio.parse(portfolio.read_private(board_path))
    portfolio.header(data, BOARD_KIND, FIELDS, BOARD_DISPOSITION)
    require(data["warning"] == BOARD_WARNING)
    require(type(data["numeric_packets"]) is list and
            len(data["numeric_packets"]) == len(sources) and
            type(data["assignments"]) is list and
            len(data["assignments"]) == len(sources))
    normalized = [native_packet(row) for row in sources]
    for claimed, original in zip(data["numeric_packets"], normalized):
        require(type(claimed) is dict and set(claimed) == PACKET_FIELDS
                and claimed == original)
    assignments = []
    for index, raw in enumerate(data["assignments"], 1):
        require(type(raw) is dict and set(raw) == ASSIGNMENT_FIELDS)
        require(type(raw["ordinal"]) is int and raw["ordinal"] == index
                and type(raw["action"]) is str and raw["action"] in ACTION_CODES
                and type(raw["state"]) is str and raw["state"] in STATE_CODES)
        original = normalized[index - 1]
        assignments.append({
            "packet_ordinal_not_original_case": index,
            "source_type": original["type"],
            "anonymous_slot_appearances_not_unique": original["slots"],
            "unverified_pending_human_questions": original["questions"],
            "local_followup_action_code": raw["action"],
            "local_planning_state_code": raw["state"],
        })
    return assignments


def summary(rows: list[dict]) -> dict:
    return {
        "kind": "lightup.private_human_anonymous_followup_board_preview",
        "schema_version": 1,
        "disposition": "LOCAL_HUMAN_ROUTING_NO_ORIGINAL_AUTHORITY",
        "packet_appearances_not_unique": len(rows),
        "unverified_pending_human_questions": sum(
            row["unverified_pending_human_questions"] for row in rows),
        "local_followup_action_counts": {
            code: sum(row["local_followup_action_code"] == code for row in rows)
            for code in ACTION_CODES},
        "local_planning_state_counts": {
            code: sum(row["local_planning_state_code"] == code for row in rows)
            for code in STATE_CODES},
        "anonymous_human_followup_rows": rows,
        "warning": WARNING,
        **{name: False for name in portfolio.FLAGS},
    }


def html_report(packet: dict) -> bytes:
    rows = packet["anonymous_human_followup_rows"]
    cards = "".join(
        "<tr><th>%d</th><td>%s</td><td>%d</td><td>%d</td><td>%s</td><td>%s</td></tr>"
        % (
            row["packet_ordinal_not_original_case"],
            html.escape(row["source_type"]),
            row["anonymous_slot_appearances_not_unique"],
            row["unverified_pending_human_questions"],
            html.escape(DISPLAY[row["local_followup_action_code"]]),
            html.escape(DISPLAY[row["local_planning_state_code"]]),
        ) for row in rows
    )
    page = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN anonymous routing desk</title>
<style>:root{color-scheme:dark}*{box-sizing:border-box}
body{background:#101b2b;color:#f3f9ff;font:16px/1.5 system-ui;
padding:clamp(16px,4vw,48px);margin:0}main{max-width:1120px;margin:auto}
h1{font-size:clamp(2rem,4vw,3rem)}.small{letter-spacing:.1em;
text-transform:uppercase;color:#96e1c4;font-size:12px}
.warning{background:#392e34;border-left:4px solid #f3c37b;
padding:16px 20px}p{color:#cbd6e2}table{width:100%%;min-width:850px;
border-collapse:collapse}th,td{padding:13px;text-align:left;
border-bottom:1px solid #44566b}.scroll{overflow:auto;
border:1px solid #44566b;border-radius:12px;margin-top:20px}
summary{font-weight:700}</style></head><body><main>
<div class="small">LightUp / PRIVATE / HUMAN-only / Incubate DRAFT HOLD</div>
<h1>Anonymous HUMAN follow-up desk</h1>
<aside class="warning"><strong>Original source NOT authenticated.</strong>
<p>%s</p></aside>
<p>%d anonymous packet appearances and %d local HUMAN question appearances.
Packet ordinals have no original source identity and the routing selections
are proposals only. They do not update original remediation records.</p>
<div class="scroll"><table><thead><tr><th>Local ordinal</th><th>Count source</th>
<th>Slots</th><th>Open HUMAN questions</th><th>Chosen HUMAN next step</th>
<th>Local routing state</th></tr></thead><tbody>%s</tbody></table></div>
<p>Continue in the genuinely authenticated original PRIVATE HUMAN source
desk before taking any real action. No network, scripts, original evidence,
scans, consents or client data in this report.</p></main></body></html>
""" % (html.escape(WARNING), packet["packet_appearances_not_unique"],
       packet["unverified_pending_human_questions"], cards)
    return page.encode("utf-8")


def export_csv(packet: dict) -> bytes:
    rows = packet["anonymous_human_followup_rows"]
    lines = ["packet_ordinal_not_original_case,source_type,anonymous_slot_appearances_not_unique,"
             "unverified_pending_human_questions,local_followup_action_code,local_planning_state_code"]
    for row in rows:
        lines.append(",".join((
            str(row["packet_ordinal_not_original_case"]),
            row["source_type"],
            str(row["anonymous_slot_appearances_not_unique"]),
            str(row["unverified_pending_human_questions"]),
            row["local_followup_action_code"], row["local_planning_state_code"],
        )))
    return ("\r\n".join(lines) + "\r\n").encode("ascii")


def human_brief(packet: dict) -> bytes:
    rows = packet["anonymous_human_followup_rows"]
    lines = [
        "LIGHTUP PRIVATE HUMAN ANONYMOUS FOLLOW-UP BOARD",
        "INCUBATE M3/M7 PLAN-LAB ONLY - DRAFT HOLD",
        WARNING, "",
        "Human-selected next steps and local statuses are NOT original source records.",
        "",
    ]
    for row in rows:
        lines.extend((
            f"Anonymous local packet {row['packet_ordinal_not_original_case']}:",
            f"  HUMAN next step: {DISPLAY[row['local_followup_action_code']]}",
            f"  Local state: {DISPLAY[row['local_planning_state_code']]}",
            "  Return to original source owner for authentic current work.",
        ))
    lines.extend(("", "Do not claim any consent, verified fixes, "
                  "source authorization, client/tenant identity or scan grant.", ""))
    return "\n".join(lines).encode("ascii")


def build(board_path: Path, session_file: Path, destination: Path) -> dict:
    require(destination.is_absolute())
    portfolio.private_dir(destination.parent)
    require(not destination.exists() and not destination.is_symlink())
    rows = board_import(board_path, session_file)
    packet = summary(rows)
    stage = Path(tempfile.mkdtemp(dir=destination.parent,
                                  prefix=".lightup-private-human-board-"))
    os.chmod(stage, 0o700)
    try:
        for name, raw in (
            ("index.html", html_report(packet)),
            ("summary.json", portfolio.serialize(packet)),
            ("human-followup.csv", export_csv(packet)),
            ("human-followup.txt", human_brief(packet)),
        ):
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
        return packet
    finally:
        if stage.exists():
            shutil.rmtree(stage)


def main() -> int:
    parser = argparse.ArgumentParser(description=(
        "Produce PRIVATE source-free HUMAN next-action board from exactly "
        "matching anonymous numeric session + follow-up JSON."))
    parser.add_argument("--session", type=Path, required=True,
                        help="Absolute original self-declared 0600 browser session JSON")
    parser.add_argument("--board", type=Path, required=True,
                        help="Absolute owner-private 0600 browser follow-up board JSON")
    parser.add_argument("--output-dir", type=Path, required=True,
                        help="Fresh owner-private 0700 output folder (never overwritten)")
    args = parser.parse_args()
    try:
        packet = build(args.board, args.session, args.output_dir)
    except (ValueError, OSError, RecursionError):
        print("HOLD: no complete source-free HUMAN routing board published.",
              file=sys.stderr)
        return 2
    print("PRIVATE HUMAN routing board created: %d anonymous packet appearances; "
          "no source, authorization, verified fixes or release." %
          packet["packet_appearances_not_unique"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
