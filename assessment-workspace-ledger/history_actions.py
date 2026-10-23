#!/usr/bin/env python3
"""PRIVATE source-locked HUMAN follow-up action board from real archived reviewer choices.

Offline human proposals, not job dispatch, task scheduler, scan or authorization.
The original customer kits are never opened by this historical workflow.
"""
from __future__ import annotations

import argparse
import csv
from datetime import date
import html
import io
import json
import os
from pathlib import Path
import re
import shutil
import stat
import sys

from history import load_history, summarize
from history_human import expected_rows
from history_team import (
    exact_context, literal_false_authority, packets_from_paths, parse_choices,
    private_parent_for_originals, MAX_REVIEW_CSV,
)
from ledger import (
    FLAGS, Hold, MAX_MANIFEST, canonical, digest, html_page, new_private,
    object_unique, read_owner_file, reject, safe_human, write_private,
)

MAX_ACTION_CSV = 196608
STATES = ("unassigned", "proposed", "waiting_on_human", "hold")
PRIORITIES = ("unset", "human_urgent", "near_term", "routine")
HEADERS = (
    "transition", "kit_ordinal", "original_ledger_sha256", "original_kit_digest",
    "original_team_choice_sha256", "original_reviewer_sha256", "original_human_stage",
    "action_status", "human_priority", "accountable_human", "proposed_day",
    "next_human_step",
)


def admit_team(context_path, choice_path, choice_csv_path):
    """Only canonical ORIGINAL native packets and their original review CSV."""
    context_raw = read_owner_file(context_path, MAX_MANIFEST)
    context = exact_context(context_raw)
    if context_raw != canonical(context):
        reject("PRIVATE HOLD: team context is not the original native canonical bytes")
    ledger_paths = [r["path"] for r in context["original_ledgers"]]
    sources = load_history(ledger_paths)
    if [item["sha256"] for item in sources] != [
            r["sha256"] for r in context["original_ledgers"]]:
        reject("PRIVATE HOLD: original archived ledgers changed")
    transitions, _, _ = summarize(sources)
    expected = expected_rows(sources, transitions)
    packets = packets_from_paths(
        [r["path"] for r in context["original_reviewers"]], sources, expected,
        [r["sha256"] for r in context["original_reviewers"]],
    )
    original_csv = read_owner_file(choice_csv_path, MAX_REVIEW_CSV)
    choices = parse_choices(original_csv, expected, packets)
    selected_raw = read_owner_file(choice_path, MAX_MANIFEST)
    try:
        selected = json.loads(selected_raw.decode("utf-8"),
                              object_pairs_hook=object_unique,
                              parse_constant=lambda _: reject("PRIVATE HOLD: nonfinite team choice"))
    except (UnicodeError, TypeError, ValueError) as exc:
        raise Hold("PRIVATE HOLD: unreadable original team choices") from exc
    if not isinstance(selected, dict) or set(selected) != {
        "schema", "authority", "sources_reopened", "review_only",
        "context_sha256", "reviewer_packet_sha256", "human_choice_csv_sha256", "rows"
    } or selected["schema"] != "lightup.private.workspace-ledger-team-human.v1":
        reject("PRIVATE HOLD: original team choice packet schema")
    if (not literal_false_authority(selected["authority"]) or
        selected["sources_reopened"] is not False or
        selected["review_only"] is not True or
        selected["context_sha256"] != digest(context_raw) or
        selected["human_choice_csv_sha256"] != digest(original_csv) or
        selected["reviewer_packet_sha256"] != [p["sha256"] for p in packets] or
        selected["rows"] != choices or selected_raw != canonical(selected)):
        reject("PRIVATE HOLD: original team choice not EXACT native finalized source")
    return {
        "context": context, "context_raw": context_raw, "sources": sources,
        "choice_sha": digest(selected_raw), "csv_sha": digest(original_csv),
        "rows": choices, "choice_raw": selected_raw,
    }


def template_rows(case):
    return [{
        "transition": str(row["transition"]),
        "kit_ordinal": str(row["kit_ordinal"]),
        "original_ledger_sha256": row["to_ledger_sha256"],
        "original_kit_digest": row["to_kit_digest"],
        "original_team_choice_sha256": case["choice_sha"],
        "original_reviewer_sha256": row["human_selected_packet"],
        "original_human_stage": row["human_stage"],
        "action_status": "unassigned", "human_priority": "unset",
        "accountable_human": "", "proposed_day": "", "next_human_step": "",
    } for row in case["rows"]]


def serialize_csv(rows):
    out = io.StringIO(newline="")
    writer = csv.DictWriter(out, fieldnames=HEADERS, lineterminator="\n")
    writer.writeheader()
    writer.writerows(rows)
    return out.getvalue()


def admission(raw, expected):
    if not raw or len(raw) > MAX_ACTION_CSV:
        reject("PRIVATE HOLD: action CSV empty or oversized")
    try:
        source = raw.decode("utf-8", errors="strict")
        if "\r" in source or "\x00" in source:
            reject("PRIVATE HOLD: invalid action CSV control characters")
        rows = list(csv.DictReader(io.StringIO(source, newline=""), strict=True))
        reader = csv.DictReader(io.StringIO(source, newline=""), strict=True)
        if tuple(reader.fieldnames or ()) != HEADERS:
            reject("PRIVATE HOLD: nonnative HUMAN action CSV columns")
    except (UnicodeError, csv.Error, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: invalid HUMAN action CSV") from exc
    if len(rows) != len(expected):
        reject("PRIVATE HOLD: HUMAN action CSV original row count")
    result = []
    for original, row in zip(expected, rows):
        if None in row or set(row) != set(HEADERS) or any(
            row[field] != original[field] for field in HEADERS[:7]
        ):
            reject("PRIVATE HOLD: attempted original source/row substitution")
        status, priority = row["action_status"], row["human_priority"]
        if status not in STATES or priority not in PRIORITIES:
            reject("PRIVATE HOLD: HUMAN action state or priority")
        owner = safe_human(row["accountable_human"], 80)
        note = safe_human(row["next_human_step"], 240)
        if "\t" in owner + note or "\n" in owner + note:
            reject("PRIVATE HOLD: multiline HUMAN text")
        proposed_day = row["proposed_day"]
        if proposed_day:
            if not re.fullmatch(r"\d{4}-\d{2}-\d{2}", proposed_day):
                reject("PRIVATE HOLD: literal yyyy-mm-dd proposed date required")
            try:
                date.fromisoformat(proposed_day)
            except ValueError:
                reject("PRIVATE HOLD: invalid proposed HUMAN day")
        if status == "unassigned" and (
            priority != "unset" or owner or proposed_day or note
        ):
            reject("PRIVATE HOLD: unassigned cannot invent work")
        if status in ("proposed", "waiting_on_human") and not note:
            reject("PRIVATE HOLD: actionable HUMAN proposal needs an explicit next step")
        if status == "proposed" and not owner:
            reject("PRIVATE HOLD: proposal requires explicit accountable HUMAN")
        result.append({
            "transition": int(original["transition"]),
            "kit_ordinal": int(original["kit_ordinal"]),
            "original_ledger_sha256": original["original_ledger_sha256"],
            "original_kit_digest": original["original_kit_digest"],
            "original_team_choice_sha256": original["original_team_choice_sha256"],
            "original_reviewer_sha256": original["original_reviewer_sha256"],
            "original_human_stage": original["original_human_stage"],
            "action_status": status, "human_priority": priority,
            "accountable_human": owner, "proposed_day": proposed_day,
            "next_human_step": note,
        })
    return result


def read_browser_file(path):
    file = Path(path)
    if not file.is_absolute() or not re.fullmatch(
        r"HUMAN-action-plan(?: ?\([1-9][0-9]{0,3}\))?\.csv", file.name
    ):
        reject("PRIVATE HOLD: select explicit original HUMAN-action-plan.csv browser download")
    fd = os.open(file, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    try:
        before = os.fstat(fd)
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid() or
            before.st_nlink != 1 or before.st_size <= 0 or before.st_size > MAX_ACTION_CSV):
            reject("PRIVATE HOLD: browser CSV nonregular, hardlinked, foreign or oversized")
        content = bytearray()
        while True:
            part = os.read(fd, 32768)
            if not part:
                break
            content.extend(part)
            if len(content) > MAX_ACTION_CSV:
                reject("PRIVATE HOLD: oversized browser downloaded actions")
        after = os.fstat(fd)
        if ((before.st_dev, before.st_ino, before.st_size,
              before.st_mtime_ns, before.st_ctime_ns) !=
            (after.st_dev, after.st_ino, after.st_size,
             after.st_mtime_ns, after.st_ctime_ns) or len(content) != before.st_size):
            reject("PRIVATE HOLD: browser action CSV changed during admission")
        return bytes(content), bool(before.st_mode & 0o077)
    finally:
        os.close(fd)


def preview(rows):
    total = {state: 0 for state in STATES}
    for item in rows:
        total[item["action_status"]] += 1
    return html_page(
        "LightUp PRIVATE HUMAN action board",
        "<p>All proposed deadlines, accountability and priorities are HUMAN NOTES, "
        "not actual dispatched tasks or proven current findings. Original kit bytes "
        "were not re-opened. Original reviewers are unsigned. No PASS, permission, "
        "consent, verification, automation, network call or background work.</p>"
        "<p>" + " · ".join(html.escape(k) + ": " + str(v)
                          for k, v in total.items()) + "</p>"
        "<p>For PRIVATE original owner, proposed day and specific action details "
        "open the separate <a href='PRIVATE-HUMAN-actions.html'>PRIVATE-HUMAN-actions.html</a>. "
        "Do not share source-relative data or this owner-private dossier.</p>"
    )


def detailed(rows):
    body = [
        "<p>PRIVATE human-only obligations, never dispatched or source owner verified. "
        "A HUMAN proposed deadline is not an actual calendar booking. "
        "A source or stage change remains HOLD for real activity.</p>",
        "<table><thead><tr><th>Step</th><th>Kit</th><th>HUMAN status</th>"
        "<th>Proposed priority</th><th>Accountable HUMAN</th>"
        "<th>Proposed day</th><th>Next HUMAN step</th></tr></thead><tbody>",
    ]
    for row in rows:
        body.append(
            "<tr><td>" + str(row["transition"]) + "</td><td>" +
            str(row["kit_ordinal"]) + "</td><td>" +
            html.escape(row["action_status"]) + "</td><td>" +
            html.escape(row["human_priority"]) + "</td><td>" +
            html.escape(row["accountable_human"]) + "</td><td>" +
            html.escape(row["proposed_day"]) + "</td><td>" +
            html.escape(row["next_human_step"]) + "</td></tr>"
        )
    body.append("</tbody></table><p>HUMAN-only, unscheduled, offline. "
                "Reopen current actual ORIGINAL kits separately using ledger.py reopen "
                "before treating any source as current.</p>")
    return html_page("LightUp PRIVATE HUMAN action details", "".join(body))


def context_record(args, case):
    return {
        "schema": "lightup.private.workspace-ledger-actions-context.v1",
        "authority": FLAGS,
        "historical_only": True,
        "sources_reopened": False,
        "original_team_context": args.context,
        "original_team_context_sha256": digest(case["context_raw"]),
        "original_team_choice": args.team_choice,
        "original_team_choice_sha256": case["choice_sha"],
        "original_team_csv": args.team_csv,
        "original_team_csv_sha256": case["csv_sha"],
    }


def open_context(raw):
    if not raw or len(raw) > MAX_MANIFEST:
        reject("PRIVATE HOLD: action context size")
    try:
        data = json.loads(raw.decode("utf-8"), object_pairs_hook=object_unique,
                          parse_constant=lambda _: reject("PRIVATE HOLD: invalid context number"))
    except (UnicodeError, ValueError, TypeError) as exc:
        raise Hold("PRIVATE HOLD: invalid action context") from exc
    if (not isinstance(data, dict) or set(data) != {
        "schema", "authority", "historical_only", "sources_reopened",
        "original_team_context", "original_team_context_sha256",
        "original_team_choice", "original_team_choice_sha256",
        "original_team_csv", "original_team_csv_sha256"
    } or data["schema"] != "lightup.private.workspace-ledger-actions-context.v1" or
        not literal_false_authority(data["authority"]) or
        data["historical_only"] is not True or data["sources_reopened"] is not False or
        raw != canonical(data)):
        reject("PRIVATE HOLD: action context authority or canonical source")
    for key in ("original_team_context", "original_team_choice", "original_team_csv"):
        val = data[key]
        if (not isinstance(val, str) or len(val) > 4096 or
            not os.path.isabs(val) or os.path.normpath(val) != val):
            reject("PRIVATE HOLD: original source path invalid")
    for key in ("original_team_context_sha256", "original_team_choice_sha256",
                "original_team_csv_sha256"):
        val = data[key]
        if not isinstance(val, str) or not re.fullmatch(r"[0-9a-f]{64}", val):
            reject("PRIVATE HOLD: original source fingerprint invalid")
    return data


def prepare(args):
    originals = [args.context, args.team_choice, args.team_csv]
    if any(not isinstance(p, str) or not os.path.isabs(p) or
           os.path.normpath(p) != p for p in originals):
        reject("PRIVATE HOLD: original references require canonical absolute paths")
    case = admit_team(args.context, args.team_choice, args.team_csv)
    dest = private_parent_for_originals(args.private_parent, case["sources"])
    actions = template_rows(case)
    from history_actions_browser import render
    output = new_private(dest)
    try:
        write_private(output, "PRIVATE-action-context.json", canonical(context_record(args, case)))
        write_private(output, "HUMAN-action-plan-template.csv", serialize_csv(actions))
        write_private(output, "REVIEW-ACTIONS-IN-BROWSER.html", render(case, actions))
        write_private(output, "OPEN-PRIVATE.html", html_page(
            "LightUp PRIVATE source-locked HUMAN action planning",
            "<p>ONLY existing source-ledger and original finalized HUMAN reviewer choices "
            "were inspected, never customer kit files, assets or network. "
            "No actions scheduled, granted, dispatched or approved.</p>"
            "<p><a href='REVIEW-ACTIONS-IN-BROWSER.html'>Open PRIVATE offline HUMAN action editor</a>. "
            "Choose accountability and proposed dates locally, export a CSV and run "
            "native history_actions.py finalize against PRIVATE-action-context.json. "
            "Potentially sensitive HUMAN names and next-step text remain PRIVATE.</p>"
        ))
    except BaseException:
        shutil.rmtree(output)
        raise
    print("PRIVATE HOLD: source-bound HUMAN action drafting only, never actual dispatch")
    print(str(Path(output) / "OPEN-PRIVATE.html"))
    return 3


def finalize(args):
    raw_context = read_owner_file(args.action_context, MAX_MANIFEST)
    action_context = open_context(raw_context)
    case = admit_team(
        action_context["original_team_context"],
        action_context["original_team_choice"],
        action_context["original_team_csv"],
    )
    if (digest(case["context_raw"]) != action_context["original_team_context_sha256"] or
        case["choice_sha"] != action_context["original_team_choice_sha256"] or
        case["csv_sha"] != action_context["original_team_csv_sha256"]):
        reject("PRIVATE HOLD: original team packet or HUMAN CSV changed since preparation")
    if bool(args.plan) == bool(args.browser_csv):
        reject("PRIVATE HOLD: choose exactly one PRIVATE plan or browser download")
    if args.plan:
        plan = read_owner_file(args.plan, MAX_ACTION_CSV)
        exposed = False
    else:
        plan, exposed = read_browser_file(args.browser_csv)
    rows = admission(plan, template_rows(case))
    if digest(read_owner_file(args.action_context, MAX_MANIFEST)) != digest(raw_context):
        reject("PRIVATE HOLD: original HUMAN action context changed during finalization")
    # Repeat original ledger chain and reviewed source exactness before publication.
    again = admit_team(
        action_context["original_team_context"],
        action_context["original_team_choice"],
        action_context["original_team_csv"],
    )
    if (again["choice_sha"], digest(again["context_raw"]), again["csv_sha"]) != (
            case["choice_sha"], digest(case["context_raw"]), case["csv_sha"]):
        reject("PRIVATE HOLD: original source or review changed before output")
    packet = {
        "schema": "lightup.private.workspace-ledger-actions-human.v1",
        "authority": FLAGS,
        "sources_reopened": False,
        "historical_only": True,
        "actions_dispatched": False,
        "context_sha256": digest(raw_context),
        "human_action_plan_sha256": digest(plan),
        "rows": rows,
    }
    private = new_private(private_parent_for_originals(args.private_parent, case["sources"]))
    try:
        write_private(private, "PRIVATE-HUMAN-actions.json", canonical(packet))
        write_private(private, "PRIVATE-HUMAN-actions.html", detailed(rows))
        write_private(private, "HUMAN-action-plan.csv", plan)
        write_private(private, "OPEN-PRIVATE.html", preview(rows))
    except BaseException:
        shutil.rmtree(private)
        raise
    print("PRIVATE HOLD: local HUMAN proposed action workroom only; nothing scheduled or dispatched")
    print(str(Path(private) / "OPEN-PRIVATE.html"))
    return 3


def main():
    p = argparse.ArgumentParser(description="PRIVATE offline source-bound post-review HUMAN action desk")
    subs = p.add_subparsers(dest="action", required=True)
    make = subs.add_parser("prepare", help="Open private HUMAN action drafting room")
    make.add_argument("--context", required=True, help="Original native PRIVATE-team-context.json")
    make.add_argument("--team-choice", required=True, help="Original finalized PRIVATE-HUMAN-team-choice.json")
    make.add_argument("--team-csv", required=True, help="Original PRIVATE HUMAN-team-review.csv")
    make.add_argument("--private-parent", required=True)
    save = subs.add_parser("finalize", help="Archive HUMAN actions after exact original records re-admission")
    save.add_argument("--action-context", required=True, help="PRIVATE-action-context.json from prepare")
    group = save.add_mutually_exclusive_group(required=True)
    group.add_argument("--plan", help="Owner-private 0600 HUMAN-action-plan.csv")
    group.add_argument("--browser-csv", help="Explicit browser downloaded HUMAN-action-plan.csv")
    save.add_argument("--private-parent", required=True)
    args = p.parse_args()
    try:
        return prepare(args) if args.action == "prepare" else finalize(args)
    except (Hold, OSError, ValueError, UnicodeError, TypeError, csv.Error):
        print("PRIVATE HOLD: source-bound HUMAN action operation refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
