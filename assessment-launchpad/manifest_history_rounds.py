#!/usr/bin/env python3
"""Source-bound PRIVATE timeline of saved HUMAN rounds. No network or assessment."""
from __future__ import annotations

import argparse
import base64
import csv
from hashlib import sha256
from html import escape
from io import StringIO
import json
import os

import manifest_history_desk as history
import manifest_history_followup as followup
import manifest_history_response as response
from launchpad import Hold, open_output_directory, read_private_bundle_item, publish_bundle, report_hold

LIMIT = 262144
MAX_ROUNDS = 8
DETAIL = "lightup-human-timeline-private.json"
BOARD = "lightup-human-timeline-private.html"
COUNTS = "lightup-human-timeline-counts-private.csv"
BACKLOG = "lightup-human-timeline-followups-private.csv"
STYLE = ("body{font:16px/1.5 system-ui,sans-serif;max-width:1040px;margin:2rem auto;"
         "padding:1rem;color:#152437}.hold{background:#fff3df;border-left:5px solid #96691a;"
         "padding:1rem}table{border-collapse:collapse;width:100%}th,td{padding:.55rem;"
         "border:1px solid #bbcada;text-align:left}th{background:#e9f0f8}.scroll{overflow-x:auto}"
         "small{color:#526174}summary{cursor:pointer;font-weight:700;padding:.6rem 0}"
         ".cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(135px,1fr));"
         "gap:.75rem;margin:1.5rem 0}.metric{border:1px solid #bfd0df;"
         "border-radius:.5rem;padding:1rem;background:#f5f8ff}"
         ".metric strong{display:block;font-size:1.5rem}.metric span{font-size:.8rem}")


def admit_sources(plan_paths, history_dir, round_paths, *, min_rounds=2):
    if min_rounds not in (1, 2) or not min_rounds <= len(round_paths) <= MAX_ROUNDS:
        raise Hold("select permitted ordered PRIVATE HUMAN review round count")
    args = [item for path in plan_paths for item in ("--plan-dir", path)]
    if history.main(args + ["--verify-output-dir", history_dir]) != 0:
        raise Hold("saved PRIVATE plan history rejected")
    plans, original = history.prepare(plan_paths)
    fd, history_abs = open_output_directory(history_dir)
    try:
        history_raw = read_private_bundle_item(fd, history.SUMMARY, LIMIT)
    finally:
        os.close(fd)
    rounds = [followup.read_response(path, original, history_raw) for path in round_paths]
    roots = [*(plan[0] for plan in plans), history_abs, *(round_[0] for round_ in rounds)]
    if len(roots) != len(set(roots)):
        raise Hold("PRIVATE plan, history and HUMAN return directories must be distinct")
    for i, (_, packet, digest) in enumerate(rounds):
        if i == 0:
            if packet["schema"] != "lightup.private-manifest-history-human-return.v1":
                raise Hold("timeline must start with one original v1 HUMAN round")
        elif (packet["schema"] != "lightup.private-manifest-history-human-return.v2"
              or packet.get("previous_return_sha256") != rounds[i-1][2]):
            raise Hold("HUMAN timeline must preserve exact unsigned previous-round binding")
    return plans, history_abs, history_raw, rounds, original


def make_packet(rounds, original, history_raw):
    changes = [0] * (len(rounds) - 1)
    rows = []
    for i, source in enumerate(original["human_review_queue"]):
        stages = [round_[1]["responses"][i]["human_stage"] for round_ in rounds]
        for j in range(len(stages)-1):
            changes[j] += int(stages[j] != stages[j+1])
        rows.append({
            "original_row": i+1, "from_plan": source["from_ordinal"],
            "to_plan": source["to_ordinal"], "literal_change": source["change"],
            "before_slot": source["before_slot"], "after_slot": source["after_slot"],
            "human_stages": stages,
        })
    return {
        "schema": "lightup.private-human-timeline.v1", "status": "REVIEW_ONLY",
        "history_sha256": sha256(history_raw).hexdigest(),
        "source_rows": len(rows), "round_count": len(rounds),
        "round_response_sha256": [round_[2] for round_ in rounds],
        "changed_rows_per_transition": changes,
        "round_stage_counts": [round_[1]["stage_counts"] for round_ in rounds],
        "rows": rows,
        "source_authenticated": False, "authorized": False,
        "client_consent_verified": False, "operator_consent_verified": False,
        "revocation_checked": False, "human_go": False,
        "assessment_executed": False, "release_allowed": False,
    }


def render_board(packet):
    hashed = base64.b64encode(sha256(STYLE.encode()).digest()).decode("ascii")
    head = ("<th>Original row</th><th>Plan pair</th><th>Literal change</th>"
            "<th>Before slot</th><th>After slot</th>") + "".join(
                "<th>HUMAN round " + str(i) + "</th>"
                for i in range(1, packet["round_count"]+1))
    rows = []
    for row in packet["rows"]:
        cells = (str(row["original_row"]),
                 str(row["from_plan"])+" → "+str(row["to_plan"]),
                 row["literal_change"],
                 str(row["before_slot"]) if row["before_slot"] is not None else "—",
                 str(row["after_slot"]) if row["after_slot"] is not None else "—",
                 *row["human_stages"])
        rows.append("<tr>"+"".join("<td>"+escape(cell)+"</td>" for cell in cells)+"</tr>")
    active = ("FOLLOW_UP_REQUIRED", "NEEDS_CONTEXT", "IN_REVIEW", "QUESTION_PREPARED")
    final_counts = packet["round_stage_counts"][-1]
    next_rows = []
    for row in packet["rows"]:
        current = row["human_stages"][-1]
        if current not in active:
            continue
        values = (str(row["original_row"]),
                  str(row["from_plan"]) + " → " + str(row["to_plan"]),
                  row["literal_change"], current)
        next_rows.append("<tr>" + "".join("<td>" + escape(value) + "</td>"
                                         for value in values) + "</tr>")
    progress_cards = "".join(
        "<div class='metric'><strong>" + str(final_counts[stage]) + "</strong>"
        "<span>" + escape(stage.replace("_", " ").title()) + "</span></div>"
        for stage in response.STAGES
    )
    active_count = sum(final_counts[stage] for stage in active)
    newest_change = packet["changed_rows_per_transition"][-1]
    next_html = (
        "<details open><summary>HUMAN follow-up queue (" + str(active_count) + ")</summary>"
        "<p>These are unsigned HUMAN work notes, not vulnerabilities or remediation claims.</p>"
        "<div class='scroll'><table><thead><tr><th>Original row</th><th>Plan pair</th>"
        "<th>Literal change</th><th>Current HUMAN stage</th></tr></thead><tbody>"
        + ("".join(next_rows) if next_rows else
           "<tr><td colspan='4'>No active HUMAN follow-up labels in the last round."
           " PARKED and HUMAN_REVIEWED are not approval or remediation.</td></tr>")
        + "</tbody></table></div></details>"
    )
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            " script-src 'none'; style-src 'sha256-"+hashed+
            "'; connect-src 'none'; img-src 'none'; object-src 'none';"
            " base-uri 'none'; form-action 'none'\">"
            "<title>LightUp PRIVATE HUMAN round timeline</title><style>"+STYLE+
            "</style></head><body><h1>PRIVATE HUMAN round timeline</h1>"
            "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY."
            " All rounds are unsigned HUMAN work notes, not authenticated chronology,"
            " consent, remediation, authority or HUMAN GO.</p>"
            "<p>"+str(packet["round_count"])+" locally chained HUMAN rounds · "+
            str(packet["source_rows"])+" source rows · "+str(newest_change)+
            " HUMAN stage changes in the last recorded transition.</p>"
            "<h2>Current HUMAN stage workload</h2><div class='cards'>"+
            progress_cards+"</div>"+next_html+
            "<h2>HUMAN stage timeline (all original rows)</h2>"
            "<div class='scroll'><table><thead><tr>"+head+
            "</tr></thead><tbody>"+"".join(rows)+"</tbody></table></div>"
            "<p><small>Private source-bound digests are in the JSON only. This HTML"
            " contains no URLs, original source paths, filenames, hashes or notes."
            " Source-owner, independent privacy/security and separately authenticated"
            " client/operator consent with action-time revocation remain required."
            "</small></p></body></html>").encode("utf-8")


def render_counts(packet):
    out = StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("round_ordinal", "human_stage", "count", "changed_rows_since_previous"))
    for i, counts in enumerate(packet["round_stage_counts"], 1):
        changed = 0 if i == 1 else packet["changed_rows_per_transition"][i-2]
        for stage in response.STAGES:
            writer.writerow((i, stage, counts[stage], changed))
    return out.getvalue().encode("utf-8")


def render_followups(packet):
    """Ordinal-only HUMAN next-review queue. Never an unremediated findings list."""
    out = StringIO(newline="")
    writer = csv.writer(out, lineterminator="\n")
    writer.writerow(("original_row", "plan_pair_from", "plan_pair_to", "literal_change",
                     "before_slot", "after_slot", "last_human_stage", "stage_changes"))
    for row in packet["rows"]:
        final = row["human_stages"][-1]
        if final not in ("FOLLOW_UP_REQUIRED", "NEEDS_CONTEXT",
                         "IN_REVIEW", "QUESTION_PREPARED"):
            continue
        stages = row["human_stages"]
        writer.writerow((row["original_row"], row["from_plan"], row["to_plan"],
                         row["literal_change"],
                         row["before_slot"] if row["before_slot"] is not None else "",
                         row["after_slot"] if row["after_slot"] is not None else "",
                         final, sum(a != b for a, b in zip(stages, stages[1:]))))
    return out.getvalue().encode("utf-8")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Compare 2–8 exactly chained saved HUMAN rounds offline, never run an assessment.")
    parser.add_argument("--plan-dir", action="append", required=True)
    parser.add_argument("--history-dir", required=True)
    parser.add_argument("--round-dir", action="append", required=True)
    target = parser.add_mutually_exclusive_group(required=True)
    target.add_argument("--output-dir")
    target.add_argument("--verify-output-dir")
    parser.add_argument("--explain-hold", action="store_true")
    args = parser.parse_args(argv)
    try:
        plans, history_abs, raw, rounds, source = admit_sources(
            args.plan_dir, args.history_dir, args.round_dir)
        packet = make_packet(rounds, source, raw)
        files = {
            DETAIL: (json.dumps(packet, sort_keys=True, separators=(",", ":"))+"\n").encode(),
            BOARD: render_board(packet), COUNTS: render_counts(packet),
            BACKLOG: render_followups(packet),
        }
        if any(not 0 < len(content) <= LIMIT for content in files.values()):
            raise Hold("PRIVATE HUMAN timeline output exceeds bound")
        fd, output = open_output_directory(args.output_dir or args.verify_output_dir)
        try:
            for root in [*(p[0] for p in plans), history_abs, *(r[0] for r in rounds)]:
                common = os.path.commonpath((root, output))
                if common in (root, output):
                    raise Hold("PRIVATE timeline output must be separate from every source tree")
            if args.verify_output_dir:
                if set(os.listdir(fd)) != set(files):
                    raise Hold("PRIVATE timeline output inventory changed")
                for name, expected in files.items():
                    if read_private_bundle_item(fd, name, LIMIT) != expected:
                        raise Hold("PRIVATE timeline changed from exact original rounds")
            else:
                if os.listdir(fd):
                    raise Hold("PRIVATE timeline directory must be empty")
                _, _, current_raw, current_rounds, current_source = admit_sources(
                    args.plan_dir, args.history_dir, args.round_dir)
                if (raw != current_raw or source != current_source
                        or [x[2] for x in rounds] != [x[2] for x in current_rounds]):
                    raise Hold("PRIVATE HUMAN timeline sources changed before publication")
                publish_bundle(fd, list(files.items()))
        finally:
            os.close(fd)
        print(("HUMAN_TIMELINE_REOPENED" if args.verify_output_dir else "HUMAN_TIMELINE_CREATED") +
              " · rounds=" + str(len(rounds)) + " · rows=" + str(packet["source_rows"]) +
              " · REVIEW_ONLY; no grant, consent, remediation or target contact")
        return 0
    except Hold as error:
        report_hold("HUMAN_TIMELINE_HOLD — original PRIVATE round chain rejected",
                    error, args.explain_hold)
    except Exception:
        report_hold("HUMAN_TIMELINE_HOLD — PRIVATE parsing or filesystem rejected",
                    None, args.explain_hold)
    return 3


if __name__ == "__main__":
    raise SystemExit(main())
