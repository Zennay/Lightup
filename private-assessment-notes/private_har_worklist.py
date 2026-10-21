"""PRIVATE source-ordinal HAR review action worksheet; never authorises actions."""
from __future__ import annotations
import csv
from html import escape
import io
from private_har_hold_board import HAR_CATEGORIES, inventory

FIELDS = ("original_ordinal", "review_area", "literal_cue_count",
          "next_human_action", "human_status", "human_notes")


def entries(rows: list[dict]) -> list[dict]:
    result = []
    for original in inventory(rows):
        ordinal = original["original_ordinal"]
        def add(area: str, count: int, action: str) -> None:
            result.append({
                "original_ordinal": ordinal, "review_area": area,
                "literal_cue_count": count, "next_human_action": action,
                "human_status": "PENDING_HUMAN", "human_notes": "",
            })
        if original["whole_derived_copy_withheld"]:
            add("WITHHELD_COPY_SOURCE_OWNER", 0,
                "Source owner: inspect original privately")
        # Mandatory even if all literal cue counts are zero.
        add("FULL_ORIGINAL_REVIEW", 0, "Inspect complete private original")
        for label, _ in HAR_CATEGORIES:
            count = original[label + "_literal_markers"]
            if count:
                add(label.upper(), count,
                    "Inspect original category privately; do not copy contents")
    return result


def worksheet_csv(rows: list[dict]) -> bytes:
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(entries(rows))
    return output.getvalue().encode("utf-8")


def worksheet_html(rows: list[dict]) -> bytes:
    actions = entries(rows)
    roster = []
    for ordinal in sorted({item["original_ordinal"] for item in actions}):
        steps = [item for item in actions if item["original_ordinal"] == ordinal]
        tasks = "".join(
            "<li><label><input type='checkbox'> <b>" +
            escape(item["review_area"].replace("_", " ")) + "</b>: " +
            escape(item["next_human_action"]) +
            (" (" + str(item["literal_cue_count"]) + " literal cues)"
             if item["literal_cue_count"] else "") +
            "</label></li>" for item in steps
        )
        roster.append("<section><h2>Original #" + str(ordinal) +
                      "</h2><ul>" + tasks + "</ul></section>")
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN HAR action worksheet</title>
<style>body{font:16px/1.55 system-ui;max-width:990px;margin:2rem auto;padding:1rem;color:#213344}
aside{padding:1rem;background:#fff0e8;border-left:5px solid #99572e}
section{padding:.5rem 1rem;border:1px solid #c4cdd8;margin:1rem 0;break-inside:avoid}
li{margin:.6rem 0}
@media print{body{margin:0;max-width:none}section{break-inside:avoid}}</style>
<h1>PRIVATE HAR source-owner HUMAN action worksheet</h1>
<aside><b>REVIEW_ONLY / HOLD · NOT AUTHORISATION.</b> Tasks come only
from literal placeholders in privately masked notes, not raw HAR or verified
findings. Original text may contain markers and absence proves nothing.
All originals require full private HUMAN review. Checkboxes have no storage,
transmission, decision, consent, privacy certification or release function.</aside>
<p>Original positions: """ + str(len(roster)) + """; non-authorising actions:
""" + str(len(actions)) + """. No content, source filenames, identities,
URLs, digests, credentials or HUMAN comments are present. Decisions belong
only in the original source-bound PRIVATE HUMAN workroom.</p>""" + "".join(roster) + """
<p>No scripts, network, scans, findings, grants, recipients or automatic
actions. Any completed copy remains owner-private and non-authorising.</p></html>"""
    return page.encode("utf-8")
