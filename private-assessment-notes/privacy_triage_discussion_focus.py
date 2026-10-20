#!/usr/bin/env python3
"""Source-minimal PRIVATE HUMAN latest-action attention board.

Derived solely from previously admitted completed original HUMAN action
rounds, never from target access, automated risk scoring or client facts.
No original note, question text, file names, reviewer identity, or source hash.
"""
from __future__ import annotations

import csv
import html
import io

FIELDS = (
    "original_ordinal", "latest_human_step", "private_question_present",
    "human_step_changes", "private_question_changes",
    "declared_rounds", "human_followup_attention",
)
# This is navigation priority for manual followup, NOT a risk/severity score.
STAGE_ORDER = ("WITHHOLD", "REQUEST_OWNER_CONTEXT", "DISCUSS", "PENDING")


def focus_rows(items: list[dict], original_ordinals: list[int],
               rounds: int) -> list[dict]:
    """Keep all original selected positions, never only a filtered subset."""
    if not 1 <= len(original_ordinals) <= 12 or not 2 <= rounds <= 8:
        raise ValueError("invalid original HUMAN selection / manually supplied rounds")
    if sorted(set(original_ordinals)) != original_ordinals:
        raise ValueError("original HUMAN ordinals must be unique and ascending")
    result = []
    for ordinal in original_ordinals:
        subset = [record for record in items if record["ordinal"] == ordinal]
        if len(subset) != rounds or [r["round"] for r in subset] != list(range(1, rounds+1)):
            raise ValueError("missing original HUMAN followup chronology")
        latest = subset[-1]
        step = latest["step"]
        if step not in STAGE_ORDER:
            raise ValueError("unsupported HUMAN step")
        result.append({
            "original_ordinal": ordinal,
            "latest_human_step": step,
            "private_question_present": bool(latest["question_present"]),
            "human_step_changes": sum(bool(x["stage_changed"]) for x in subset),
            "private_question_changes": sum(bool(x["question_changed"]) for x in subset),
            "declared_rounds": rounds,
            "human_followup_attention": step != "PENDING" or bool(latest["question_present"]),
        })
    # Human-first navigation only, ordinal is stable within an attention group.
    result.sort(key=lambda row: (STAGE_ORDER.index(row["latest_human_step"]),
                                 row["original_ordinal"]))
    return result


def csv_bytes(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.DictWriter(stream, fieldnames=FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for row in rows:
        writer.writerow({
            field: ("TRUE" if value else "FALSE") if type(value) is bool else value
            for field, value in row.items()
        })
    return stream.getvalue().encode("utf-8")


def page(rows: list[dict], rounds: int) -> bytes:
    count = {stage: sum(x["latest_human_step"] == stage for x in rows)
             for stage in STAGE_ORDER}
    cards = []
    for row in rows:
        label = row["latest_human_step"].replace("_", " ")
        cards.append(
            "<tr><th scope='row'>Original #" + str(row["original_ordinal"]) +
            "</th><td>" + html.escape(label) +
            "</td><td>" + ("Yes; content withheld" if row["private_question_present"]
                           else "No") +
            "</td><td>" + str(row["human_step_changes"]) +
            "</td><td>" + str(row["private_question_changes"]) +
            "</td><td>" + ("Follow up privately" if row["human_followup_attention"]
                           else "Pending HUMAN decision") +
            "</td></tr>"
        )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN latest action focus</title>
<style>body{max-width:950px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#24394a}
aside{border-left:5px solid #a74825;background:#fff0e9;padding:1rem}
table{border-collapse:collapse;width:100%;margin:1.4rem 0}
th,td{border:1px solid #c9d4db;text-align:left;padding:.65rem}
thead{background:#eef3f7}
@media print{body{max-width:100%;margin:0}}
</style>
<h1>PRIVATE HUMAN latest-action desk</h1>
<aside><b>HOLD · PLAN/LAB ONLY · NOT A SECURITY VERDICT.</b>
This is only a prioritised display of manually declared HUMAN followup steps.
WITHHOLD, REQUEST OWNER CONTEXT and DISCUSS are not security severity;
PENDING is not approval. A human change does NOT prove remediation, privacy
clearance, real consent, independent reviewers or permission to disclose.
Keep this entire output confidential.</aside>
<p>Original selected sources: """ + str(len(rows)) + """.
Manually ordered HUMAN action rounds: """ + str(rounds) + """.
Latest human follow-up: WITHHOLD """ + str(count["WITHHOLD"]) +
            """, REQUEST OWNER CONTEXT """ + str(count["REQUEST_OWNER_CONTEXT"]) +
            """, DISCUSS """ + str(count["DISCUSS"]) +
            """, PENDING """ + str(count["PENDING"]) +
            """. Ordering helps private discussion only, never a risk score.</p>
<table><thead><tr>
<th>Original source</th><th>Latest HUMAN action</th>
<th>PRIVATE question</th><th>Status changes</th><th>Question changes</th>
<th>Next HUMAN attention</th></tr></thead>
<tbody>""" + "".join(cards) + """</tbody></table>
<p>Question text, original evidence, filenames, hashes, customer identity,
scanned targets and signer identity are intentionally absent.
The original completed reviewer packets, source-bound receipts and full
action CSVs remain separately PRIVATE. No network, model, tool execution,
auto-assignment, dispatch, grant or release.</p>
</html>""").encode("utf-8")
