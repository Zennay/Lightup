#!/usr/bin/env python3
"""Read-only private human review revision board; no source authority or execution."""
from __future__ import annotations

from base64 import b64encode
from collections import Counter
from hashlib import sha256
from html import escape

from portfolio import FLAGS, Hold, load_one, encode

SCHEMA = "lightup.assessment_portfolio_human_change_aggregate.v1"
STYLE = """
:root{font:16px/1.48 system-ui,sans-serif;color-scheme:dark;background:#0a1726;color:#e8f4fd}
*{box-sizing:border-box}body{margin:auto;max-width:1250px;padding:24px}
header{background:linear-gradient(130deg,#153e54,#17273b);border:1px solid #416077;border-radius:19px;padding:28px}
h1{font-size:clamp(2rem,5vw,3rem)}small{color:#9ce7d0;letter-spacing:.12em;font-weight:800}
p{color:#c1d2df}.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin:18px 0}
.card{background:#152d42;border:1px solid #3d5c70;border-radius:12px;padding:20px}
.card b{font-size:2rem;display:block}.card span{color:#b8d6e4}
table{border-collapse:collapse;width:100%;font-size:.86rem}
th,td{padding:10px;border-bottom:1px solid #36566c;text-align:left;vertical-align:top}
th{color:#a8e8d7}tr:nth-child(even){background:#1b3547}
aside{border-left:4px solid #e2cc8f;padding:16px;background:#2a2b3d;margin-top:22px}
@media(max-width:850px){.grid{display:block}.card{margin:12px 0}body{padding:12px}table{font-size:.74rem}}
@media print{body,header,.card,aside{background:white;color:black}p{color:black}}
"""


def build(old_agendas, new_agendas, old_reference, new_reference):
    if (not 1 <= len(old_agendas) <= 12
            or len(old_agendas) != len(new_agendas)):
        raise Hold("incomplete human revision membership")
    diffs = []
    stages = Counter()
    role_moves = 0
    date_moves = 0
    total_items = 0
    for index, (raw_before, raw_after) in enumerate(zip(old_agendas, new_agendas), 1):
        before = load_one(None, old_reference, raw=raw_before)
        after = load_one(None, new_reference, raw=raw_after)
        if (before["status"] != after["status"]
                or len(before["rows"]) != len(after["rows"])):
            raise Hold("original human status or membership changed")
        old_slots = {row["slot"]: row for row in before["rows"]}
        new_slots = {row["slot"]: row for row in after["rows"]}
        if set(old_slots) != set(new_slots):
            raise Hold("original human membership changed")
        total_items += len(old_slots)
        for slot in sorted(old_slots):
            old, new = old_slots[slot], new_slots[slot]
            if old["source_kind"] != new["source_kind"]:
                raise Hold("original source kind changed")
            changed = [field for field in ("stage", "next_role", "review_date")
                       if old[field] != new[field]]
            if not changed:
                continue
            stages[(old["stage"], new["stage"])] += 1
            role_moves += int("next_role" in changed)
            date_moves += int("review_date" in changed)
            diffs.append({"source": index, "slot": slot,
                          "before_stage": old["stage"], "after_stage": new["stage"],
                          "before_role": old["next_role"], "after_role": new["next_role"],
                          "before_date": old["review_date"], "after_date": new["review_date"],
                          "changed_fields": changed})
    overview = {
        "schema": SCHEMA, "previous_reference_date": old_reference,
        "new_reference_date": new_reference, "agenda_count": len(old_agendas),
        "human_item_count": total_items, "changed_human_slots": len(diffs),
        "changed_roles": role_moves, "changed_proposed_dates": date_moves,
        "human_stage_transitions": [
            {"from": old, "to": new, "count": count}
            for (old, new), count in sorted(stages.items())
        ],
        "planning_not_permission": True,
        **{f: False for f in FLAGS}
    }
    h = b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    rows = []
    for row in diffs:
        values = [row["source"], row["slot"], row["before_stage"], row["after_stage"],
                  row["before_role"], row["after_role"], row["before_date"] or "—",
                  row["after_date"] or "—", ", ".join(row["changed_fields"])]
        rows.append("<tr>" + "".join("<td>"+escape(str(v))+"</td>" for v in values) + "</tr>")
    if not rows:
        rows = ["<tr><td colspan='9'>No human-only changes to original review choices.</td></tr>"]
    headings = ["Agenda", "Source slot", "Prior stage", "Proposed stage",
                "Prior role", "Proposed role", "Prior date", "Proposed date", "Changed fields"]
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            " connect-src 'none'; script-src 'none'; img-src 'none'; object-src 'none';"
            " base-uri 'none'; form-action 'none'; style-src 'sha256-"+h+"'\">"
            "<title>LightUp · Private human revision board</title><style>"+STYLE+"</style></head>"
            "<body><header><small>LIGHTUP / ASSESSMENT / OFFLINE HUMAN REVIEW</small>"
            "<h1>What changed between human reviews?</h1>"
            "<p>Original private human stages, neutral roles and proposed discussion dates only; "
            "no original lab evidence, targets, client identities or actual work assignments.</p>"
            "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO</strong></header>"
            "<section class='grid'><div class='card'><b>"+str(len(diffs))+"</b><span>changed human slots</span></div>"
            "<div class='card'><b>"+str(role_moves)+"</b><span>role changes</span></div>"
            "<div class='card'><b>"+str(date_moves)+"</b><span>proposed date changes</span></div></section>"
            "<section class='card'><h2>Private source-neutral human changes</h2>"
            "<p>Agenda and source slot numbers identify only positions in the owner-private workspace.</p>"
            "<table><thead><tr>"+ "".join("<th>"+escape(k)+"</th>" for k in headings)
            +"</tr></thead><tbody>"+"".join(rows)+"</tbody></table></section>"
            "<aside><strong>This is NOT an authenticated outcome, remediation or authorization.</strong>"
            "<p>Original HOLD remains in place. An apparent date or stage change does not verify original "
            "findings, ownership, client consent, source provenance, task completion, actual scope "
            "or a security fix. Existing original exact-head CI, source owner, independent security/privacy, "
            "genuine independent client/operator consent with at-use revocation, and HUMAN GO remain mandatory.</p>"
            "</aside><footer>Offline scriptless owner-private human review; no network or execution.</footer>"
            "</body></html>").encode("utf-8")
    csv = ["prior_stage,proposed_stage,human_changed_slots"]
    for row in overview["human_stage_transitions"]:
        csv.append(f'{row["from"]},{row["to"]},{row["count"]}')
    return html, encode(overview), ("\r\n".join(csv)+"\r\n").encode("ascii")
