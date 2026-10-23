#!/usr/bin/env python3
"""Source-minimal browser-only local HUMAN workpack progress cockpit.

Render from exact original native admitted workpack rows only. Inline script
is SHA256-CSP pinned, never fetches, stores or exports PRIVATE source data.
"""
from __future__ import annotations

import base64
import hashlib
import html

import human_workpack
import route_queue

JS = r"""'use strict';
(() => {
  const filter = document.querySelector('#workflow-search');
  const stage = document.querySelector('#stage-select');
  const team = document.querySelector('#team-select');
  const attention = document.querySelector('#attention-only');
  const changed = document.querySelector('#changed-only');
  const counter = document.querySelector('#visible-count');
  const rows = Array.from(document.querySelectorAll('[data-workflow-row]'));
  function apply() {
    const query = filter.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const row of rows) {
      const match = (!query || row.dataset.search.toLocaleLowerCase().includes(query)) &&
        (!stage.value || row.dataset.stage === stage.value) &&
        (!team.value || row.dataset.team === team.value) &&
        (!attention.checked || row.dataset.attention === 'true') &&
        (!changed.checked || row.dataset.changed === 'true');
      row.hidden = !match;
      if (match) visible++;
    }
    counter.textContent = visible + ' of ' + rows.length + ' original HUMAN workflows visible';
  }
  for (const control of [filter, stage, team, attention, changed]) {
    control.addEventListener('input', apply);
    control.addEventListener('change', apply);
  }
  document.querySelector('#reset-filters').addEventListener('click', () => {
    filter.value = '';
    stage.value = '';
    team.value = '';
    attention.checked = false;
    changed.checked = false;
    apply();
    filter.focus();
  });
  apply();
})();
"""

CSS = """<style>
:root{color-scheme:dark;background:#0c182b;color:#e7f2fc;
 font:16px/1.5 system-ui,-apple-system,sans-serif}
*{box-sizing:border-box}body{max-width:1300px;margin:auto;padding:20px}
header,section,footer{background:#172d44;border:1px solid #476782;
 padding:24px;border-radius:18px;margin:16px 0}
header{background:linear-gradient(130deg,#14263b,#203c56)}
.tag{font-weight:750;letter-spacing:.08em;color:#f4d09e;font-size:.83rem}
h1{font-size:clamp(1.8rem,4vw,3rem);margin:.3rem 0}
h2{margin:.2rem 0 1rem;font-size:1.35rem}h3{font-size:1.05rem}
p{color:#d4e2ed}strong{color:#eff8ff}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(170px,1fr));gap:13px}
.metric{background:#223b51;border-radius:13px;padding:16px;border:1px solid #476782}
.metric b{font-size:2rem;display:block;color:#c7f3dc}.metric span{font-size:.84rem}
.controls{display:grid;grid-template-columns:2fr repeat(2,minmax(140px,1fr));gap:12px;margin:16px 0}
label{font-weight:600}input[type=search],select,button{font:inherit;width:100%;padding:10px;
 background:#0d233a;border:1px solid #8aa6bb;color:#edf6fc;border-radius:9px}
button{cursor:pointer;width:auto;padding:10px 17px}
.checks{display:flex;gap:20px;flex-wrap:wrap;padding:6px 0}
.checks label{font-weight:500}input[type=checkbox]{accent-color:#a3e9c8}
.scroller{overflow-x:auto}table{border-collapse:collapse;width:100%;min-width:740px}
th,td{text-align:left;vertical-align:top;padding:13px;border-bottom:1px solid #456078}
th{color:#cbebe6}tr:hover{background:#274259}tr[hidden]{display:none!important}
.pill{border:1px solid #7c95a4;border-radius:99px;padding:3px 8px;
display:inline-block;font-size:.82rem;font-weight:700}
.attn{color:#ffd5ac;border-color:#ffce8e}
.change{color:#a8e3ca}.muted{color:#b9cddd;font-size:.87rem}
ol{padding-left:24px}li{padding:8px 0;border-bottom:1px solid #425e79}
details{margin:10px 0}summary{cursor:pointer;font-weight:700;padding:9px 0}
:focus-visible{outline:3px solid #ffe09b;outline-offset:4px}
@media(max-width:780px){.controls{grid-template-columns:1fr}header,section,footer{padding:17px}}
</style>"""


def render(snapshots: list[tuple[str, list[dict]]],
           metrics: list[dict], changes: list[dict], attention: list[dict],
           movement: list[dict]) -> bytes:
    esc = lambda value: html.escape(str(value), quote=True)
    oldest = snapshots[0][1]
    latest = snapshots[-1][1]
    last_counts = metrics[-1]
    attention_keys = {a["workflow_key"] for a in attention}
    snapshot_rows = []
    for index, ((date, _), metric) in enumerate(zip(snapshots, metrics), 1):
        team_workload = ", ".join(
            f"{team}: {count}" for team, count in metric["teams"].items() if count
        ) or "No HUMAN team"
        snapshot_rows.append(
            "<tr><th scope='row'>#" + str(index) + "</th><td>" + esc(date) +
            "</td><td>" + str(metric["unassessed"]) + "</td><td>" +
            str(metric["attention"]) + "</td><td>" + str(metric["human_review"]) +
            "</td><td>" + str(metric["human_followup"]) + "</td><td>" +
            esc(team_workload) + "</td></tr>"
        )
    current_rows = []
    for before, now in zip(oldest, latest):
        key = now["workflow_key"]
        is_attention = key in attention_keys
        is_changed = any(
            before[k] != now[k] for k in (
                "human_stage", "review_team", "followup_date", "human_question"))
        search = " ".join((key, now["title"], now["human_stage"],
                           now["review_team"], now["followup_date"]))
        stage_class = "pill attn" if is_attention else "pill"
        current_rows.append(
            '<tr data-workflow-row data-search="' + esc(search) +
            '" data-stage="' + esc(now["human_stage"]) +
            '" data-team="' + esc(now["review_team"]) +
            '" data-attention="' + str(is_attention).lower() +
            '" data-changed="' + str(is_changed).lower() + '"><th scope="row">' +
            esc(now["title"]) + '<div class="muted">' + esc(key) + '</div></th>' +
            '<td><span class="' + stage_class + '">' + esc(now["human_stage"]) +
            "</span></td><td>" + esc(now["review_team"] or "Unassigned") +
            "</td><td>" + esc(now["followup_date"] or "None declared") +
            "</td><td>" + esc(before["human_stage"]) +
            "</td><td>" + ('<span class="change">Changed</span>' if is_changed
                           else "Same HUMAN metadata") + "</td></tr>"
        )
    attention_rows = []
    for entry in attention:
        attention_rows.append(
            "<li><strong>" + esc(entry["workflow_title"]) + "</strong>: " +
            esc(entry["declared_stage"]) + " · " +
            esc(entry["declared_team"] or "Unassigned") +
            "<br><span class='muted'>Consecutive operator-ordered snapshots: " +
            str(entry["consecutive_attention_snapshots"]) + " (since #" +
            str(entry["first_continuous_declared_position"]) + "); manual follow-up " +
            esc(entry["declared_followup"] or "not declared") + "</span></li>"
        )
    history = []
    for change in changes:
        history.append(
            "<li><strong>" + esc(change["workflow_title"]) + "</strong> · #" +
            str(change["from_snapshot"]) + " → #" + str(change["to_snapshot"]) +
            " · " + esc(", ".join(change["fields"])) +
            "<br><span class='muted'>" + esc(change["previous_stage"]) +
            " → " + esc(change["current_stage"]) + " · " +
            esc(change["previous_team"] or "Unassigned") + " → " +
            esc(change["current_team"] or "Unassigned") + "</span></li>"
        )
    movement_rows = []
    for item in movement:
        movement_rows.append(
            "<tr><th scope='row'>#" + str(item["from_snapshot"]) + " → #" +
            str(item["to_snapshot"]) + "</th><td>" +
            str(item["human_stage_changes"]) + "</td><td>" +
            str(item["human_team_changes"]) + "</td><td>" +
            str(item["newly_declared_attention"]) + "</td><td>" +
            str(item["no_longer_declared_attention"]) + "</td><td>" +
            str(item["continuously_declared_attention"]) + "</td><td>" +
            str(item["human_question_edits"]) + "</td></tr>"
        )
    options_stage = "".join('<option value="' + esc(value) + '">' +
                            esc(value) + "</option>" for value in route_queue.STAGES)
    options_team = "".join('<option value="' + esc(team) + '">' +
                           esc(team) + "</option>" for team in human_workpack.TEAM_FOLDERS)
    options_team = '<option value="">All teams / unassigned</option>' + options_team
    script_hash = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode("ascii")
    page = ('''<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-''' + script_hash + """'; connect-src 'none'; form-action 'none'; base-uri 'none'; img-src 'none'; object-src 'none'">
<title>LightUp · PRIVATE HUMAN Progress Cockpit</title>""" + CSS + """</head><body>
<header><p class="tag">LIGHTUP / OFFLINE / HUMAN ONLY / REVIEW_ONLY</p>
<h1>Assessment Progress Cockpit</h1><p>Original private human workpacks compared against one unchanged
local session PATH fingerprint. This is NOT verified evidence,
risk severity, a completed assessment, client consent or permission to scan.</p>
<div class="metrics"><div class="metric"><b>""" + str(len(snapshots)) + """</b><span>Manually ordered snapshots</span></div>
<div class="metric"><b>""" + str(len(latest)) + """</b><span>Original HUMAN workflows</span></div>
<div class="metric"><b>""" + str(last_counts["attention"]) + """</b><span>Latest declared HOLD / NEEDS INPUT</span></div>
<div class="metric"><b>""" + str(len(changes)) + """</b><span>Recorded transitions</span></div></div></header>
<section><h2>Latest HUMAN workflow state</h2>
<p>Local-only search and filters never modify source or export hidden data.
The latest workpack remains editable only by continuing it in the original
native HUMAN workpack workflow (console 51 or CLI workpack-continue).</p>
<div class="controls">
<label>Search original HUMAN workflow<input id="workflow-search" type="search" placeholder="Workflow, team, declared date" autocomplete="off"></label>
<label>HUMAN stage<select id="stage-select"><option value="">All stages</option>""" +
            options_stage + """</select></label>
<label>Assigned team<select id="team-select">""" + options_team + """</select></label>
</div>
<div class="checks"><label><input id="attention-only" type="checkbox">
 Latest HOLD / NEEDS_INPUT only</label><label><input id="changed-only" type="checkbox">
 Changed since first declared snapshot</label><button id="reset-filters" type="button">
 Clear filters</button></div>
<p id="visible-count" role="status" aria-live="polite">""" +
            str(len(latest)) + """ original workflows shown</p>
<div class="scroller"><table><thead><tr><th>Workflow</th><th>Latest HUMAN stage</th>
<th>Team</th><th>Proposed follow-up</th><th>First HUMAN stage</th>
<th>Change</th></tr></thead><tbody>""" + "".join(current_rows) +
            """</tbody></table></div></section>
<section><h2>Still-declared HUMAN attention</h2>
<p>No real duration, source findings or incident severity is inferred.</p><ol>""" +
            ("".join(attention_rows) or "<li>No latest HUMAN attention declarations.</li>") +
            """</ol></section>
<section><h2>Declared HUMAN movement between snapshots</h2>
<p>Newly marked HOLD and no-longer-marked HOLD are only operator
status choices, NEVER a new security incident or verified fix.</p>
<div class="scroller"><table><thead><tr><th>Declared positions</th>
<th>Stage edits</th><th>Team edits</th><th>New attention</th>
<th>No longer marked</th><th>Still marked</th><th>Private question edits</th>
</tr></thead><tbody>""" + "".join(movement_rows) + """</tbody></table></div>
</section>
<section><details><summary>Show all declared snapshot summaries</summary>
<div class="scroller"><table><thead><tr><th>Snapshot</th><th>Declared date</th>
<th>Unassessed</th><th>Attention</th><th>Review</th><th>Follow-up</th><th>Teams</th>
</tr></thead><tbody>""" + "".join(snapshot_rows) +
            """</tbody></table></div></details>
<details><summary>Show manual transition history</summary><ol>""" +
            ("".join(history) or "<li>No HUMAN changes declared.</li>") +
            """</ol></details></section><footer>
<p class="tag">INCUBATE M3/M7 · DRAFT/HOLD · NO AUTHORITY</p>
<p>Dates and order are operator declarations, never authenticated chronology.
PRIVATE source bytes, paths, original filenames, credential material, free
HUMAN questions and user identities are not included. This downloaded
owner-private page has no network calls or persistent storage. No scan,
grant, scheduling, client contact, automated risk decision or release.
Current separately verified client/operator consent including revocation
at action time, source-owner approval, independent security/privacy/browser
review, existing exact-head CI and explicit HUMAN GO are still required.</p>
</footer><script>""" + JS + """</script></body></html>""")
    return page.encode("utf-8")
