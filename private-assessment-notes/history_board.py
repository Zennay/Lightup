"""Generate a fully offline source-minimal PRIVATE HUMAN timeline browser.

Original sources, masked note bytes, free text and recipient identifiers are
intentionally never included in this software-rendered history board.
"""
from __future__ import annotations
import base64
from hashlib import sha256
import html

JS = r"""
"use strict";
(() => {
  const select=document.getElementById("state");
  const search=document.getElementById("ordinal");
  const changes=document.getElementById("changed");
  const count=document.getElementById("count");
  const order=document.getElementById("order");
  const deck=document.getElementById("history-cards");
  const cards=Array.from(document.querySelectorAll("article[data-ordinal]"));
  const humanGroup={"WITHHOLD":0,"SOURCE_OWNER_REQUIRED":1,
    "NEEDS_HUMAN_REVIEW":2,"INTERNAL_REVIEW_ONLY":3};
  const stageCounts=document.getElementById("stage-counts");
  function refresh() {
    // Reorder only existing source-minimal DOM cards. This is a local visual
    // grouping of declared HUMAN stages, never an urgency/security verdict.
    const sorted=cards.slice().sort((a,b)=>{
      if(order.value==="STAGE_GROUP") {
        const delta=(humanGroup[a.dataset.stage]??9)-(humanGroup[b.dataset.stage]??9);
        if(delta) return delta;
      }
      if(order.value==="MOST_CHANGES") {
        const delta=Number(b.dataset.events)-Number(a.dataset.events);
        if(delta) return delta;
      }
      return Number(a.dataset.ordinal)-Number(b.dataset.ordinal);
    });
    sorted.forEach(card=>deck.appendChild(card));
    const term=search.value.trim();
    let shown=0, shownEvents=0;
    const counts=new Map();
    for(const card of cards) {
      const stage=card.dataset.stage;
      const recent=card.dataset.changed==="yes";
      counts.set(stage,(counts.get(stage)||0)+1);
      const show=(!term||card.dataset.ordinal.includes(term)) &&
        (select.value==="ALL"||stage===select.value) &&
        (!changes.checked||recent);
      card.hidden=!show;
      if(show) {shown++;shownEvents+=Number(card.dataset.events);}
    }
    count.textContent=shown+" / "+cards.length+" original HUMAN sources shown; "+
      shownEvents+" declared HUMAN change events across visible sources. "+
      "Filters do not modify any original review decision.";
    stageCounts.textContent=Array.from(counts).map(([stage,n])=>stage+": "+n).join(" · ");
  }
  select.addEventListener("change",refresh);
  search.addEventListener("input",refresh);
  changes.addEventListener("change",refresh);
  order.addEventListener("change",refresh);
  document.getElementById("open-visible").addEventListener("click",()=>{
    for(const card of cards) if(!card.hidden) card.querySelector("details").open=true;
  });
  document.getElementById("close-visible").addEventListener("click",()=>{
    for(const card of cards) if(!card.hidden) card.querySelector("details").open=false;
  });
  document.addEventListener("visibilitychange",()=>{
    if(document.hidden){search.value="";select.value="ALL";changes.checked=false;order.value="ORDINAL";refresh();}
  });
  refresh();
})();
"""

STYLE = """
:root{font:16px/1.55 system-ui;color:#172b43;background:#edf2f6}
*{box-sizing:border-box}body{max-width:1100px;margin:auto;padding:22px}
header,.filters,article,footer{background:#fff;border:1px solid #cbdbe8;
border-radius:14px;padding:20px;margin:16px 0}
h1{font-size:clamp(1.6rem,4vw,2.5rem)}h2{font-size:1.15rem}
.warn{border-left:5px solid #bd512a;background:#fff2e9;padding:15px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:16px}
label{display:block;font-weight:650}
select,input{width:100%;font:inherit;padding:11px;border:1px solid #8099aa;
border-radius:7px}input[type=checkbox]{width:auto;margin-right:8px}
button{border:0;border-radius:8px;padding:12px 16px;background:#155474;
font:inherit;color:white;cursor:pointer;margin:5px}
button:focus-visible,input:focus-visible,select:focus-visible,summary:focus-visible{
outline:3px solid #ce9036;outline-offset:3px}
article[hidden]{display:none}
strong{color:#243b5a}details{border-top:1px solid #c7d5e0;margin-top:10px;padding-top:10px}
summary{cursor:pointer;font-weight:650}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #bccbd8;padding:10px;text-align:left}
th{background:#e7eff5}
@media print{body{background:white;margin:0;padding:0}button,.filters{display:none}
article{break-inside:avoid}article[hidden]{display:block}}
"""


def render(rows: list[dict], events: list[dict], revision_count: int) -> bytes:
    integrity = base64.b64encode(sha256(JS.encode("utf-8")).digest()).decode("ascii")
    allowed = {"NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED", "WITHHOLD",
               "INTERNAL_REVIEW_ONLY"}
    cards = []
    for row in rows:
        ordinal = row["original_source_ordinal"]
        stage = row["current_human_stage"]
        if type(ordinal) is not int or not 1 <= ordinal <= 12 or stage not in allowed:
            raise ValueError("invalid original HUMAN browser stage/ordinal")
        original_events = [event for event in events
                           if event["original_source_ordinal"] == ordinal]
        events_html = "".join(
            "<tr><td>" + str(item["revision_level"]) + "</td><td>" +
            html.escape(item["previous_human_stage"]) + "</td><td>" +
            html.escape(item["current_human_stage"]) + "</td><td>" +
            ("Changed" if item["stage_changed"] else "Unchanged") +
            "</td><td>" +
            ("Changed, text withheld" if item["private_note_changed"] else "Unchanged") +
            "</td></tr>" for item in original_events
        )
        follow_up = ("Needs further PRIVATE HUMAN follow-up"
                     if row["human_action_needed"] else
                     "Individually marked PRIVATE internal review; not a release")
        cards.append(
            '<article data-ordinal="' + str(ordinal) +
            '" data-stage="' + html.escape(stage) +
            '" data-changed="' + ("yes" if original_events else "no") +
            '" data-events="' + str(len(original_events)) + '">' +
            '<h2>Original PRIVATE source position #' + str(ordinal) + '</h2>' +
            '<p><strong>Latest HUMAN stage:</strong> ' + html.escape(stage) + '</p>' +
            '<p><strong>Human discussion:</strong> ' + html.escape(follow_up) +
            ' · ' + str(row["stage_changes_total"]) + ' stage changes and ' +
            str(row["private_note_changes_total"]) + ' note changes since selected baseline.</p>' +
            '<details><summary>Review source-minimal HUMAN stage history (' +
            str(len(original_events)) + ' changes)</summary>' +
            '<table><thead><tr><th>Revision</th><th>Previous HUMAN stage</th>' +
            '<th>Current HUMAN stage</th><th>Stage changed</th>' +
            '<th>PRIVATE note</th></tr></thead><tbody>' +
            (events_html or "<tr><td colspan='5'>No HUMAN status or note changes</td></tr>") +
            '</tbody></table></details></article>'
        )
    options = "".join(
        '<option value="' + stage + '">' + stage.replace("_", " ") + '</option>'
        for stage in sorted(allowed)
    )
    document = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-""" +
                integrity + """'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · PRIVATE HUMAN history board</title><style>""" +
                STYLE + """</style><header><p class="warn"><strong>LightUp PRIVATE HUMAN
history — HOLD / NO AUTHORIZATION</strong><br>Local original-byte-bound
human decisions only. No security verdict, independently authenticated author,
recipient, consent, grant or permission to share.</p>
<h1>Private original HUMAN review history</h1><p>""" +
                str(len(rows)) + " exact original source positions, " +
                str(revision_count) + """ consecutive original completed review revisions.
Original source names, byte hashes, masked text and private notes are
intentionally absent from this browser report. Source references are ordinals
only, not proof of original owner identity.</p></header>
<section class="filters" aria-label="Filter local HUMAN history">
<h2>Find HUMAN follow-up</h2><div class="grid">
<label>Source slot<input id="ordinal" type="search" autocomplete="off"
placeholder="Original position, e.g. 2"></label>
<label>Current HUMAN stage<select id="state"><option value="ALL">All stages</option>""" +
                options + """</select></label>
<label><input id="changed" type="checkbox">Only original sources with a declared HUMAN change</label>
<label>Local presentation order<select id="order">
<option value="ORDINAL">Original source position</option>
<option value="STAGE_GROUP">Group by declared HUMAN follow-up stage (not urgency)</option>
<option value="MOST_CHANGES">Most declared HUMAN change events first</option>
</select></label>
</div><p id="count" role="status" aria-live="polite"></p>
<p id="stage-counts"></p>
<button id="open-visible" type="button">Expand visible timelines</button>
<button id="close-visible" type="button">Collapse visible timelines</button>
<p>Filtering changes only the visible local source-minimal view, never
an original PRIVATE decision, source identity or review status.</p></section>
<main id="history-cards">""" + "".join(cards) + """</main>
<footer><p>All data were generated offline from original completed PRIVATE HUMAN
packets. There is no browser upload, storage, network, target scanning,
model invocation, grant or client assessment. This report does not replace
the original source-bound native finalize process.
Incubate M3/M7 PLAN/LAB ONLY DRAFT/HOLD.</p></footer>
<script>""" + JS + """</script></html>""")
    return document.encode("utf-8")
