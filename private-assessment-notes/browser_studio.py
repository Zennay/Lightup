"""Generate a fully offline PRIVATE HUMAN decision editor without browser storage or network."""
from __future__ import annotations
import base64
import hashlib
import html

JS = r"""
"use strict";
(() => {
  const permitted = new Set(["NEEDS_HUMAN_REVIEW","SOURCE_OWNER_REQUIRED","WITHHOLD","INTERNAL_REVIEW_ONLY"]);
  const bulkPermitted = new Set(["NEEDS_HUMAN_REVIEW","SOURCE_OWNER_REQUIRED","WITHHOLD"]);
  const nodes = Array.from(document.querySelectorAll("article[data-ordinal]"));
  const message = document.getElementById("message");
  const stageFilter = document.getElementById("filter-stage");
  const search = document.getElementById("filter-text");
  const count = document.getElementById("count");
  const bulk = document.getElementById("bulk-stage");
  const undo = document.getElementById("undo");
  let beforeBulk = null;
  function csv(value) {return '"' + String(value).replaceAll('"','""') + '"';}
  function status(node) {return node.querySelector("select").value;}
  function note(node) {return node.querySelector("textarea").value;}
  function refresh() {
    const totals = Object.fromEntries(Array.from(permitted, key => [key,0]));
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const node of nodes) {
      totals[status(node)]++;
      const match = (stageFilter.value === "ALL" || stageFilter.value === status(node))
        && (!query || node.dataset.ordinal.includes(query) || note(node).toLocaleLowerCase().includes(query));
      node.hidden = !match;
      if (match) visible++;
    }
    count.textContent = visible + " of " + nodes.length + " original PRIVATE sources displayed. " +
      "Needs review: " + totals.NEEDS_HUMAN_REVIEW +
      " · Owner required: " + totals.SOURCE_OWNER_REQUIRED +
      " · Withhold: " + totals.WITHHOLD +
      " · Internal review only: " + totals.INTERNAL_REVIEW_ONLY + ".";
    undo.disabled = !beforeBulk;
  }
  stageFilter.addEventListener("change",refresh);
  search.addEventListener("input",refresh);
  for (const node of nodes) {
    node.querySelector("select").addEventListener("change",() => {beforeBulk=null;refresh();});
    node.querySelector("textarea").addEventListener("input",refresh);
  }
  document.getElementById("bulk").addEventListener("click",() => {
    const choice=bulk.value;
    const visible=nodes.filter(node=>!node.hidden);
    if (!bulkPermitted.has(choice) || !visible.length) {
      message.textContent="HOLD: choose a permitted HUMAN discussion stage and at least one visible row.";
      return;
    }
    if (!window.confirm("Change " + visible.length + " visible PRIVATE HUMAN stages to " + choice +
      "? Hidden original rows remain unchanged. This is not authorization or permission to share.")) return;
    beforeBulk=nodes.map(status);
    for (const node of visible) node.querySelector("select").value=choice;
    message.textContent=visible.length+" locally proposed HUMAN stages updated. Review each source before CSV export.";
    refresh();
  });
  undo.addEventListener("click",() => {
    if (!beforeBulk) return;
    nodes.forEach((node,i)=>node.querySelector("select").value=beforeBulk[i]);
    beforeBulk=null;
    message.textContent="Last group stage change undone. HUMAN notes remain unchanged.";
    refresh();
  });
  document.getElementById("save").addEventListener("click", () => {
    const rows=["source_ordinal,source_sha256_unsigned,human_stage,human_note"];
    for (const node of nodes) {
      const ordinal=node.dataset.ordinal;
      const source=node.dataset.sha256;
      const stage=status(node);
      const human=note(node).replace(/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/g," ").trim();
      if (!/^[0-9a-f]{64}$/.test(source) || !/^\d+$/.test(ordinal) || !permitted.has(stage)
          || human.length>500 || /^[\s]*[=+@-]/.test(human)) {
        message.textContent="HOLD: invalid local HUMAN choice or formula-like note; no CSV saved.";
        return;
      }
      rows.push([ordinal,source,stage,human].map(csv).join(","));
    }
    const blob=new Blob([rows.join("\r\n")+"\r\n"],{type:"text/csv;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;
    link.download="PRIVATE-HUMAN-decisions-completed.csv";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    message.textContent="Complete original-source-bound PRIVATE CSV saved locally ("+nodes.length+
      " original rows, including all hidden rows). Run native finalize separately. No release permission.";
  });
  refresh();
})();

"""


def render(sources: list[dict], decisions: list[dict] | None = None) -> bytes:
    integrity = base64.b64encode(hashlib.sha256(JS.encode("utf-8")).digest()).decode("ascii")
    cards = []
    for item in sources:
        ordinal = item["ordinal"]
        sha = item["source_sha256_unsigned"]
        assert type(ordinal) is int and 1 <= ordinal <= 12
        assert type(sha) is str and len(sha) == 64 and all(x in "0123456789abcdef" for x in sha)
        prior = decisions[ordinal - 1] if decisions else {}
        prior_stage = prior.get("human_stage", "NEEDS_HUMAN_REVIEW")
        prior_note = prior.get("human_note", "")
        assert prior_stage in {"NEEDS_HUMAN_REVIEW", "SOURCE_OWNER_REQUIRED",
                               "WITHHOLD", "INTERNAL_REVIEW_ONLY"}
        assert type(prior_note) is str and len(prior_note) <= 500
        options = (
            ("NEEDS_HUMAN_REVIEW", "Needs further HUMAN review"),
            ("SOURCE_OWNER_REQUIRED", "Ask original source owner"),
            ("WITHHOLD", "Withhold from all recipients"),
            ("INTERNAL_REVIEW_ONLY", "Internal PRIVATE review only"),
        )
        select_options = "".join(
            '<option value="' + value + '"' + (' selected' if value == prior_stage else '') +
            '>' + label + '</option>' for value, label in options
        )
        cards.append(
            f'<article data-ordinal="{ordinal}" data-sha256="{sha}">'
            f'<h2>PRIVATE original note #{ordinal}</h2>'
            f'<label for="stage-{ordinal}">HUMAN disposition (not authorization)</label>'
            f'<select id="stage-{ordinal}">' + select_options + '</select>'
            f'<label for="note-{ordinal}">PRIVATE optional HUMAN note (max 500 characters)</label>'
            f'<textarea id="note-{ordinal}" maxlength="500" rows="3" '
            'placeholder="Next HUMAN question; no secrets or personal details">'
            + html.escape(prior_note) + '</textarea>'
            '<details><summary>Inspect PRIVATE pattern-masked source #' + str(ordinal) +
            ' (may still contain secrets)</summary><pre>' +
            html.escape(item["redacted_text"]) + '</pre></details></article>'
        )
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" + integrity + """'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'; img-src 'none'">
<title>LightUp PRIVATE HUMAN disposition studio</title>
<style>
:root{font:17px/1.5 system-ui;color:#102638;background:#eef4f7}
*{box-sizing:border-box}body{max-width:850px;margin:auto;padding:24px}
header,article,footer,.toolbar{background:white;border:1px solid #c8d9e8;border-radius:14px;padding:20px;margin:14px 0}
h1{font-size:clamp(1.7rem,4vw,2.6rem);margin:0 0 10px}
h2{font-size:1.13rem;margin:0 0 12px}
p{line-height:1.65}
.warning{border-left:4px solid #b3532a;padding:12px 16px;background:#fff1eb;color:#7d351b}
label{display:block;font-weight:650;margin:12px 0 5px}
select,textarea,input{width:100%;font:inherit;border:1px solid #8c9caa;border-radius:7px;padding:10px}
button{border:0;border-radius:10px;padding:15px 24px;font-weight:750;font:inherit;background:#125376;color:white;cursor:pointer}
button:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #d9982f;outline-offset:2px}
#message{min-height:3em;font-weight:650}
article[hidden]{display:none}
.toolbar{display:grid;gap:12px;margin:14px 0}
.toolbar label{margin:0}
.toolbar .grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(210px,1fr));gap:14px}
.toolbar button{margin:6px 8px 0 0}
.toolbar button:disabled{opacity:.5;cursor:not-allowed}
details{margin-top:18px;border-top:1px solid #c8d9e8;padding-top:8px}
summary{cursor:pointer;font-weight:650}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#172535;color:#f1f5fb;border-radius:8px;padding:16px}
#count{font-weight:650}
@media print{button{display:none}body{background:white;padding:0}article{break-inside:avoid}}
</style><header><p class="warning"><b>LightUp · PRIVATE HUMAN ONLY · REVIEW_ONLY/HOLD</b><br>
Local decisions are not approval, consent or permission to share.</p>
<h1>Assess credential-masked notes</h1>
<p>Use each source slot to record a strictly local HUMAN disposition.
This browser page does not contain the original raw credentials, but hashes,
notes and masked text remain confidential. The masking is pattern-based;
secret strings and personal data may remain elsewhere.</p>
<p>Nothing is uploaded or stored by the page. Save a new PRIVATE decision
CSV and provide it to the separate native finalize step. The native original
source identity and every row must match exactly or the handoff will HOLD.</p></header>
<section class="toolbar" aria-label="Filter and propose HUMAN stages">
<h2>Local HUMAN review board</h2>
<p>Filters change visibility only: every original source remains in the complete CSV. Masked
content stays hidden until explicitly expanded; masking does not prove privacy.</p>
<div class="grid">
<label>Find ordinal or local HUMAN note<input id="filter-text" type="search" autocomplete="off" placeholder="Filter PRIVATE entries"></label>
<label>Stage filter<select id="filter-stage">
<option value="ALL">All original stages</option>
<option value="NEEDS_HUMAN_REVIEW">Needs review</option>
<option value="SOURCE_OWNER_REQUIRED">Source owner required</option>
<option value="WITHHOLD">Withhold</option>
<option value="INTERNAL_REVIEW_ONLY">Internal review only</option></select></label>
</div><p id="count" role="status" aria-live="polite"></p>
<div class="grid"><label>Bulk proposal for VISIBLE rows only
<select id="bulk-stage"><option value="">Choose HUMAN stage</option>
<option value="NEEDS_HUMAN_REVIEW">Needs review</option>
<option value="SOURCE_OWNER_REQUIRED">Source owner required</option>
<option value="WITHHOLD">Withhold</option></select></label>
<div><button id="bulk" type="button">Confirm visible-stage proposal</button>
<button id="undo" type="button" disabled>Undo last group change</button></div></div>
<p class="warning">Group changes require manual confirmation and never assign authority.
For safety, INTERNAL_REVIEW_ONLY must be chosen individually.</p>
</section><main>""" + "".join(cards) + """</main>
<footer><button id="save" type="button">Save PRIVATE HUMAN decisions CSV</button>
<p role="status" id="message" aria-live="polite"></p>
<p class="warning">Even a completed HUMAN CSV never grants sharing authority.
All outputs remain owner-private. Original client/operator consent,
at-use revocation, source ownership, independent privacy/security
review, required CI and explicit HUMAN GO are external.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></footer>
<script>""" + JS + """</script></html>"""
    return page.encode("utf-8")
