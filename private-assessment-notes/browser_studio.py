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
  function unsafeHumanCSVNote(value) {
    const text = String(value);
    const direction = Array.from(text).some(ch => {
      const n = ch.codePointAt(0);
      return n === 0x061C || (n >= 0x202A && n <= 0x202E) ||
        (n >= 0x2066 && n <= 0x2069) || n === 0x2028 || n === 0x2029;
    });
    const trimmed = text.trimStart();
    const initial = trimmed.codePointAt(0);
    const formatted = initial !== undefined &&
      ((initial >= 0x200B && initial <= 0x200F) ||
       (initial >= 0x2060 && initial <= 0x206F) ||
       (initial >= 0x0300 && initial <= 0x036F) || initial === 0xFEFF);
    return direction || formatted ||
      /^[=+@-]/.test(trimmed.normalize("NFKC").trimStart());
  }
  function status(node) {return node.querySelector("select").value;}
  function note(node) {return node.querySelector("textarea").value;}
  function refresh() {
    const totals = Object.fromEntries(Array.from(permitted, key => [key,0]));
    const query = search.value.trim().toLocaleLowerCase();
    let visible = 0;
    for (const node of nodes) {
      totals[status(node)]++;
      const pick = node.querySelector("input[data-private-select]");
      if (status(node) !== "INTERNAL_REVIEW_ONLY") pick.checked = false;
      pick.disabled = status(node) !== "INTERNAL_REVIEW_ONLY";
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
  // Exact original-row-bound resumption of a browser-exported PRIVATE HUMAN CSV.
  // No partial application: all rows, ordinals, hashes, values and byte size
  // are admitted before one explicit local HUMAN confirmation.
  const resume = document.getElementById("resume");
  resume.addEventListener("change", async () => {
    const file=resume.files && resume.files[0];
    resume.value="";
    if (!file) return;
    try {
      if (file.size === 0 || file.size > 65536)
        throw Error("PRIVATE decision draft exceeds the original size budget.");
      const data=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      if (data.includes("\uFEFF"))
        throw Error("Unexpected byte-order mark in PRIVATE draft.");
      const lines=data.split("\r\n");
      if (lines.pop() !== "" || lines.length !== nodes.length + 1 ||
          lines[0] !== "source_ordinal,source_sha256_unsigned,human_stage,human_note")
        throw Error("Draft must contain every original source in exact canonical order.");
      const fields=/^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$/u;
      const proposed=[];
      for (let i=0;i<nodes.length;i++) {
        const match=fields.exec(lines[i+1]);
        if (!match) throw Error("Draft row does not match the original browser CSV.");
        const [ordinal,sha,stage,human]=match.slice(1).map(x=>x.replaceAll('""','"'));
        const node=nodes[i];
        if (ordinal !== node.dataset.ordinal || sha !== node.dataset.sha256 ||
            !permitted.has(stage) || human.length > 500 ||
            /[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/.test(human) ||
            unsafeHumanCSVNote(human))
          throw Error("Draft original byte identity or HUMAN stage does not match.");
        proposed.push({stage,human});
      }
      if (!window.confirm("Restore all "+nodes.length+
          " original PRIVATE HUMAN draft rows? This replaces current unsaved local choices " +
          "but never authorizes sharing or edits any original file.")) {
        message.textContent="PRIVATE draft was not restored. Current choices are unchanged.";
        return;
      }
      nodes.forEach((node,i)=>{
        node.querySelector("select").value=proposed[i].stage;
        node.querySelector("textarea").value=proposed[i].human;
      });
      beforeBulk=null;
      message.textContent="All original source-bound HUMAN choices restored locally. " +
        "Inspect them before native finalize; unsigned SHA does not authenticate an author.";
      refresh();
    } catch (error) {
      message.textContent="HOLD: PRIVATE draft not restored; current choices unchanged. "+
        (error instanceof Error ? error.message : "Invalid local file.");
    }
  });
  // Restore only the exact canonical plan generated by this original offline UI.
  // No JSON partial update, no trusted author or recipient inferred.
  document.getElementById("resume-plan").addEventListener("change",async event=>{
    const file=event.target.files && event.target.files[0];
    event.target.value="";
    if (!file) return;
    try {
      if (file.size < 20 || file.size > 8192) throw Error("PRIVATE plan outside size bound.");
      const input=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      const parsed=JSON.parse(input);
      if (input !== JSON.stringify(parsed,null,2)+"\n" ||
          !parsed || Array.isArray(parsed) || typeof parsed!=="object" ||
          Object.keys(parsed).join("|")!==
            "schema|claimed_status|source_count|selected|recipient_authenticated|approved_to_share|release_allowed|dispatch_allowed" ||
          parsed.schema!=="lightup.private_assessment_selected_plan.v1" ||
          parsed.claimed_status!=="HOLD" ||
          parsed.source_count!==nodes.length ||
          parsed.recipient_authenticated!==false || parsed.approved_to_share!==false ||
          parsed.release_allowed!==false || parsed.dispatch_allowed!==false ||
          !Array.isArray(parsed.selected) || parsed.selected.length<1 ||
          parsed.selected.length>nodes.length)
        throw Error("PRIVATE plan source count/schema/authority fields invalid.");
      let last=0;
      const slots=new Set();
      for (const entry of parsed.selected) {
        if (!entry || Array.isArray(entry) || typeof entry!=="object" ||
            Object.keys(entry).join("|")!=="ordinal|source_sha256_unsigned" ||
            !Number.isInteger(entry.ordinal) || entry.ordinal<=last ||
            entry.ordinal>nodes.length ||
            entry.source_sha256_unsigned!==nodes[entry.ordinal-1].dataset.sha256 ||
            status(nodes[entry.ordinal-1])!=="INTERNAL_REVIEW_ONLY")
          throw Error("PRIVATE selected source bytes, order or HUMAN status mismatch.");
        last=entry.ordinal;
        slots.add(last);
      }
      if (!window.confirm("Restore "+slots.size+" exact original PRIVATE internal discussion " +
          "selections from unsigned local plan? Existing checkbox choices will be replaced; " +
          "HUMAN stages and free notes remain untouched.")) {
        message.textContent="PRIVATE selection restoration cancelled; no local choices modified.";
        return;
      }
      nodes.forEach(node=>{node.querySelector("input[data-private-select]").checked=
        slots.has(Number(node.dataset.ordinal));});
      refresh();
      message.textContent="PRIVATE original selected slots restored locally. " +
        "No completed native source admission or recipient permission was inferred.";
    } catch (error) {
      message.textContent="HOLD: plan not restored; selected rows unchanged. " +
        (error instanceof Error ? error.message : "Invalid plan.");
    }
  });
  // PRIVATE source-reference-only plan. Never serialize raw/masked text, HUMAN
  // free notes, browser paths, recipient identifiers or authorization claims.
  document.getElementById("save-plan").addEventListener("click", () => {
    refresh();
    const chosen=nodes.filter(node=>node.querySelector("input[data-private-select]").checked);
    if (!chosen.length || chosen.some(node=>status(node)!=="INTERNAL_REVIEW_ONLY")) {
      message.textContent="HOLD: individually choose at least one INTERNAL_REVIEW_ONLY original note.";
      return;
    }
    if (!window.confirm("Save a PRIVATE source-reference-only plan for "+chosen.length+
        " original HUMAN discussion entries? No note text is included and no recipient " +
        "is authenticated. Native source-bound admission and separate finalize remain required.")) return;
    const selected=chosen.map(node=>({
      ordinal:Number(node.dataset.ordinal),
      source_sha256_unsigned:node.dataset.sha256
    }));
    const payload={
      schema:"lightup.private_assessment_selected_plan.v1",
      claimed_status:"HOLD",
      source_count:nodes.length,
      selected,
      recipient_authenticated:false,
      approved_to_share:false,
      release_allowed:false,
      dispatch_allowed:false
    };
    const blob=new Blob([JSON.stringify(payload,null,2)+"\n"],{type:"application/json"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;link.download="PRIVATE-HUMAN-selected-plan.json";
    document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    message.textContent="Local PRIVATE source reference plan saved for "+selected.length+
      " original positions. chmod 600 before native notes.py select --plan. " +
      "This is not a receipt, authorization, recipient validation or delivery.";
  });
  document.getElementById("save").addEventListener("click", () => {
    const rows=["source_ordinal,source_sha256_unsigned,human_stage,human_note"];
    for (const node of nodes) {
      const ordinal=node.dataset.ordinal;
      const source=node.dataset.sha256;
      const stage=status(node);
      const human=note(node).replace(/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/g," ").trim();
      if (!/^[0-9a-f]{64}$/.test(source) || !/^\d+$/.test(ordinal) || !permitted.has(stage)
          || human.length>500 || unsafeHumanCSVNote(human)) {
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
            '<label class="checkrow"><input type="checkbox" data-private-select '
            'aria-label="Select source ' + str(ordinal) + ' for PRIVATE internal discussion plan">'
            'Plan internal-only discussion for this source (only after individual INTERNAL_REVIEW_ONLY)'
            '</label>'
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
input[type="checkbox"]{width:auto;min-width:22px;min-height:22px;accent-color:#125376}
.checkrow{display:flex;gap:10px;align-items:center;padding:10px;border:1px solid #aebfcd;border-radius:8px}
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
</div>
<label>Resume previously browser-exported PRIVATE HUMAN decisions (complete original CSV, no upload)
<input id="resume" type="file" accept=".csv,text/csv"></label>
<p>Imports are bounded to 64 KiB; every original position and unsigned source SHA
must match in order before explicit human confirmation. On mismatch, no choices
are changed. This only restores HUMAN suggestions, never release permission.</p>
<label>Reopen original PRIVATE selected discussion plan (after restoring HUMAN stages)
<input id="resume-plan" type="file" accept=".json,application/json"></label>
<p>A plan must have the exact original source roster and only individually
INTERNAL_REVIEW_ONLY entries. This restores checkbox selections only;
it never changes HUMAN stages or notes and never establishes authority.</p>
<p id="count" role="status" aria-live="polite"></p>
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
<button id="save-plan" type="button">Save selected PRIVATE discussion plan</button>
<p>Mark eligible original sources individually above. Save the complete HUMAN decisions
CSV first, complete native finalize, then use the separate PRIVATE plan with
native <code>notes.py select --plan</code>. Planning does not confer authority.</p>
<p role="status" id="message" aria-live="polite"></p>
<p class="warning">Even a completed HUMAN CSV never grants sharing authority.
All outputs remain owner-private. Original client/operator consent,
at-use revocation, source ownership, independent privacy/security
review, required CI and explicit HUMAN GO are external.
INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</p></footer>
<script>""" + JS + """</script></html>"""
    return page.encode("utf-8")
