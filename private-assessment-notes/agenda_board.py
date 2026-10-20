"""Render an independent offline PRIVATE HUMAN proposal board.

The UI proposes conversation only: it never schedules, assigns, authenticates
a HUMAN owner, or loads an original assessment finding.
"""
from __future__ import annotations

import base64
from hashlib import sha256
import html

JS = r"""
"use strict";
(() => {
  const nodes=Array.from(document.querySelectorAll("article[data-ordinal]"));
  const stages=new Set(["NO_PROPOSAL","DISCUSS_PRIVATELY","ASK_SOURCE_OWNER","WITHHOLD"]);
  const teams=new Set(["UNASSIGNED","SECURITY","PRIVACY","CLIENT_OPERATIONS","PLATFORM"]);
  const digest=document.body.dataset.historySha256;
  const message=document.getElementById("message");
  const filter=document.getElementById("filter");
  const counter=document.getElementById("count");
  function csv(s) {return '"' + String(s).replaceAll('"','""') + '"';}
  function fields(node) {
    return {
      ordinal:node.dataset.ordinal,
      original:node.dataset.stage,
      proposal:node.querySelector("select[data-proposal]").value,
      team:node.querySelector("select[data-team]").value,
      day:node.querySelector("input[data-day]").value,
      question:node.querySelector("textarea[data-question]").value
    };
  }
  function refresh() {
    let shown=0, proposed=0;
    for(const node of nodes){
      const item=fields(node);
      const isProposal=item.proposal!=="NO_PROPOSAL";
      if(isProposal) proposed++;
      const match=filter.value==="ALL" ||
        (filter.value==="PROPOSED" && isProposal) ||
        (filter.value==="UNPROPOSED" && !isProposal);
      node.hidden=!match;
      if(match) shown++;
    }
    counter.textContent=shown+" / "+nodes.length+" original PRIVATE HUMAN sources shown · "+
      proposed+" explicit local discussion proposals. Hidden rows remain in the complete CSV.";
  }
  function normalizeQuestion(s) {
    return s.replace(/[\r\n\x00-\x08\x0B\x0C\x0E-\x1F]/g," ").trim();
  }
  function validate(item) {
    const question=normalizeQuestion(item.question);
    if(!/^\d+$/.test(item.ordinal) || !stages.has(item.proposal) ||
        !teams.has(item.team) || question.length>300 ||
        /^[\s]*[=+@-]/.test(question) ||
        (item.day && !/^\d{4}-\d{2}-\d{2}$/.test(item.day)) ||
        (item.day && (Number.isNaN(Date.parse(item.day+"T00:00:00Z")) ||
          new Date(item.day+"T00:00:00Z").toISOString().slice(0,10)!==item.day)) ||
        (item.proposal==="NO_PROPOSAL" &&
          (item.team!=="UNASSIGNED" || item.day || question))) return null;
    return [
      item.ordinal,item.original,digest,item.proposal,item.team,item.day,question
    ];
  }
  for(const node of nodes){
    const status=node.querySelector("select[data-proposal]");
    status.addEventListener("change",()=>{
      if(status.value==="NO_PROPOSAL"){
        node.querySelector("select[data-team]").value="UNASSIGNED";
        node.querySelector("input[data-day]").value="";
        node.querySelector("textarea[data-question]").value="";
      }
      refresh();
    });
  }
  filter.addEventListener("change",refresh);
  document.getElementById("save").addEventListener("click",()=>{
    const rows=["original_source_ordinal,original_human_stage,history_sha256_unsigned,human_proposal,proposed_team,proposed_day,private_human_question"];
    for(const node of nodes){
      const values=validate(fields(node));
      if(!values){
        message.textContent="HOLD: invalid or unconfirmed local HUMAN proposal; no CSV exported.";
        return;
      }
      rows.push(values.map(csv).join(","));
    }
    if(!window.confirm("Save complete PRIVATE HUMAN discussion proposals for all "+nodes.length+
        " original source positions? This does not create tasks, notify anyone, or grant consent."))return;
    const blob=new Blob([rows.join("\r\n")+"\r\n"],{type:"text/csv;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;link.download="PRIVATE-HUMAN-agenda-completed.csv";
    document.body.appendChild(link);link.click();link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    message.textContent="Complete local PRIVATE CSV downloaded. Set file mode 0600 then use "+
      "native notes.py agenda-finalize. No real work was scheduled.";
  });
  document.getElementById("resume").addEventListener("change",async e=>{
    const file=e.target.files && e.target.files[0];
    e.target.value="";
    if(!file)return;
    try {
      if(!file.size || file.size>65536)throw Error("Draft outside original size bound.");
      const data=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      if(data.includes("\uFEFF"))throw Error("Unexpected UTF-8 marker.");
      const lines=data.split("\r\n");
      if(lines.pop()!=="" || lines.length!==nodes.length+1 ||
         lines[0]!=="original_source_ordinal,original_human_stage,history_sha256_unsigned,human_proposal,proposed_team,proposed_day,private_human_question")
        throw Error("Complete original CSV header and rows required.");
      const pattern=/^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$/u;
      const proposed=[];
      for(let i=0;i<nodes.length;i++){
        const match=pattern.exec(lines[i+1]);
        if(!match)throw Error("Noncanonical original HUMAN CSV row.");
        const dataFields=match.slice(1).map(s=>s.replaceAll('""','"'));
        const node=nodes[i];
        if(dataFields[0]!==node.dataset.ordinal ||
           dataFields[1]!==node.dataset.stage || dataFields[2]!==digest)
          throw Error("Original source history/digest differs.");
        const data={
          ordinal:dataFields[0],original:dataFields[1],
          proposal:dataFields[3],team:dataFields[4],
          day:dataFields[5],question:dataFields[6]
        };
        if(!validate(data))throw Error("Invalid HUMAN discussion fields.");
        proposed.push(data);
      }
      if(!window.confirm("Restore all "+nodes.length+" HUMAN discussion rows? "+
        "Current unsaved local proposals will be replaced, without any real work assignment.")){
        message.textContent="Restore cancelled; local choices unchanged.";return;
      }
      nodes.forEach((node,i)=>{
        const item=proposed[i];
        node.querySelector("select[data-proposal]").value=item.proposal;
        node.querySelector("select[data-team]").value=item.team;
        node.querySelector("input[data-day]").value=item.day;
        node.querySelector("textarea[data-question]").value=item.question;
      });
      refresh();
      message.textContent="PRIVATE original history-bound proposal draft restored locally; "+
        "native source-admission and separate HUMAN confirmation still required.";
    }catch(error){
      message.textContent="HOLD: no PRIVATE draft restored; existing choices unchanged. "+
        (error instanceof Error?error.message:"Invalid file.");
    }
  });
  refresh();
})();
"""

CSS = """
:root{color-scheme:light;font:16px/1.55 system-ui;color:#162e44;background:#edf3f7}
*{box-sizing:border-box}body{max-width:950px;margin:auto;padding:22px}
header,article,footer,.toolbar{background:white;border:1px solid #ccdce9;border-radius:14px;padding:20px;margin:14px 0}
h1{font-size:clamp(1.7rem,4vw,2.6rem)}h2{font-size:1.14rem}
.warn{border-left:5px solid #ac4c27;background:#fff1e7;padding:12px}
select,input,textarea{width:100%;border-radius:7px;border:1px solid #88a0b1;font:inherit;padding:9px}
label{display:block;font-weight:650;margin:14px 0 5px}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(205px,1fr));gap:12px}
button{font:inherit;background:#135776;color:white;border:0;border-radius:8px;padding:12px 20px;margin:8px;cursor:pointer}
button:focus-visible,select:focus-visible,input:focus-visible,textarea:focus-visible{outline:3px solid #c98b34}
article[hidden]{display:none}small{color:#486079}
@media print{body{background:white}button,input[type=file]{display:none}article{break-inside:avoid}}
"""


def render(positions: list[dict], digest: str) -> bytes:
    if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
        raise ValueError("original history digest invalid")
    integrity=base64.b64encode(sha256(JS.encode("utf-8")).digest()).decode("ascii")
    cards=[]
    for index, item in enumerate(positions, 1):
        if item["original_source_ordinal"]!=index or item["original_human_stage"] not in {
                "NEEDS_HUMAN_REVIEW","SOURCE_OWNER_REQUIRED","WITHHOLD","INTERNAL_REVIEW_ONLY"}:
            raise ValueError("invalid source position identity")
        cards.append(
            '<article data-ordinal="'+str(index)+'" data-stage="'+
            html.escape(item["original_human_stage"])+'"><h2>Original source position #'+
            str(index)+'</h2><p>Last source-bound HUMAN review stage: <strong>'+
            html.escape(item["original_human_stage"])+'</strong></p>'+
            '<div class="grid"><label>Proposed HUMAN discussion action<select data-proposal>'+
            '<option value="NO_PROPOSAL">No HUMAN proposal</option>'+
            '<option value="DISCUSS_PRIVATELY">Discuss privately</option>'+
            '<option value="ASK_SOURCE_OWNER">Ask original source owner (concept only)</option>'+
            '<option value="WITHHOLD">Withhold from discussion</option></select></label>'+
            '<label>Suggested HUMAN team (not assigned)<select data-team>'+
            '<option value="UNASSIGNED">Unassigned</option>'+
            '<option value="SECURITY">Security</option>'+
            '<option value="PRIVACY">Privacy</option>'+
            '<option value="CLIENT_OPERATIONS">Client operations</option>'+
            '<option value="PLATFORM">Platform</option></select></label></div>'+
            '<label>Manually proposed calendar day (never scheduled)<input data-day type="date"></label>'+
            '<label>PRIVATE internal HUMAN question, up to 300 characters'+
            '<textarea data-question maxlength="300" rows="3" '+
            'placeholder="Human follow-up question; do not paste secrets"></textarea></label>'+
            '<small>Original masked evidence and notes are intentionally excluded; '+
            'this is neither a task nor permission to share.</small></article>'
        )
    page = ('''<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; script-src 'sha256-''' +
            integrity + """'; connect-src 'none'; form-action 'none'; base-uri 'none'; img-src 'none'">
<title>LightUp · PRIVATE HUMAN next discussion editor</title><style>""" + CSS +
            """</style><body data-history-sha256=\"""" + digest + """\">
<header><p class="warn"><strong>HOLD · PRIVATE HUMAN concepts only</strong>
<br>No authenticated owner, actual task, consent, notification, client
reporting, execution or security PASS.</p>
<h1>Next HUMAN discussion proposals</h1><p>""" + str(len(positions)) +
            """ original byte-bound source positions. All original text,
masked evidence, source names and private HUMAN notes are absent.
Only the current original HUMAN stage and ordinal are shown.</p></header>
<section class="toolbar"><div class="grid">
<label>View local proposals<select id="filter">
<option value="ALL">All original rows</option>
<option value="PROPOSED">With manual proposals</option>
<option value="UNPROPOSED">Without proposal</option></select></label>
<label>Resume complete local PRIVATE agenda draft (.csv)
<input type="file" id="resume" accept=".csv,text/csv"></label>
</div><p role="status" id="count"></p><p>No filtered source row is
ever omitted from the exported CSV; a mismatch rejects an entire saved draft.
Dates are HUMAN suggestions, not reminders or appointments.</p></section>
<main>""" + "".join(cards) + """</main>
<footer><button id="save" type="button">Save complete PRIVATE HUMAN agenda CSV</button>
<p id="message" role="status" aria-live="polite"></p>
<p class="warn">Saving does NOT run native `agenda-finalize`, schedule any
event, assign a human owner, authenticate consent, disclose source material,
or authorize a scan. Current original source identity must be checked
again by the separate offline native command. Incubate M3/M7 DRAFT/HOLD.</p>
</footer><script>""" + JS + """</script></body></html>""")
    return page.encode("utf-8")
