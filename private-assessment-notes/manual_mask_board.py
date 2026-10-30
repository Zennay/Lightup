"""Offline PRIVATE HUMAN literal mask plan editor, not a disclosure/sanitization gate."""
from __future__ import annotations

import base64
from hashlib import sha256
import html

JS = r"""
"use strict";
(() => {
  const cards=Array.from(document.querySelectorAll("article[data-original-slot]"));
  const feedback=document.getElementById("feedback");
  const count=document.getElementById("count");
  function entries() {
    return cards.flatMap(card=>
      Array.from(card.querySelectorAll("input[data-rule]")).map(input=>({
        original_source_ordinal:Number(card.dataset.originalSlot),
        original_source_sha256_unsigned:card.dataset.originalSha,
        literal_to_mask:input.value
      }))
    );
  }
  function refresh() {
    count.textContent=entries().length+" / 24 original PRIVATE HUMAN literal rules currently entered. "+
      "Every literal must be an exact match in the already-masked source.";
    for(const card of cards) {
      card.querySelector("button[data-add]").disabled=entries().length>=24;
    }
  }
  function add(card) {
    if(entries().length>=24) {
      feedback.textContent="HOLD: maximum 24 PRIVATE manual masking rules.";
      return;
    }
    const area=card.querySelector("div[data-rules]");
    const row=document.createElement("div");
    row.className="inputrow";
    const label=document.createElement("label");
    label.textContent="Exact PRIVATE remaining sensitive phrase (3–256 characters)";
    const input=document.createElement("input");
    input.type="text";
    input.maxLength=256;
    input.autocomplete="off";
    input.spellcheck=false;
    input.setAttribute("data-rule","");
    const remove=document.createElement("button");
    remove.type="button";
    remove.textContent="Remove this unsaved rule";
    remove.addEventListener("click",()=>{row.remove();refresh();});
    label.appendChild(input);
    row.appendChild(label);
    row.appendChild(remove);
    area.appendChild(row);
    input.focus();
    refresh();
  }
  for(const card of cards) {
    card.querySelector("button[data-add]").addEventListener("click",()=>add(card));
  }
  document.getElementById("resume").addEventListener("change",async event=>{
    const file=event.target.files && event.target.files[0];
    event.target.value="";
    if(!file)return;
    try{
      if(file.size<40 || file.size>65536)
        throw Error("Original PRIVATE masking draft exceeds local import bound.");
      const data=new TextDecoder("utf-8",{fatal:true}).decode(await file.arrayBuffer());
      if(data.includes("\uFEFF"))throw Error("Unexpected byte-order marker.");
      const doc=JSON.parse(data);
      if(!doc || typeof doc!=="object" || Array.isArray(doc) ||
        data!==JSON.stringify(doc,null,2)+"\n" ||
        Object.keys(doc).join("|")!==
          "schema|claimed_status|completed_manifest_sha256_unsigned|completed_human_csv_sha256_unsigned|rules|source_authenticated|client_consent_verified|operator_consent_verified|approved_to_share|release_allowed|dispatch_allowed" ||
        doc.schema!=="lightup.private_human_extra_mask_rules.v1" ||
        doc.claimed_status!=="HOLD" ||
        doc.completed_manifest_sha256_unsigned!==document.body.dataset.originalManifest ||
        doc.completed_human_csv_sha256_unsigned!==document.body.dataset.originalDecisions ||
        doc.source_authenticated!==false || doc.client_consent_verified!==false ||
        doc.operator_consent_verified!==false || doc.approved_to_share!==false ||
        doc.release_allowed!==false || doc.dispatch_allowed!==false ||
        !Array.isArray(doc.rules) || doc.rules.length<1 || doc.rules.length>24)
        throw Error("Original PRIVATE masking rule file or SHA binding differs.");
      const staged=[];
      const unique=new Set();
      for(const item of doc.rules){
        if(!item || Array.isArray(item) || typeof item!=="object" ||
          Object.keys(item).join("|")!==
             "original_source_ordinal|original_source_sha256_unsigned|literal_to_mask" ||
          !Number.isInteger(item.original_source_ordinal) ||
          item.original_source_ordinal<1 || item.original_source_ordinal>cards.length ||
          item.original_source_sha256_unsigned!==
            cards[item.original_source_ordinal-1].dataset.originalSha ||
          typeof item.literal_to_mask!=="string" ||
          item.literal_to_mask.length<3 || item.literal_to_mask.length>256 ||
          item.literal_to_mask!==item.literal_to_mask.trim() ||
          /[\x00-\x1F\x7F]/.test(item.literal_to_mask) ||
          item.literal_to_mask.includes("[REDACTED") ||
          item.literal_to_mask.includes("[MANUALLY_REDACTED]")){
          throw Error("Malformed original source PRIVATE literal.");
        }
        const key=item.original_source_ordinal+"::"+item.literal_to_mask;
        if(unique.has(key))throw Error("Repeated original source masking literal.");
        unique.add(key);
        staged.push(item);
      }
      if(!window.confirm("Restore all "+staged.length+" ORIGINAL source-bound PRIVATE "+
          "masking phrases into this local browser? This replaces current unsaved "+
          "rules but does not edit any original source or authorize release.")){
        feedback.textContent="PRIVATE draft restoration cancelled; existing rules unchanged.";
        return;
      }
      cards.forEach(card=>card.querySelector("div[data-rules]").replaceChildren());
      for(const item of staged){
        const card=cards[item.original_source_ordinal-1];
        add(card);
        const inputs=card.querySelectorAll("input[data-rule]");
        inputs[inputs.length-1].value=item.literal_to_mask;
      }
      refresh();
      feedback.textContent="Source-bound PRIVATE masking phrases restored locally. "+
        "Native exact-source re-admission remains required before creating a new packet.";
    }catch(error){
      feedback.textContent="HOLD: no manual PRIVATE rules restored; current choices unchanged. "+
        (error instanceof Error?error.message:"Invalid local PRIVATE draft.");
    }
  });
  document.getElementById("clear").addEventListener("click",()=>{
    if(!window.confirm("Clear every unsaved PRIVATE HUMAN literal from this local browser page? "+
      "No original source or completed packet will change."))return;
    document.querySelectorAll("div[data-rules]").forEach(node=>node.replaceChildren());
    feedback.textContent="Unsaved PRIVATE literal fields cleared locally.";
    refresh();
  });
  document.getElementById("save").addEventListener("click",()=>{
    const rules=entries();
    if(!rules.length || rules.length>24){
      feedback.textContent="HOLD: select 1–24 literal PRIVATE masking rules.";return;
    }
    const seen=new Set();
    for(const entry of rules){
      const value=entry.literal_to_mask;
      const key=entry.original_source_ordinal+"::"+value;
      if(value.length<3||value.length>256||value.trim()!==value||
         /[\x00-\x1F\x7F]/.test(value) || value.includes("[REDACTED") ||
         value.includes("[MANUALLY_REDACTED]") || seen.has(key)) {
        feedback.textContent="HOLD: empty, repeated, unsafe or malformed PRIVATE HUMAN literal.";return;
      }
      seen.add(key);
    }
    if(!window.confirm("Export "+rules.length+" PRIVATE source-bound masking rules? "+
      "The JSON will CONTAIN the actual sensitive literal text. Move the file immediately "+
      "to an owner-only 0600 location. This does not anonymize or authorize sharing."))return;
    const doc={
      schema:"lightup.private_human_extra_mask_rules.v1",
      claimed_status:"HOLD",
      completed_manifest_sha256_unsigned:document.body.dataset.originalManifest,
      completed_human_csv_sha256_unsigned:document.body.dataset.originalDecisions,
      rules,
      source_authenticated:false,
      client_consent_verified:false,
      operator_consent_verified:false,
      approved_to_share:false,
      release_allowed:false,
      dispatch_allowed:false
    };
    const bytes=JSON.stringify(doc,null,2)+"\n";
    const blob=new Blob([bytes],{type:"application/json;charset=utf-8"});
    const url=URL.createObjectURL(blob);
    const link=document.createElement("a");
    link.href=url;
    link.download="PRIVATE-manual-mask-rules-completed.json";
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    feedback.textContent="PRIVATE rules JSON exported locally. It CONTAINS secret literals. "+
      "Keep mode 0600 and run native notes.py mask-copy separately; no source was modified.";
  });
  refresh();
})();
"""
CSS = """
:root{font:16px/1.6 system-ui;color:#172a41;background:#eaf1f6}
*{box-sizing:border-box}body{max-width:940px;margin:auto;padding:22px}
header,article,footer{background:white;border:1px solid #c7d8e5;border-radius:14px;padding:20px;margin:15px 0}
h1{font-size:clamp(1.65rem,4vw,2.5rem)}h2{font-size:1.2rem}
.warning{background:#fff0e7;border-left:5px solid #ac502a;padding:15px}
label{display:block;font-weight:650;margin:15px 0 6px}
input{display:block;width:100%;padding:11px;font:inherit;border:1px solid #95a8b8;border-radius:6px}
button{font:inherit;background:#125675;color:white;border:0;
border-radius:8px;padding:10px 15px;margin:8px 6px;cursor:pointer}
button:disabled{opacity:.4;cursor:not-allowed}
button:focus-visible,input:focus-visible,summary:focus-visible{outline:3px solid #d19a42}
.inputrow{background:#f2f7fa;border:1px solid #d9e3ed;padding:12px;border-radius:8px;margin:9px 0}
pre{white-space:pre-wrap;overflow-wrap:anywhere;background:#1c2a39;color:#f0f5fd;
padding:16px;border-radius:8px}
details{margin-top:15px}summary{font-weight:650;cursor:pointer}
@media print{button,input{display:none}article{break-inside:avoid}}
"""


def render(rows: list[dict], manifest_digest: str, decisions_digest: str) -> bytes:
    for digest in (manifest_digest, decisions_digest):
        if len(digest)!=64 or any(c not in "0123456789abcdef" for c in digest):
            raise ValueError("invalid owner-private unsigned original digest")
    cards=[]
    for index,item in enumerate(rows,1):
        if (type(item.get("ordinal")) is not int or item["ordinal"]!=index
            or type(item.get("source_sha256_unsigned")) is not str or
            len(item["source_sha256_unsigned"])!=64):
            raise ValueError("invalid original PRIVATE HUMAN source identity")
        slot=str(index)
        cards.append(
            '<article data-original-slot="'+slot+'" data-original-sha="'+
            html.escape(item["source_sha256_unsigned"])+'">'+
            '<h2>Original PRIVATE completed HUMAN note #'+slot+'</h2>'+
            '<p>Source content remains PRIVATE after masking. Inspect the already-masked '+
            'content locally and add exact remaining phrases to mask.</p>'+
            '<details><summary>Expand pattern-masked original #'+slot+
            ' (may still contain sensitive details)</summary><pre>'+
            html.escape(item["redacted_text"])+'</pre></details>'+
            '<div data-rules></div><button data-add type="button">'+
            'Add original-specific PRIVATE literal</button></article>'
        )
    js_integrity=base64.b64encode(sha256(JS.encode("utf-8")).digest()).decode("ascii")
    text=( """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" +
            js_integrity + """'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp · PRIVATE HUMAN extra-masking plan</title>
<style>""" + CSS + """</style><body data-original-manifest=\"""" +
            manifest_digest + """\" data-original-decisions=\"""" +
            decisions_digest + """\"><header><p class="warning"><b>HOLD · PRIVATE HUMAN ONLY</b>
<br>These masked notes may still contain secrets, personal data, proprietary
details or original source evidence. The browser never uploads or stores data,
and this plan does NOT make anything safe to disclose.</p>
<h1>Mask more PRIVATE content manually</h1>
<p>Select only exact sensitive phrases in the currently shown already-pattern-masked
source. Your typed secret literal remains in this local browser page until
you explicitly export it or close/clear the page. The downloaded JSON
**CONTAINS THE ACTUAL SENSITIVE PHRASE**; protect it with mode 0600.
Native source-bound admission and final external consent/review remain separate.</p></header>
<p id="count" role="status" aria-live="polite"></p>
<div><label>Reopen original locally exported PRIVATE masking rules (.json)
<input id="resume" type="file" accept=".json,application/json"></label>
<p>Import is local-only, bounded to 64 KiB and requires exact original
manifest, HUMAN CSV digest, ordinals and secret literal values before one
explicit HUMAN confirmation. No upload, network or automatic source edits.</p>
</div><main>""" + "".join(cards) + """</main><footer>
<button id="save" type="button">Save SENSITIVE PRIVATE source-bound masking JSON</button>
<button id="clear" type="button">Clear unsaved literals</button>
<p id="feedback" role="status" aria-live="polite"></p>
<p class="warning">This offline editor cannot verify that the selected phrases
are complete, actually contain secrets, or are safe to share. The native
`notes.py mask-copy` must check all exact original source identities and
apply every requested phrase. No task, network, scanning, approval, consent,
recipient authentication or disclosure. INCUBATE M3/M7 PLAN/LAB ONLY.</p>
</footer><script>""" + JS + """</script></body></html>""")
    return text.encode("utf-8")
