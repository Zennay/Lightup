"""Offline one-file visual PRIVATE HUMAN revision choice editor.

Source export and the exact earlier encrypted notes are read through original
guarded admission; only a FALSE-by-default source-bound choice sheet is embedded
in the generated local browser artifact. The browser never sees earlier private
HUMAN notes/aliases or the source ciphertexts. No external scripts, network,
browser persistence or authority is provided.
"""
from __future__ import annotations

import argparse
import base64
from html import escape
import hashlib
import json
import sys

from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_human_revision import _read_inputs
from .private_export_human_revision_choices import _make_choices, MAX_CHOICES

CSS = """
:root{font:16px/1.5 system-ui,-apple-system,sans-serif;color:#142b43;background:#eef2f7}
*{box-sizing:border-box}body{margin:0}header{background:#10263f;color:white;padding:24px 4vw}
h1{font-size:clamp(23px,3vw,34px);margin:0}.sub{margin:.5rem 0 0}
main{max-width:1120px;padding:20px;margin:auto}
.warning{border-left:5px solid #a65c0a;background:#fff3d9;padding:18px;margin-bottom:18px}
.summary,.toolbar,.card{background:white;border:1px solid #cbd7e5;border-radius:11px;padding:16px;margin-bottom:12px}
.toolbar{display:flex;gap:12px;flex-wrap:wrap;align-items:end;position:sticky;top:0;z-index:2}
label{font-weight:650}label span{display:block;font-size:13px}
input[type=search],select{font:inherit;border:1px solid #92a6be;padding:9px;border-radius:7px}
input[type=search]{min-width:230px;max-width:100%;flex:1}
button{font:inherit;background:#095caa;color:white;border:0;border-radius:7px;cursor:pointer;padding:10px 15px;font-weight:700}
button:disabled{opacity:.5;cursor:default}
button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #448bee;outline-offset:2px}
.card{border-left:5px solid #9eacbd}.card[data-state=changed]{border-color:#af422e}
.card[data-state=new]{border-color:#ab790f}
.card[data-state=five_column_identical]{border-color:#147857}
.card h2{margin:0 0 5px;font-size:19px;overflow-wrap:anywhere}
.muted{color:#435970;font-size:13px}
.controls{display:flex;gap:18px;flex-wrap:wrap;margin-top:12px}
.controls label{background:#f4f7fb;border-radius:7px;padding:11px;flex:1 1 260px}
.controls input{width:19px;height:19px;vertical-align:middle;margin-right:8px}
.pill{display:inline-block;background:#edf2fa;padding:4px 9px;border-radius:99px;font-size:13px}
#notice{font-weight:700;color:#744207}
@media(max-width:620px){.toolbar{position:static;display:block}.toolbar>*{margin:5px 0;width:100%}}
@media print{.toolbar,.controls,#export,#clear{display:none!important}header{background:white;color:#142b43}}
"""

JS = r"""
"use strict";
const DATA = JSON.parse(new TextDecoder("utf-8",{fatal:true}).decode(Uint8Array.from(atob(__PAYLOAD__),c=>c.charCodeAt(0))));
const rows = DATA.decisions;
const root = document.getElementById("rows");
const status = document.getElementById("status");
const search = document.getElementById("search");
const filter = document.getElementById("filter");
const text = (tag,value)=>{const el=document.createElement(tag);el.textContent=String(value);return el;};
const known = new Set(["five_column_identical","changed","new"]);
function counts(){
 const owners=rows.filter(r=>r.copy_owner_and_note).length;
 const stages=rows.filter(r=>r.copy_stage_and_due).length;
 const eligible=rows.filter(r=>r.source_change==="five_column_identical").length;
 document.getElementById("summary").textContent=
   rows.length+" original new-source findings · "+eligible+
   " five-column-identical candidates · "+owners+
   " personally selected owner/note carries · "+stages+
   " explicitly selected stage/date carries. No choices are authorizations.";
}
function render(){
 root.replaceChildren();
 const query=search.value.trim().toLocaleLowerCase();
 const category=filter.value;
 for(const [index,row] of rows.entries()){
   const isSame=row.source_change==="five_column_identical";
   const kind=known.has(row.source_change)?row.source_change:"unknown";
   if(category!=="all"&&category!==kind)continue;
   if(query&&!([row.finding_id,row.title,row.severity,kind].join(" ").toLocaleLowerCase().includes(query)))continue;
   const card=text("article","");
   card.className="card";card.dataset.state=kind;
   const title=text("h2",row.title);card.append(title);
   const meta=text("p",row.finding_id+" · "+row.severity+" · "+kind.replaceAll("_"," "));
   meta.className="muted";card.append(meta);
   const notice=text("p",isSame?
     "All five source-exported columns match. Underlying evidence, authenticity, approval and fixes are UNKNOWN.":
     "Changed/new source row — no prior HUMAN coordination can be carried.");
   notice.className="pill";card.append(notice);
   const controls=text("div","");controls.className="controls";
   const ownerLabel=text("label","");
   const owner=document.createElement("input");owner.type="checkbox";owner.disabled=!isSame;
   owner.checked=row.copy_owner_and_note===true;
   owner.setAttribute("aria-label","Carry HUMAN alias and note for "+row.finding_id);
   owner.addEventListener("change",()=>{
     row.copy_owner_and_note=owner.checked;
     if(!owner.checked){row.copy_stage_and_due=false;stage.checked=false;}
     stage.disabled=!owner.checked;
     counts();
   });
   ownerLabel.append(owner,text("span","Copy HUMAN owner alias and private note — unverified"));
   const stageLabel=text("label","");
   const stage=document.createElement("input");stage.type="checkbox";
   stage.checked=row.copy_stage_and_due===true;
   stage.disabled=!isSame||!owner.checked;
   stage.setAttribute("aria-label","Carry HUMAN stage and proposed date for "+row.finding_id);
   stage.addEventListener("change",()=>{row.copy_stage_and_due=stage.checked;counts();});
   stageLabel.append(stage,text("span","Also carry HUMAN stage and proposed date — not a fix"));
   controls.append(ownerLabel,stageLabel);card.append(controls);root.append(card);
 }
 status.textContent=String(root.childElementCount)+" source rows shown.";
}
function download(){
 if(!document.getElementById("consent").checked){
   status.textContent="Review original data and explicitly acknowledge private recipient/storage first.";
   return;
 }
 if(!window.confirm("Export UNENCRYPTED original IDs and source labels for your PRIVATE human review? This file grants NO action."))return;
 const payload=JSON.stringify(DATA,null,2)+"\n";
 const blob=new Blob([payload],{type:"application/json;charset=utf-8"});
 const url=URL.createObjectURL(blob);
 try{
   const a=document.createElement("a");
   a.href=url;a.download="LightUp-PRIVATE-HUMAN-Revision-Choices.json";
   document.body.append(a);a.click();a.remove();
   status.textContent="Private unencrypted decision JSON requested. Securely store and verify the downloaded file (owner-only permissions) before CLI import.";
 }finally{
   setTimeout(()=>URL.revokeObjectURL(url),1500);
 }
}
search.addEventListener("input",render);filter.addEventListener("change",render);
document.getElementById("clear").addEventListener("click",()=>{
 for(const row of rows){row.copy_owner_and_note=false;row.copy_stage_and_due=false;}
 render();counts();status.textContent="All HUMAN carry choices reset to FALSE.";
});
document.getElementById("export").addEventListener("click",download);
render();counts();
"""

def _html(document: dict) -> bytes:
    raw = json.dumps(document, ensure_ascii=False, separators=(",", ":"),
                     allow_nan=False).encode("utf-8", "strict")
    if len(raw) > MAX_CHOICES:
        raise ValueError("private visual decision source exceeds offline limit")
    payload = base64.b64encode(raw).decode("ascii")
    script = JS.replace("__PAYLOAD__", json.dumps(payload))
    csp_css = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp_script = base64.b64encode(hashlib.sha256(script.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; style-src 'sha256-" + csp_css +
           "'; script-src 'sha256-" + csp_script +
           "'; base-uri 'none'; form-action 'none'; object-src 'none'")
    notice = (
        "INCUBATE · PLAN/LAB ONLY · DRAFT/HOLD. PRIVATE and UNENCRYPTED: "
        "this file contains original finding IDs/titles/severity and "
        "declared client/engagement/source hashes. Use a trusted offline device. "
        "The original five exported columns omit underlying evidence; an identical "
        "row does NOT establish evidence equality, real identity, current consent "
        "or a verified fix. Missing is NOT repaired. Choices refer to HUMAN notes "
        "and proposed dates only, never permission to scan, retest or remediate. "
        "No network, browser persistence, upload or automatic save is performed."
    )
    html = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        '<meta http-equiv="Content-Security-Policy" content="' + escape(csp, quote=True) + '">'
        "<title>LightUp PRIVATE HUMAN source revision editor</title>"
        "<style>" + CSS + "</style><header><h1>Original-source HUMAN revision choices</h1>"
        "<p class='sub'>Offline, per-finding review · manual decisions, never release authority</p>"
        "</header><main><aside class='warning'>" + escape(notice) + "</aside>"
        "<div class='summary' id='summary' aria-live='polite'></div>"
        "<div class='toolbar'><label for='search'>Find original finding</label>"
        "<input id='search' type='search' placeholder='ID, title or severity'>"
        "<label for='filter'>Source change</label><select id='filter'>"
        "<option value='all'>All original rows</option>"
        "<option value='five_column_identical'>Five-column identical</option>"
        "<option value='changed'>Changed source records</option>"
        "<option value='new'>New source records</option></select>"
        "<button type='button' id='clear'>Clear all decisions</button></div>"
        "<div id='rows'></div>"
        "<section class='summary'><label><input id='consent' type='checkbox'>"
        " I independently reviewed actual client/recipient, and approve saving "
        "the UNENCRYPTED original-identity decision JSON privately.</label>"
        "<p><button id='export' type='button'>Export PRIVATE decisions JSON</button></p>"
        "<p id='status' role='status' aria-live='polite'></p></section>"
        "<p>Use the existing strict <code>private_export_human_revision_choices apply</code>"
        " CLI with the saved original source inputs; no decisions in this browser"
        " ever update an original source, grant, assessment, or encrypted plan.</p>"
        "<script>" + script + "</script></main></html>"
    )
    return html.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Prepare source-bound PRIVATE offline visual HUMAN decision editor"
    )
    p.add_argument("earlier_source")
    p.add_argument("earlier_plan")
    p.add_argument("later_source")
    p.add_argument("--output", required=True, help="new unencrypted owner-private .html")
    p.add_argument("--ack-private-handling", action="store_true")
    p.add_argument("--ack-same-real-client", action="store_true")
    p.add_argument("--ack-plaintext-original-ids", action="store_true")
    a = p.parse_args(argv)
    try:
        if not (a.ack_private_handling and a.ack_same_real_client
                and a.ack_plaintext_original_ids):
            raise ValueError("privacy and independent client acknowledgment required")
        out = _output_path(a.output, ".html")
        old_meta, old_rows, notes, new_meta, new_rows = _read_inputs(
            a.earlier_source, a.earlier_plan, a.later_source
        )
        sheet = _make_choices(old_meta, old_rows, notes, new_meta, new_rows)
        _atomic_private_publish(out, _html(sheet))
        print("Created PRIVATE, UNENCRYPTED offline per-finding HUMAN decision editor.")
        print("Review and export JSON locally; original source and plans untouched.")
        print("HOLD: No authentic client identity, consent, unchanged evidence or fixes asserted.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN visual editor HOLD: original source or output refused.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
