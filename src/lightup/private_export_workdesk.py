"""Offline source-bound human evidence desk. PRIVATE, non-authorizing, no target calls."""
from __future__ import annotations

import argparse
import base64
from datetime import date
import hashlib
from html import escape
import json
from pathlib import Path
import re
import sys

from .private_export_handoff import _atomic_private_publish, _no_duplicate_keys, _output_path, _read_archive

KIND = "lightup.private_human_workplan"
STAGES = ("unassigned", "triaging", "waiting_on_owner", "awaiting_evidence", "ready_for_human_review", "blocked")
FIELDS = {"finding_id", "stage", "owner_alias", "due_date", "human_note"}
MAX_PLAN = 256 * 1024

CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;line-height:1.5;color:#14233a;background:#f5f7fb}
*{box-sizing:border-box}body{margin:0}header{background:#10253e;color:white;padding:25px 4vw}
h1{margin:0;font-size:clamp(24px,4vw,36px)}h2{font-size:20px}
main{max-width:1120px;margin:auto;padding:20px}.warning{border-left:5px solid #b87506;background:#fff3d7;padding:18px;margin-bottom:20px}
.bar{display:flex;flex-wrap:wrap;align-items:end;gap:12px;background:#fff;border:1px solid #cbd5e1;padding:15px;border-radius:10px;position:sticky;top:0}
.bar label{flex:1 1 170px}label{display:block;font-weight:650;font-size:14px}
label span{display:block;margin-bottom:5px}input,select,textarea{font:inherit;padding:9px;border:1px solid #acbdd0;border-radius:7px;color:#14233a;background:#fff}
label input,label select,label textarea{width:100%}button{padding:11px 15px;border:0;border-radius:8px;background:#1665bd;color:white;font:inherit;font-weight:700;cursor:pointer}
button:focus-visible,input:focus-visible,select:focus-visible,textarea:focus-visible{outline:3px solid #4488ee}
.finding{background:white;border:1px solid #d1dceb;border-left:6px solid #a7b1c1;border-radius:10px;padding:20px;margin:15px 0;break-inside:avoid}
.finding[data-severity=critical]{border-left-color:#b91c1c}.finding[data-severity=high]{border-left-color:#ea580c}.finding[data-severity=medium]{border-left-color:#cca40a}
.finding h3{display:flex;gap:12px;flex-wrap:wrap;justify-content:space-between;margin:0}.finding small{font-size:12px;text-transform:uppercase;color:#52677e}
.finding .source-id{font:13px ui-monospace,monospace;color:#536985;overflow-wrap:anywhere}
.remedy{background:#f4f7fb;padding:14px;white-space:pre-wrap;overflow-wrap:anywhere;border-radius:7px}
.controls{display:grid;grid-template-columns:1fr 1fr;gap:14px}.controls label:last-child{grid-column:1/-1}
#message{color:#7c4700;font-weight:700}
@media(max-width:680px){.controls{grid-template-columns:1fr}.bar{position:static}}
@media print{header{background:#fff;color:#14233a}.bar,button{display:none!important}}
"""

SCRIPT = """
"use strict";
const DATA=__PAYLOAD__;
const STAGES=["unassigned","triaging","waiting_on_owner","awaiting_evidence","ready_for_human_review","blocked"];
const id=x=>document.getElementById(x);
const draft=DATA.annotations;
const prio={critical:0,high:1,medium:2,low:3,info:4};
const E=(tag,content)=>{const node=document.createElement(tag);if(content!==undefined)node.textContent=content;return node;};
const fmt=text=>text.replaceAll("_"," ");
function labeled(parent,name,input){const lab=E("label");lab.append(E("span",name),input);parent.append(lab);}
function summary(){
 const counts={};
 for(const r of DATA.rows){const stage=draft[r.finding_id].stage;counts[stage]=(counts[stage]||0)+1;}
 id("summary").textContent=DATA.rows.length+" original findings · "+STAGES.map(s=>fmt(s)+": "+(counts[s]||0)).join(" · ");
}
function render(){
 const search=id("search").value.trim().toLowerCase(),sev=id("severity").value,stage=id("stage").value;
 const matches=DATA.rows.filter(r=>(!sev||r.severity===sev)&&(!stage||draft[r.finding_id].stage===stage)&&
  (!search||[r.finding_id,r.title,r.remediation,draft[r.finding_id].owner_alias,draft[r.finding_id].human_note]
   .some(s=>s.toLowerCase().includes(search))));
 const board=id("board");board.replaceChildren();
 for(const row of matches){
  const a=draft[row.finding_id],item=E("article");item.className="finding";item.dataset.severity=row.severity;
  const title=E("h3");title.append(E("span",row.title),E("small",row.severity.toUpperCase()+" · source "+fmt(row.retest_status)));
  item.append(title,E("p",row.finding_id),E("h4","Source-reported remediation"),E("p",row.remediation));
  item.children[1].className="source-id";item.children[3].className="remedy";
  const controls=E("div");controls.className="controls";
  const choice=E("select");
  STAGES.forEach(s=>{const opt=E("option",fmt(s));opt.value=s;choice.append(opt);});
  choice.value=a.stage;
  choice.addEventListener("change",()=>{a.stage=choice.value;summary();});
  labeled(controls,"HUMAN stage (never a fix verdict)",choice);
  const owner=E("input");owner.value=a.owner_alias;owner.maxLength=80;owner.placeholder="Human contact alias";
  owner.addEventListener("input",()=>{a.owner_alias=owner.value;});
  labeled(controls,"Unverified owner alias",owner);
  const due=E("input");due.type="date";due.value=a.due_date;
  due.addEventListener("change",()=>{a.due_date=due.value;});
  labeled(controls,"Proposed human follow-up date",due);
  const note=E("textarea");note.value=a.human_note;note.maxLength=900;note.rows=3;
  note.placeholder="Private HUMAN coordination only. Never paste credentials, raw evidence or secret keys.";
  note.addEventListener("input",()=>{a.human_note=note.value;});
  labeled(controls,"Private human note",note);
  item.append(controls);board.append(item);
 }
 id("shown").textContent=matches.length+" / "+DATA.rows.length+" original findings visible";summary();
}
function exportDraft(){
 const result={kind:"lightup.private_human_workplan",version:1,
  source_csv_sha256:DATA.source_csv_sha256,declared_client_id:DATA.declared_client_id,
  declared_engagement_id:DATA.declared_engagement_id,authorizes_action:false,
  certifies_remediation:false,confirms_client_identity:false,
  records:DATA.rows.map(r=>({...draft[r.finding_id]}))};
 const blob=new Blob([JSON.stringify(result,null,2)+"\\n"],{type:"application/json"});
 const url=URL.createObjectURL(blob),a=E("a");a.href=url;
 a.download="LightUp-PRIVATE-HUMAN-Workplan.json";document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),60000);
 id("message").textContent="PRIVATE unsigned workplan exported. Use trusted transport; no consent, remediation or retest is verified.";
}
DATA.rows.sort((a,b)=>prio[a.severity]-prio[b.severity]||a.finding_id.localeCompare(b.finding_id));
id("search").addEventListener("input",render);
id("severity").addEventListener("change",render);
id("stage").addEventListener("change",render);
id("clear").addEventListener("click",()=>{id("search").value="";id("severity").value="";id("stage").value="";render();});
id("export").addEventListener("click",exportDraft);
render();
"""


def _load_resume(filename: str, manifest: dict, rows: list[dict[str, str]]) -> dict:
    file = Path(filename)
    if not file.is_file() or file.stat().st_size > MAX_PLAN:
        raise ValueError("oversized or absent private workplan")
    try:
        draft = json.loads(file.read_text(encoding="utf-8"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid private workplan") from exc
    required = {"kind", "version", "source_csv_sha256", "declared_client_id",
                "declared_engagement_id", "authorizes_action", "certifies_remediation",
                "confirms_client_identity", "records"}
    if type(draft) is not dict or set(draft) != required:
        raise ValueError("invalid human workplan fields")
    if draft["kind"] != KIND or type(draft["version"]) is not int or draft["version"] != 1:
        raise ValueError("unknown human workplan")
    if any(draft[k] is not False for k in
           ("authorizes_action", "certifies_remediation", "confirms_client_identity")):
        raise ValueError("authority claim is prohibited")
    if any(draft[k] != manifest[k] for k in
           ("source_csv_sha256", "declared_client_id", "declared_engagement_id")):
        raise ValueError("workplan is not bound to exactly this original source")
    entries = draft["records"]
    if type(entries) is not list or len(entries) != len(rows):
        raise ValueError("incomplete source membership")
    expected = {r["finding_id"] for r in rows}
    result: dict[str, dict] = {}
    for item in entries:
        if type(item) is not dict or set(item) != FIELDS:
            raise ValueError("malformed human annotation")
        fid = item["finding_id"]
        if type(fid) is not str or fid not in expected or fid in result:
            raise ValueError("duplicate or unknown original finding")
        if type(item["stage"]) is not str or item["stage"] not in STAGES:
            raise ValueError("invalid human review stage")
        owner, due, note = item["owner_alias"], item["due_date"], item["human_note"]
        if type(owner) is not str or len(owner) > 80 or any(ord(c) < 32 for c in owner):
            raise ValueError("invalid human contact alias")
        if type(note) is not str or len(note) > 900 or any(
                ord(c) < 32 and c not in "\n\t" for c in note):
            raise ValueError("invalid human review note")
        if type(due) is not str or (due and (
                not re.fullmatch(r"\d{4}-\d{2}-\d{2}", due) or
                date.fromisoformat(due).isoformat() != due)):
            raise ValueError("invalid human follow-up date")
        result[fid] = item
    if set(result) != expected:
        raise ValueError("missing original finding in human workplan")
    return result


def _render(manifest: dict, rows: list[dict[str, str]], annotations: dict) -> bytes:
    payload = {
        "source_csv_sha256": manifest["source_csv_sha256"],
        "declared_client_id": manifest["declared_client_id"],
        "declared_engagement_id": manifest["declared_engagement_id"],
        "rows": rows,
        "annotations": annotations,
    }
    # Escaped JSON expression, not markup: hostile source text cannot end SCRIPT.
    data = json.dumps(payload, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
    data = data.replace("<", r"\u003c").replace(">", r"\u003e").replace("&", r"\u0026")
    js = SCRIPT.replace("__PAYLOAD__", data)
    css_hash = base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    js_hash = base64.b64encode(hashlib.sha256(js.encode("utf-8")).digest()).decode("ascii")
    csp = ("default-src 'none'; script-src 'sha256-" + js_hash + "'; style-src 'sha256-" +
           css_hash + "'; connect-src 'none'; object-src 'none'; img-src 'none'; "
           "frame-src 'none'; form-action 'none'; base-uri 'none'")
    document = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="' + escape(csp, quote=True) + '">'
        '<title>LightUp PRIVATE HUMAN Workdesk</title><style>' + CSS + '</style></head><body>'
        '<header><h1>LightUp · PRIVATE HUMAN Evidence Workdesk</h1>'
        '<p>Locally rendered from a previously authorized original finding export. '
        'No network calls, browser storage or server.</p></header><main>'
        '<section class="warning"><strong>HUMAN HOLD · NOT AN AUTHORIZATION.</strong> '
        'Source severity, retest status and remediation text are unverified claims. '
        'Human coordination stages, aliases, notes and dates are not authorization, '
        'proof of client identity, security retest, evidence authenticity or verified fixes. '
        'This original data is private and unencrypted: verify recipients and transport.</section>'
        '<section class="bar" aria-label="Source filtering">'
        '<label><span>Search source findings / human notes</span><input id="search" type="search"></label>'
        '<label><span>Severity</span><select id="severity"><option value="">All</option>' +
        "".join('<option value="' + n + '">' + n.title() + '</option>'
                for n in ("critical", "high", "medium", "low", "info")) +
        '</select></label><label><span>Human stage</span><select id="stage">'
        '<option value="">All</option>' +
        "".join('<option value="' + n + '">' + n.replace("_", " ").title() + '</option>'
                for n in STAGES) +
        '</select></label><button id="clear" type="button">Clear filters</button>'
        '<button id="export" type="button">Export PRIVATE HUMAN JSON</button></section>'
        '<p id="shown" role="status"></p><p id="summary" aria-live="polite"></p>'
        '<p>Original source SHA-256 prefix: <code>' + escape(manifest["source_csv_sha256"][:16]) + '</code></p>'
        '<p id="message" role="status"></p>'
        '<section id="board" aria-label="Original findings and human follow-up"></section>'
        '<p>To resume, use the original unchanged ZIP with the exported PRIVATE JSON '
        'and the --resume option. Invalid/changed source or missing IDs are rejected. '
        'No annotations are automatically migrated to other source versions.</p></main>'
        '<script>' + js + '</script></body></html>'
    )
    return document.encode("utf-8")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Private source-bound HUMAN evidence coordination only")
    parser.add_argument("archive", help="original authenticated export ZIP")
    parser.add_argument("--output", required=True, help="new private .html, never overwritten")
    parser.add_argument("--resume", help="optional original-source human JSON export")
    parser.add_argument("--ack-private-plaintext", action="store_true")
    parser.add_argument("--ack-original-identifiers", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_plaintext or not args.ack_original_identifiers:
            raise ValueError("must acknowledge original private data")
        destination = _output_path(args.output, ".html")
        manifest, rows = _read_archive(args.archive)
        draft = _load_resume(args.resume, manifest, rows) if args.resume else {
            r["finding_id"]: {"finding_id": r["finding_id"], "stage": "unassigned",
                              "owner_alias": "", "due_date": "", "human_note": ""}
            for r in rows
        }
        _atomic_private_publish(destination, _render(manifest, rows, draft))
        print("Created local PRIVATE HUMAN workdesk. No grants, retest or fixes verified.")
        return 0
    except (ValueError, OSError, UnicodeError):
        print("Private HUMAN workdesk HOLD: invalid source, annotation, or output.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
