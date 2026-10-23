#!/usr/bin/env python3
"""Original-bound offline HUMAN selected-discussion action planner.

Explicit manual follow-up proposals on an already privately received HUMAN
selected discussion; never grants authorization, identity or privacy clearance.
No original source, model, network, scanning, delivery or background actions.
"""
from __future__ import annotations

from private_csv_formula import unsafe_private_csv_note

import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import tempfile

from notes import Hold, file_new, private_directory, private_input, save_json
from privacy_triage import FALSE_FLAGS
from privacy_triage_selected_discussion import admit, reopen

SCHEMA = "lightup.private_notes_human_discussion_actions.v1"
FIELDS = ("original_ordinal", "human_next_step", "private_human_question")
STEPS = ("PENDING", "DISCUSS", "REQUEST_OWNER_CONTEXT", "WITHHOLD")
MAX_QUESTION = 180


def rows_csv(rows: list[dict]) -> bytes:
    out = io.StringIO(newline="")
    writer = csv.writer(out, lineterminator="\r\n", quoting=csv.QUOTE_ALL)
    # Same literal unquoted header as the original reviewer Studio.
    out.write(",".join(FIELDS) + "\r\n")
    for row in rows:
        writer.writerow([row[name] for name in FIELDS])
    return out.getvalue().encode("utf-8")


def blank_rows(selected) -> list[dict]:
    return [
        {"original_ordinal": str(ordinal),
         "human_next_step": "PENDING",
         "private_human_question": ""}
        for ordinal, _ in selected
    ]


def read_actions(raw: bytes, selected) -> list[dict]:
    if not raw or len(raw) > 65536 or b"\x00" in raw:
        raise Hold("HOLD: missing or oversized selected HUMAN action CSV")
    try:
        value = raw.decode("utf-8", "strict")
        if value.startswith("\ufeff") or not value.endswith("\r\n"):
            raise ValueError("format")
        reader = csv.reader(io.StringIO(value, newline=""), strict=True)
        lines = list(reader)
        if not lines or lines[0] != list(FIELDS) or len(lines)-1 != len(selected):
            raise ValueError("row count or header")
        parsed = []
        for line, (ordinal, _) in zip(lines[1:], selected):
            if len(line) != 3 or line[0] != str(ordinal) or line[1] not in STEPS:
                raise ValueError("original-bound position or HUMAN stage")
            question = line[2]
            if (len(question) > MAX_QUESTION or
                    any(ord(char) < 32 or ord(char) == 127 for char in question) or
                    question.lstrip().startswith(("=", "+", "-", "@")) or
                    unsafe_private_csv_note(question, MAX_QUESTION)):
                raise ValueError("unsafe private HUMAN question")
            parsed.append({
                "original_ordinal": str(ordinal),
                "human_next_step": line[1],
                "private_human_question": question,
            })
        if raw != rows_csv(parsed):
            raise ValueError("noncanonical local HUMAN action export")
        return parsed
    except (UnicodeError, ValueError, csv.Error):
        raise Hold("HOLD: noncanonical or changed source-bound HUMAN action CSV") from None


def studio(selected) -> bytes:
    ordinals = [n for n, _ in selected]
    # Original selected-only flags, NOT original notes, targets, identities or
    # source SHA values. Retain full selected roster in every exported CSV.
    signals = {str(n): list(flags) for n, flags in selected}
    javascript = """'use strict';
const attention = """ + json.dumps(signals, separators=(",", ":")) + """;
const ordinals = """ + json.dumps(ordinals, separators=(",", ":")) + """;
const stages=['PENDING','DISCUSS','REQUEST_OWNER_CONTEXT','WITHHOLD'];
const list=document.getElementById('list');
const attentionLabels=[
 'HUMAN stage disagreement','HUMAN category disagreement',
 'PRIVATE note-text disagreement (withheld)','At least one HUMAN WITHHOLD',
 'At least one HUMAN REVIEW_REQUIRED'
];
const filters={ALL:()=>true,DIFFERENCES:v=>v.slice(0,3).some(Boolean),
 WITHHOLD:v=>v[3],REVIEW_REQUIRED:v=>v[4],AGREED:v=>!v.some(Boolean)};
const cards=new Map();
const filter=document.getElementById('focus');
function updateVisibility(){
 let visible=0;
 for(const ordinal of ordinals){
   const show=filters[filter.value](attention[String(ordinal)]);
   cards.get(ordinal).hidden=!show;
   if(show)visible++;
 }
 document.getElementById('summary').textContent=visible+' of '+ordinals.length+
  ' selected originals shown. Filters never remove selected originals from the complete HUMAN CSV.';
}
filter.addEventListener('change',updateVisibility);

const current=new Map();
for(const ordinal of ordinals){
 const box=document.createElement('section');
 const title=document.createElement('h2');
 title.textContent='Selected original #'+ordinal; box.append(title);
 const flags=attention[String(ordinal)];
 const badges=document.createElement('p');
 const reasons=attentionLabels.filter((_,i)=>flags[i]);
 badges.textContent=reasons.length ? reasons.join(' · ') :
   'Literally matching HUMAN labels/notes — NOT a privacy pass.';
 box.append(badges);
 cards.set(ordinal,box);
 const label=document.createElement('label');
 label.textContent='Next HUMAN action ';
 const select=document.createElement('select');
 select.setAttribute('aria-label','HUMAN action for original '+ordinal);
 for(const stage of stages){
   const option=document.createElement('option');
   option.value=stage; option.textContent=stage.replaceAll('_',' ');
   select.append(option);
 }
 label.append(select);box.append(label);
 const questionLabel=document.createElement('label');
 questionLabel.textContent=' PRIVATE human-only question (max 180; no secrets) ';
 const question=document.createElement('input');
 question.type='text';question.maxLength=180;
 question.setAttribute('aria-label','Private question for original '+ordinal);
 questionLabel.append(question);box.append(questionLabel);
 current.set(ordinal,{select,question});list.append(box);
}
updateVisibility();
const bad=s=>s.length>180 || /^[\\s]*[=+@-]/.test(s) || /[\\x00-\\x1f\\x7f]/.test(s);

const resume=document.getElementById('resume');
resume.addEventListener('change',async()=>{
 const file=resume.files&&resume.files[0];
 resume.value='';
 if(!file)return;
 try{
  if(file.size===0||file.size>65536)throw Error('HOLD: oversized PRIVATE draft');
  const bytes=await file.arrayBuffer();
  const value=new TextDecoder('utf-8',{fatal:true}).decode(bytes);
  const lines=value.split('\\r\\n');
  if(lines.shift()!=='original_ordinal,human_next_step,private_human_question' ||
     lines.pop()!=='' || lines.length!==ordinals.length)throw Error('HOLD: draft membership');
  const updated=[];
  const cell=s=>'"'+String(s).replaceAll('"','""')+'"';
  for(let i=0;i<lines.length;i++){
   const match=/^"([0-9]+)","(PENDING|DISCUSS|REQUEST_OWNER_CONTEXT|WITHHOLD)","((?:[^"]|"")*)"$/.exec(lines[i]);
   if(!match||match[1]!==String(ordinals[i]))throw Error('HOLD: source or HUMAN stage mismatch');
   const question=match[3].replaceAll('""','"');
   if(bad(question)||question.length>180 ||
      [match[1],match[2],question].map(cell).join(',')!==lines[i])
     throw Error('HOLD: invalid or noncanonical PRIVATE question');
   updated.push({stage:match[2],question});
  }
  if(!window.confirm('Restore ALL original-bound PRIVATE HUMAN draft actions? Current unsaved choices will be replaced. No authorization is granted.'))return;
  updated.forEach((next,i)=>{
    const record=current.get(ordinals[i]);
    record.select.value=next.stage;record.question.value=next.question;
  });
  document.getElementById('message').textContent='Restored COMPLETE local selected-original HUMAN draft. Native finalization remains required; HOLD.';
 }catch(_){
  document.getElementById('message').textContent='HOLD: invalid or changed local original-bound HUMAN draft. Current choices were NOT changed.';
 }
});

document.getElementById('export').addEventListener('click',()=>{
 const lines=['original_ordinal,human_next_step,private_human_question'];
 for(const ordinal of ordinals){
   const entry=current.get(ordinal);
   const q=entry.question.value;
   if(bad(q) || !stages.includes(entry.select.value)){
     document.getElementById('message').textContent='HOLD: invalid PRIVATE question; no export.';
     return;
   }
   const cell=s=>'"'+String(s).replaceAll('"','""')+'"';
   lines.push([ordinal,entry.select.value,q].map(cell).join(','));
 }
 if(!window.confirm('Export COMPLETE PRIVATE HUMAN actions for all selected originals? No recipient or privacy clearance.'))return;
 const blob=new Blob([lines.join('\\r\\n')+'\\r\\n'],{type:'text/csv;charset=utf-8'});
 const url=URL.createObjectURL(blob);
 const a=document.createElement('a');a.href=url;
 a.download='PRIVATE-HUMAN-discussion-actions-completed.csv';
 document.body.append(a);a.click();a.remove();
 setTimeout(()=>URL.revokeObjectURL(url),15000);
 document.getElementById('message').textContent='PRIVATE local download only. Store as 0600, then invoke native sensitivity-discussion-actions-finalize. Still HOLD.';
});
"""
    import base64
    pin = base64.b64encode(sha256(javascript.encode("utf-8")).digest()).decode("ascii")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'sha256-""" +
            pin + """';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN selected discussion actions</title>
<style>body{max-width:900px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{background:#fff0e8;border-left:5px solid #ac4a28;padding:1rem}
section{border:1px solid #becbd5;border-radius:10px;margin:12px 0;padding:14px}
label{display:block;margin:.5rem 0}input{width:90%;max-width:600px}
button{padding:12px;margin:10px 0}button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #b66c24}</style>
<h1>PRIVATE · original HUMAN next-step planner</h1>
<aside><b>HOLD · offline HUMAN discussion only.</b> All original source
positions below were manually selected in the original offline reviewer Studio.
No reviewer identity, consent, privacy clearance, source verification, fix,
release, risk verdict, recipient authentication, scan or grant is implied.
Questions can remain confidential: export owner-private only.</aside>
<p>Every selected original must be retained. New choices start PENDING, not
from a reviewer verdict. Nothing is saved automatically or sent externally.</p>
<label>Show attention subset <select id="focus">
<option value="ALL">All selected originals</option>
<option value="DIFFERENCES">Human disagreements</option>
<option value="WITHHOLD">Declared WITHHOLD</option>
<option value="REVIEW_REQUIRED">Declared REVIEW_REQUIRED</option>
<option value="AGREED">No literal disagreement</option>
</select></label>
<p id="summary" role="status" aria-live="polite"></p>
<main id="list"></main>
<label>Restore previous complete local PRIVATE HUMAN action CSV
<input id="resume" type="file" accept=".csv,text/csv"></label>
<button id="export" type="button">Export COMPLETE PRIVATE HUMAN next-step CSV</button>
<p id="message" role="status" aria-live="polite">Native exact-original finalization is separately required.</p>
<script>""" + javascript + """</script></html>""").encode("utf-8")


def receipt(sources, manifest, decisions, packets, selected_raw, selected) -> dict:
    return {
        "schema": SCHEMA,
        "claimed_status": "HOLD",
        "original_count": len(sources),
        "selected_original_ordinals": [ordinal for ordinal, _ in selected],
        "original_manifest_sha256_unsigned": manifest,
        "original_human_csv_sha256_unsigned": decisions,
        "received_selected_csv_sha256_unsigned": sha256(selected_raw).hexdigest(),
        "manual_review_csv_sha256_unsigned": [
            packet["csv_sha256_unsigned"] for packet in packets],
        "human_only": True,
        **{flag: False for flag in FALSE_FLAGS},
    }


def admit_room(original: str, reviews: list[str], received_room: str):
    room = private_directory(received_room)
    # Independent exact admission of original source + source-owning HUMAN
    # receipt and all HUMAN reviews; refuses changed derived HTML or receipt.
    reopen(original, reviews, str(room))
    sources, manifest, decisions, packets, selected_raw, selected = admit(
        original, reviews, str(room / "PRIVATE-HUMAN-selected-discussion.csv"))
    return sources, manifest, decisions, packets, selected_raw, selected


def plan(original: str, reviews: list[str], received_room: str, parent_name: str) -> int:
    sources, manifest, decisions, packets, selected_raw, selected = admit_room(
        original, reviews, received_room)
    parent = private_directory(parent_name)
    workroom = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-action-draft-", dir=parent))
    os.chmod(workroom, 0o700)
    finished = False
    try:
        save_json(workroom / "PRIVATE-HUMAN-action-source.json",
                  receipt(sources, manifest, decisions, packets, selected_raw, selected))
        file_new(workroom / "PRIVATE-HUMAN-action-template.csv",
                 rows_csv(blank_rows(selected)))
        file_new(workroom / "PRIVATE-HUMAN-action-editor.html", studio(selected))
        finished = True
        print("REVIEW_ONLY: PRIVATE original-bound HUMAN next-step draft prepared")
        print("OPEN LOCALLY: " + str(workroom / "PRIVATE-HUMAN-action-editor.html"))
        return 2
    finally:
        if not finished:
            shutil.rmtree(workroom)


def action_page(rows: list[dict]) -> bytes:
    """Scriptless source-minimal HUMAN meeting view: no actual question contents."""
    pieces = []
    for row in rows:
        pieces.append("<li>Original #" + row["original_ordinal"] +
                      " — next HUMAN step: <b>" +
                      html.escape(row["human_next_step"]) +
                      "</b>. PRIVATE question: " +
                      ("present; text withheld" if row["private_human_question"]
                       else "none") + "</li>")
    page = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';base-uri 'none';form-action 'none'">
<title>PRIVATE HUMAN next-step meeting</title>
<style>body{max-width:850px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{border-left:5px solid #a94325;background:#fff0e8;padding:14px}li{padding:8px}</style>
<h1>PRIVATE · manually selected HUMAN next actions</h1>
<aside><b>HOLD / HUMAN ONLY.</b> These are local human proposals,
not an authenticated reviewer, owner obligation, privacy clearance, fixed
finding, client approval, consent, grant, recipient or release authority.</aside>
<p>Selected original positions: """ + str(len(rows)) + """.
No original note content, masked note, HUMAN question text, source filename,
original SHA or target is exposed in this printable agenda. The separately
stored private CSV may contain HUMAN question text.</p><ol>""" +
            "".join(pieces) + """</ol><p>Original full source-bound HUMAN
review and all existing release gates remain separate and mandatory.
No background dispatch, messaging, network, model or assessment.</p></html>""")
    return page.encode("utf-8")


def close(original: str, reviews: list[str], received_room: str,
          draft_room: str, completed_csv: str, parent_name: str) -> int:
    sources, manifest, decisions, packets, selected_raw, selected = admit_room(
        original, reviews, received_room)
    draft = private_directory(draft_room)
    template = rows_csv(blank_rows(selected))
    if private_input(str(draft / "PRIVATE-HUMAN-action-template.csv"), 65536) != template:
        raise Hold("HOLD: original-bound blank HUMAN action template was edited")
    if private_input(str(draft / "PRIVATE-HUMAN-action-editor.html"), 65536) != studio(selected):
        raise Hold("HOLD: original-bound offline HUMAN action Studio changed")
    binding = receipt(sources, manifest, decisions, packets, selected_raw, selected)
    exact_binding = (json.dumps(binding, indent=2, sort_keys=True,
                                ensure_ascii=False) + "\n").encode("utf-8")
    if private_input(str(draft / "PRIVATE-HUMAN-action-source.json"), 65536) != exact_binding:
        raise Hold("HOLD: original HUMAN action-draft receipt changed")
    selected_actions = private_input(completed_csv, 65536)
    rows = read_actions(selected_actions, selected)
    parent = private_directory(parent_name)
    out = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-action-final-", dir=parent))
    os.chmod(out, 0o700)
    finished = False
    try:
        counts = {step: sum(row["human_next_step"] == step for row in rows) for step in STEPS}
        save_json(out / "PRIVATE-HUMAN-action-receipt.json", {
            **binding,
            "completed_human_actions_sha256_unsigned": sha256(selected_actions).hexdigest(),
            "human_next_step_counts": counts,
            "not_authorized_or_verified": True,
        })
        file_new(out / "PRIVATE-HUMAN-actions.csv", selected_actions)
        file_new(out / "PRIVATE-HUMAN-actions.html", action_page(rows))
        finished = True
        print("HOLD: PRIVATE HUMAN selected next-step record written; NO permission")
        print("OPEN LOCALLY: " + str(out / "PRIVATE-HUMAN-actions.html"))
        return 3
    finally:
        if not finished:
            shutil.rmtree(out)



def reopen_actions(original: str, reviews: list[str], received_room: str,
                   final_room: str) -> int:
    """Read-only re-admission of final PRIVATE HUMAN action packet."""
    sources, manifest, decisions, packets, selected_raw, selected = admit_room(
        original, reviews, received_room)
    final = private_directory(final_room)
    actions_raw = private_input(str(final / "PRIVATE-HUMAN-actions.csv"), 65536)
    rows = read_actions(actions_raw, selected)
    counts = {step: sum(row["human_next_step"] == step for row in rows)
              for step in STEPS}
    expected = {
        **receipt(sources, manifest, decisions, packets, selected_raw, selected),
        "completed_human_actions_sha256_unsigned": sha256(actions_raw).hexdigest(),
        "human_next_step_counts": counts,
        "not_authorized_or_verified": True,
    }
    exact_receipt = (json.dumps(expected, indent=2, sort_keys=True,
                                ensure_ascii=False) + "\n").encode("utf-8")
    if (private_input(str(final / "PRIVATE-HUMAN-action-receipt.json"), 65536)
            != exact_receipt):
        raise Hold("HOLD: completed original HUMAN action receipt changed")
    if (private_input(str(final / "PRIVATE-HUMAN-actions.html"), 65536)
            != action_page(rows)):
        raise Hold("HOLD: completed private HUMAN action agenda changed")
    print("HOLD: original-bound PRIVATE HUMAN action packet reopened; NO privacy clearance")
    print("OPEN LOCALLY: " + str(final / "PRIVATE-HUMAN-actions.html"))
    return 3
