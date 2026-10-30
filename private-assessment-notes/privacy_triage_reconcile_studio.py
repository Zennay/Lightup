#!/usr/bin/env python3
"""Portable HUMAN-only reviewer comparison and explicit next-review proposal editor.

Embeds only original ordinal/SHA, human labels, and note-presence flags.
No original or masked note text, prior HUMAN notes or reviewer identity claims.
"""
from __future__ import annotations

from base64 import b64encode
from hashlib import sha256
import html
import json


def render(sources: list[dict], packets: list[dict]) -> bytes:
    if not (1 <= len(sources) <= 12 and 2 <= len(packets) <= 8):
        raise ValueError("unsupported original HUMAN review source roster")
    data = []
    for ordinal, source in enumerate(sources, start=1):
        reviewers = []
        for index, packet in enumerate(packets, start=1):
            row = packet["rows"][ordinal-1]
            reviewers.append({
                "slot": index,
                "stage": row["review_status"],
                "topics": row["privacy_topics"].split("|"),
                "notePresent": bool(row["human_followup"]),
            })
        # Original HUMAN free-text notes remain Python-side only. A single
        # Boolean reveals disagreement without embedding any note contents,
        # hashes of guessable note strings, source filenames or identities.
        note_disagreement = len({
            packet["rows"][ordinal - 1]["human_followup"]
            for packet in packets
        }) > 1
        data.append({
            "ordinal": ordinal,
            "sha": source["source_sha256_unsigned"],
            "reviewers": reviewers,
            "noteDisagreement": note_disagreement,
        })
    encoded = json.dumps(data, ensure_ascii=True, separators=(",", ":")).replace("<", r"\u003c")
    identical_pairs = [
        [i + 1, j + 1]
        for i in range(len(packets))
        for j in range(i + 1, len(packets))
        if packets[i]["csv_sha256_unsigned"] == packets[j]["csv_sha256_unsigned"]
    ]
    pairs_json = json.dumps(identical_pairs, separators=(",", ":"))
    javascript = r"""'use strict';
const originals = """ + encoded + r""";
const exactSameHumanCSVSlots = """ + pairs_json + r""";
const STAGES=['PENDING','REVIEW_REQUIRED','WITHHOLD'];
const TOPICS=['CREDENTIALS','PERSONAL_DATA','CLIENT_DATA','OTHER','UNKNOWN'];
const list=document.getElementById('sources');
const message=document.getElementById('message');
const status=document.getElementById('count');
const find=document.getElementById('find');
const focus=document.getElementById('focus');
const proposal=new Map();
const csvCell = value => '"' + String(value).replaceAll('"','""') + '"';
function conflict(record) {
  return new Set(record.reviewers.map(x=>x.stage)).size>1 ||
    new Set(record.reviewers.map(x=>x.topics.join('|'))).size>1 ||
    record.noteDisagreement;
}
function make(tag, text, cls) {
  const el=document.createElement(tag);
  if(text!==undefined)el.textContent=text;
  if(cls)el.className=cls;
  return el;
}
function visibleRecord(record) {
  const filter=focus.value;
  const dispute=conflict(record);
  const declaredWithhold=record.reviewers.some(x=>x.stage==='WITHHOLD');
  const declaredReview=record.reviewers.some(x=>x.stage==='REVIEW_REQUIRED');
  const relevant=filter==='ALL' ||
    (filter==='DISAGREEMENT' && dispute) ||
    (filter==='NOTE_DISAGREEMENT' && record.noteDisagreement) ||
    (filter==='WITHHOLD' && declaredWithhold) ||
    (filter==='REVIEW_REQUIRED' && declaredReview) ||
    (filter==='AGREED' && !dispute);
  return relevant && (!find.value.trim() ||
    String(record.ordinal).includes(find.value.trim()));
}
function sync() {
  let shown=0, disputes=0, noteDisputes=0, withhold=0;
  for(const record of originals) {
    const value=proposal.get(record.ordinal);
    const dispute=conflict(record);
    const declaredWithhold=record.reviewers.some(x=>x.stage==='WITHHOLD');
    if(dispute)disputes++;
    if(record.noteDisagreement)noteDisputes++;
    if(declaredWithhold)withhold++;
    const visible=visibleRecord(record);
    value.card.hidden=!visible;
    if(visible)shown++;
  }
  status.textContent=shown+' of '+originals.length+' original positions shown · '+
    disputes+' HUMAN disagreements (including '+noteDisputes+
    ' PRIVATE note-only/content disagreement positions) · '+
    withhold+' positions with at least one declared WITHHOLD.'+
    (exactSameHumanCSVSlots.length ? ' '+exactSameHumanCSVSlots.length+
    ' slot pairs have byte-identical HUMAN decisions; this is NOT independent reviewer authentication.' : '')+
    ' Filtering does not alter the complete original-bound HUMAN export.';
}
for(const record of originals) {
  const card=make('section',undefined,'source');
  const title=make('h2','Original source #'+record.ordinal);
  card.append(title);
  const table=make('table');
  const head=make('thead');
  const header=make('tr');
  for(const label of ['HUMAN reviewer slot','Declared HUMAN stage','Possible categories','HUMAN note'])
    header.append(make('th',label));
  head.append(header);table.append(head);
  const body=make('tbody');
  for(const review of record.reviewers) {
    const row=make('tr');
    row.append(make('th','#'+review.slot));
    row.append(make('td',review.stage.replaceAll('_',' ')));
    row.append(make('td',review.topics.join(' · ')));
    row.append(make('td',review.notePresent?'Present; text withheld':'Blank'));
    body.append(row);
  }
  table.append(body);card.append(table);
  const disputed=conflict(record);
  const reasons=[];
  if(new Set(record.reviewers.map(x=>x.stage)).size>1) reasons.push('declared stages');
  if(new Set(record.reviewers.map(x=>x.topics.join('|'))).size>1) reasons.push('categories');
  if(record.noteDisagreement) reasons.push('PRIVATE follow-up note content (withheld)');
  if(record.reviewers.some(x=>x.stage==='WITHHOLD'))
    reasons.push('at least one declared WITHHOLD concern');
  const summary=make('p',reasons.length ?
    'Original HUMAN discussion: '+reasons.join(' · ')+'. No automatic consensus or privacy clearance.' :
    'Literal HUMAN stage/category/PRIVATE note choices align; this is NOT a privacy PASS.',
    reasons.length?'warn':'neutral');
  card.append(summary);
  const controls=make('div',undefined,'controls');
  const stageLabel=make('label','Your NEXT independent HUMAN stage');
  const stage=make('select');
  for(const choice of STAGES) {
    const opt=make('option',choice.replaceAll('_',' '));
    opt.value=choice;stage.append(opt);
  }
  stage.setAttribute('aria-label','Next HUMAN stage for original '+record.ordinal);
  stageLabel.append(stage);controls.append(stageLabel);
  const topicGroup=make('fieldset');
  topicGroup.append(make('legend','Next independently selected concern categories'));
  const checks=new Map();
  for(const item of TOPICS) {
    const label=make('label');
    const box=make('input');
    box.type='checkbox';box.checked=item==='UNKNOWN';
    label.append(box,document.createTextNode(item.replaceAll('_',' ')));
    topicGroup.append(label);
    checks.set(item,box);
    box.addEventListener('change',()=>{
      if(box.checked&&item==='UNKNOWN') {
        for(const [name,c] of checks) if(name!=='UNKNOWN')c.checked=false;
      }else if(box.checked)checks.get('UNKNOWN').checked=false;
      if(![...checks.values()].some(c=>c.checked))checks.get('UNKNOWN').checked=true;
    });
  }
  controls.append(topicGroup);
  const noteLabel=make('label','PRIVATE next HUMAN follow-up (max 300, no secret content)');
  const note=make('textarea');note.maxLength=300;note.rows=2;
  note.setAttribute('aria-label','PRIVATE follow-up for source '+record.ordinal);
  noteLabel.append(note);controls.append(noteLabel);
  const adopt=make('div',undefined,'explicit');
  adopt.append(make('p','Optional: prefill stage/categories from one declared reviewer; HUMAN confirmation required, NEVER automatically approved.'));
  for(const review of record.reviewers) {
    const button=make('button','Copy HUMAN proposal #'+review.slot+' (no notes)');
    button.type='button';
    button.addEventListener('click',()=>{
      if(!window.confirm('Copy only this HUMAN stage/categories to your editable next review? This is NOT identity, privacy clearance or approval.'))return;
      stage.value=review.stage;
      for(const [name,box] of checks)box.checked=review.topics.includes(name);
      note.value='';
      message.textContent='Copied a HUMAN-only proposal for original #'+record.ordinal+
        '. All other source positions and prior PRIVATE notes remain untouched.';
    });
    adopt.append(button);
  }
  controls.append(adopt);
  card.append(controls);
  proposal.set(record.ordinal,{stage,checks,note,card});
  list.append(card);
}
function unsafe(value) {
  return value.length>300 || /^[\s]*[=+@-]/.test(value) ||
    /[\x00-\x1f\x7f]/.test(value);
}
document.getElementById('exportFocus').addEventListener('click',()=>{
  const selected=originals.filter(visibleRecord);
  if(!selected.length){
    message.textContent='No HUMAN positions match the current local filters; nothing was exported.';
    return;
  }
  // Deliberate source-minimal PRIVATE export, never a substitute for the
  // COMPLETE original-bound next HUMAN decisions CSV or native finalizer.
  const lines=[
    'original_ordinal,human_stage_disagreement,human_topic_disagreement,private_note_disagreement,at_least_one_human_withhold,at_least_one_human_review_required'
  ];
  for(const record of selected){
    const values=[
      record.ordinal,
      new Set(record.reviewers.map(x=>x.stage)).size>1,
      new Set(record.reviewers.map(x=>x.topics.join('|'))).size>1,
      record.noteDisagreement,
      record.reviewers.some(x=>x.stage==='WITHHOLD'),
      record.reviewers.some(x=>x.stage==='REVIEW_REQUIRED')
    ];
    lines.push(values.map(x=>csvCell(typeof x==='boolean' ?
      (x?'TRUE':'FALSE'):x)).join(','));
  }
  const data=lines.join('\r\n')+'\r\n';
  const url=URL.createObjectURL(new Blob([data],
                   {type:'text/csv;charset=utf-8'}));
  const a=make('a');a.href=url;
  a.download='PRIVATE-HUMAN-selected-discussion.csv';
  document.body.append(a);a.click();a.remove();
  setTimeout(()=>URL.revokeObjectURL(url),15000);
  message.textContent='Downloaded '+selected.length+
    ' selected PRIVATE HUMAN ordinal-only discussion rows. No source SHA, raw notes or private free-text contents. Keep locally private and do not use as a finalized HUMAN review.';
});
document.getElementById('export').addEventListener('click',()=>{
  try {
    const lines=['source_ordinal,source_sha256_unsigned,review_status,privacy_topics,human_followup'];
    for(const original of originals) {
      const p=proposal.get(original.ordinal);
      const categories=TOPICS.filter(name=>p.checks.get(name).checked);
      if(!categories.length ||
         (categories.includes('UNKNOWN')&&categories.length!==1) ||
         unsafe(p.note.value))
        throw Error('invalid private HUMAN category or note');
      lines.push([original.ordinal,original.sha,p.stage.value,
        categories.join('|'),p.note.value].map(csvCell).join(','));
    }
    const payload=lines.join('\r\n')+'\r\n';
    const url=URL.createObjectURL(new Blob([payload],
                    {type:'text/csv;charset=utf-8'}));
    const a=make('a');a.href=url;a.download='PRIVATE-HUMAN-sensitivity-completed.csv';
    document.body.append(a);a.click();a.remove();
    setTimeout(()=>URL.revokeObjectURL(url),15000);
    message.textContent='Downloaded full PRIVATE HUMAN draft. Move into mode 0600 owner-private directory. Native sensitivity-finalize is still required; no clearance.';
  }catch(_){
    message.textContent='HOLD: unsupported PRIVATE note or category. No data exported.';
  }
});
const reopen = document.getElementById('reopen');
reopen.addEventListener('change',async()=>{
  const file=reopen.files && reopen.files[0];
  if(!file)return;
  try{
    if(file.size<80 || file.size>65536)throw Error('oversized/incomplete');
    const content=new TextDecoder('utf-8',{fatal:true})
      .decode(await file.arrayBuffer());
    const lines=content.split('\r\n');
    const canonicalHeader='source_ordinal,source_sha256_unsigned,review_status,privacy_topics,human_followup';
    if(lines[0]!==canonicalHeader || lines.length!==originals.length+2 ||
       lines.at(-1)!=='')throw Error('incomplete roster');
    const format=/^"((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)","((?:[^"]|"")*)"$/;
    const incoming=[];
    for(let n=0;n<originals.length;n++){
      const match=format.exec(lines[n+1]);
      if(!match)throw Error('noncanonical CSV row');
      const values=match.slice(1).map(value=>value.replaceAll('""','"'));
      if(values.map(csvCell).join(',')!==lines[n+1])throw Error('CSV changed');
      const [ordinal,sha,stage,topicText,note]=values;
      const original=originals[n];
      const selected=topicText.split('|');
      if(ordinal!==String(original.ordinal)||sha!==original.sha ||
         !STAGES.includes(stage)||selected.length===0 ||
         selected.some(item=>!TOPICS.includes(item)) ||
         selected.join('|')!==TOPICS.filter(item=>selected.includes(item)).join('|') ||
         (selected.includes('UNKNOWN')&&selected.length!==1) ||
         unsafe(note))throw Error('source HUMAN draft drift');
      incoming.push({stage,selected,note});
    }
    if(!window.confirm('Restore all '+incoming.length+
      ' HUMAN draft choices from this exact ORIGINAL-bound PRIVATE CSV? No privacy clearance or permissions will be granted.')){
      message.textContent='Cancelled; your current HUMAN choices remain unchanged.';
      return;
    }
    // Apply ALL only after every original source and every HUMAN row was admitted.
    for(let n=0;n<originals.length;n++){
      const target=proposal.get(originals[n].ordinal);
      const next=incoming[n];
      target.stage.value=next.stage;
      for(const [item,box] of target.checks)box.checked=next.selected.includes(item);
      target.note.value=next.note;
    }
    message.textContent='Exact-original PRIVATE HUMAN draft restored. Re-review labels and call native finalize separately.';
  }catch(_){
    message.textContent='HOLD: unsupported, incomplete or changed-original PRIVATE draft. All current HUMAN choices remain untouched.';
  }finally{reopen.value='';}
});
find.addEventListener('input',sync);
focus.addEventListener('change',sync);
window.addEventListener('pagehide',()=>{
  find.value='';focus.value='ALL';
  for(const p of proposal.values()){
    p.stage.value='PENDING';p.note.value='';
    for(const [name,box] of p.checks)box.checked=name==='UNKNOWN';
  }
  message.textContent='All local next-round draft proposals reset; downloaded files are not erased.';
  sync();
});
sync();
"""
    digest = b64encode(sha256(javascript.encode("utf-8")).digest()).decode("ascii")
    css = """
:root{color-scheme:light;background:#ecf2f8;color:#22354c;font:16px/1.55 system-ui}
*{box-sizing:border-box}body{max-width:1180px;margin:auto;padding:18px}
header,main,footer{background:white;border:1px solid #cddbe6;border-radius:14px;padding:22px;margin:17px 0}
.warning{background:#fff2eb;border-left:5px solid #b64e2b;padding:1rem}
.source{border:1px solid #cad7e4;border-radius:10px;padding:18px;margin:18px 0}
.source[hidden]{display:none}
h1{font-size:clamp(1.5rem,4vw,2.4rem)}
h2{font-size:1.2rem}
table{width:100%;border-collapse:collapse}td,th{padding:9px;border-bottom:1px solid #c3d4e1;text-align:left}
.controls{display:grid;grid-template-columns:1fr 1fr;gap:13px;margin:16px 0}
fieldset{border:1px solid #c4d1e0}fieldset label{display:block}
label{font-weight:600}select,textarea,input,button{font:inherit;padding:7px}
textarea{width:100%}button{border-radius:7px;border:1px solid #a0b6c5;background:#edf5fc;cursor:pointer}
button:focus-visible,input:focus-visible,textarea:focus-visible,select:focus-visible{outline:3px solid #d38b24}
.warn{background:#fff5e7;padding:9px}.neutral{background:#eaf5ef;padding:9px}
.explicit{grid-column:span 2}.explicit button{margin:5px}
@media(max-width:760px){.controls{display:block}.controls>*{display:block;margin:14px 0}
table{display:block;overflow-x:auto}}
@media print{button,.controls{display:none}body{background:white;padding:0}}
"""
    body = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'sha256-""" + digest + """'; style-src 'unsafe-inline'; connect-src 'none'; img-src 'none'; base-uri 'none'; form-action 'none'; object-src 'none'">
<title>LightUp PRIVATE HUMAN reviewer reconciliation Studio</title>
<style>""" + css + """</style><header>
<aside class="warning"><b>PRIVATE / HUMAN DISCUSSION / DRAFT-HOLD</b><p>
No reviewer slot is independently authenticated, and HUMAN consensus,
selected labels or a saved draft never authorize a recipient, consent,
release, security verdict or privacy clearance. All original, masked and
PRIVATE free-note source contents are withheld; this app does contain original
unsigned byte SHA references needed for the existing native source re-admission.
Keep the entire static HTML PRIVATE. No network, storage, server or upload.</p></aside>
<h1>HUMAN sensitivity reconciliation Studio</h1><p>Compare local, source-exact
reviewer proposals per original source position, deliberately choose your next
separate HUMAN review, and export the complete original-bound local CSV.
Default is <b>PENDING / UNKNOWN for every original</b>, not reviewer consensus.
Copying any earlier HUMAN choice requires a source-specific confirmation and
does NOT carry forward any private HUMAN free-text note.</p></header>
<main><label for="find">Filter original ordinal
<input id="find" type="search" inputmode="numeric"></label>
<label for="focus">HUMAN follow-up focus
<select id="focus" aria-describedby="count">
<option value="ALL">All original source positions</option>
<option value="DISAGREEMENT">Any HUMAN disagreement (including hidden note text)</option>
<option value="NOTE_DISAGREEMENT">PRIVATE HUMAN notes differ (text withheld)</option>
<option value="WITHHOLD">At least one HUMAN WITHHOLD</option>
<option value="REVIEW_REQUIRED">At least one HUMAN REVIEW_REQUIRED</option>
<option value="AGREED">Same HUMAN stage/category/note values</option>
</select></label>
<p id="count" role="status" aria-live="polite"></p><div id="sources"></div>
<p><label for="reopen">Resume complete earlier PRIVATE HUMAN draft (exact original sources only)</label>
<input id="reopen" type="file" accept=".csv,text/csv" aria-describedby="message"></p>
<p><button type="button" id="exportFocus">Save PRIVATE selected HUMAN discussion rows (not a final review)</button></p>
<button type="button" id="export">Save COMPLETE PRIVATE original-bound HUMAN decisions CSV</button>
<p id="message" role="status" aria-live="polite">
All next HUMAN choices are independent and pending. This browser does not finalize.</p>
</main><footer>Use the existing native
<code>notes.py sensitivity-finalize --completed-packet ORIGINAL --triage-kit THIS_KIT
--completed-csv PRIVATE_FILE --private-parent OWNER_0700</code>.
Native source SHA/owner-private checks remain mandatory. Always HOLD; no active
assessment, model, grant, network, outbound communication or deployment.
</footer><script>""" + javascript + """</script></html>"""
    return body.encode("utf-8")
