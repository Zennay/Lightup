#!/usr/bin/env python3
"""Merge disjoint PRIVATE human-only proposals against one exact original archive.

This is a human coordination handoff, not scanner authorization or finding validation.
"""
from __future__ import annotations
import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
from io import BytesIO
from zipfile import ZipFile, ZipInfo, ZIP_STORED
import sys

from portfolio import MAX_BYTES, FLAGS, Hold, decode_json, encode, publish, read_regular
from proposal_return import reconcile
from followup import CHOICES_SCHEMA
from archive import MAX_MANIFEST

SCHEMA="lightup.assessment_portfolio_merged_human_proposals.v1"
STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;color:#ecf7ff;background:#091622}
*{box-sizing:border-box}body{max-width:1110px;margin:0 auto;padding:25px}
header{border-radius:20px;background:linear-gradient(120deg,#175062,#192940);
border:1px solid #446578;padding:30px}
small{font-weight:800;letter-spacing:.14em;color:#9ce8cd}h1{font-size:clamp(2.1rem,5vw,3.4rem)}
p{color:#bacfe0}strong{color:#f4d899}
section{background:#182d43;padding:20px;border:1px solid #375970;border-radius:13px;margin:18px 0}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:10px;border-bottom:1px solid #355469}
th{color:#9de8ce}tr:nth-child(even){background:#20374b}
.warning{border-left:4px solid #e0ca8e;padding:18px;background:#2d3041}
footer{color:#adc2d0;font-size:.84rem}
@media print{body,header,section{color:black;background:white}p{color:#222}}
"""

def html(rows,status,number):
    checksum=b64encode(sha256(STYLE.encode()).digest()).decode()
    changes="".join(
        "<tr><td>"+str(row["slot"])+"</td><td>"+str(row["contributor"])+
        "</td><td>"+escape(", ".join(row["human_changed_fields"]))+"</td></tr>"
        for row in rows)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            " img-src 'none'; connect-src 'none'; script-src 'none'; object-src 'none';"
            " base-uri 'none'; form-action 'none'; style-src 'sha256-"+checksum+"'\">"
            "<title>LightUp · Private Human Proposal Merge</title><style>"+STYLE+"</style>"
            "</head><body><header><small>LIGHTUP / PRIVATE ORIGINAL-SOURCE REVIEW</small>"
            "<h1>Disjoint human proposal merge.</h1>"
            "<p>"+str(number)+" independently exported private proposals from one exact original human agenda. "
            "Any two editors changing the same original slot causes the ENTIRE operation to HOLD without output.</p>"
            "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · "+escape(status)+" · DRAFT/HOLD · NO GO</strong>"
            "</header><section><h2>Human-only changed slots</h2>"
            "<table><thead><tr><th>Original source slot</th><th>Local proposal number</th>"
            "<th>Human-only fields changed</th></tr></thead><tbody>"+changes+"</tbody></table></section>"
            "<aside class='warning'><strong>No inferred validation, safe scan or consent.</strong>"
            "<p>All original choices and source rows remain separate and immutable. This is an unsigned human-only "
            "discussion proposal; it does not authenticate reviewer identity or verify evidence. "
            "Source-owner approval, independent security/privacy, real client/operator consent including "
            "action-time revocation, original exact-head hosted and permanent named VPS CI and HUMAN GO "
            "remain mandatory before any live activity or production release.</p></aside>"
            "<footer>Private offline handoff · no browser scripts, network, model, scan or grants</footer>"
            "</body></html>").encode("utf-8")

def pack(files):
    stream=BytesIO()
    with ZipFile(stream,"w",compression=ZIP_STORED) as package:
        for name,data in files.items():
            info=ZipInfo(name,(2026,10,18,0,0,0))
            info.external_attr=0o600<<16
            package.writestr(info,data)
    return stream.getvalue()

def build(manifest_path,choices_path,agenda_path,proposals):
    if not 2<=len(proposals)<=12:
        raise Hold("two to twelve original human proposals required")
    # Pin all three immutable original reference files across multiple source reads.
    refs=((manifest_path,MAX_MANIFEST),(choices_path,MAX_MANIFEST),(agenda_path,MAX_BYTES))
    initial=[sha256(read_regular(path,bound)).hexdigest() for path,bound in refs]
    baseline=None
    original_status=None
    proposed_changes={}
    contributions=[]
    for index,path in enumerate(proposals,1):
        returned,status,_=reconcile(manifest_path,choices_path,agenda_path,path)
        doc=decode_json(returned)
        if (type(doc) is not dict or doc.get("schema")!=CHOICES_SCHEMA or
                type(doc.get("items")) is not list or
                any(doc.get(f) is not False for f in FLAGS)):
            raise Hold("invalid original human choices output")
        if baseline is None:
            baseline=decode_json(read_regular(choices_path,MAX_MANIFEST))
            if (type(baseline) is not dict or baseline.get("schema")!=CHOICES_SCHEMA or
                    baseline.get("manifest_sha256")!=doc["manifest_sha256"] or
                    type(baseline.get("items")) is not list or
                    len(baseline["items"])!=len(doc["items"])):
                raise Hold("original human baseline changed")
            original_status=status
        elif status!=original_status:
            raise Hold("mixed original source review state")
        updates=0
        for current,updated in zip(baseline["items"],doc["items"]):
            if (current["slot"]!=updated["slot"] or
                    current["source_sha256"]!=updated["source_sha256"]):
                raise Hold("original human slot replaced")
            fields=[name for name in ("stage","next_role","review_date")
                    if current[name]!=updated[name]]
            if not fields:
                continue
            slot=current["slot"]
            if slot in proposed_changes:
                raise Hold("overlapping human slot proposals require explicit owner review")
            proposed_changes[slot]=updated
            contributions.append({"slot":slot,"contributor":index,
                                  "human_changed_fields":fields})
            updates+=1
    after=[sha256(read_regular(path,bound)).hexdigest() for path,bound in refs]
    if initial!=after:
        raise Hold("source drifted during private human reconciliation")
    final_items=[proposed_changes.get(item["slot"],item) for item in baseline["items"]]
    result=encode({"schema":CHOICES_SCHEMA,
                   "manifest_sha256":baseline["manifest_sha256"],
                   "items":final_items,
                   **{flag:False for flag in FLAGS}})
    contributions.sort(key=lambda x:x["slot"])
    summary={"schema":SCHEMA,
             "original_manifest_sha256":initial[0],
             "original_choices_sha256":initial[1],
             "original_agenda_sha256":initial[2],
             "result_original_choices_sha256":sha256(result).hexdigest(),
             "source_slots":len(final_items),
             "human_changed_slots":len(contributions),
             "source_proposal_count":len(proposals),
             "human_slot_contributions":contributions,
             "claimed_status":original_status,
             "planning_not_permission":True,
             **{flag:False for flag in FLAGS}}
    files={"START-HERE.txt":(
            "LIGHTUP PRIVATE DISJOINT HUMAN RETURN — DRAFT/HOLD · NO GO\n"
            "new-original-human-choices.json contains exactly the original archive follow-up schema.\n"
            "human-merge-manifest.json binds original SHA snapshots and changed HUMAN slot numbers.\n"
            "Open index.html offline for scriptless human review.\n"
            "No original target, lab evidence, client findings, private passwords or raw original source files "
            "are bundled. Treat entire ZIP as PRIVATE due to original per-slot SHA references.\n"
            "An original human proposal is not verified remediation, authenticated consent or release.\n"
            "The recipient must separately confirm original context and deliberately call the ORIGINAL "
            "assessment-archive/agenda.py to render from matching original manifest.\n").encode("utf-8"),
           "new-original-human-choices.json":result,
           "human-merge-manifest.json":encode(summary),
           "index.html":html(contributions,original_status,len(proposals))}
    return pack(files),original_status,len(contributions)

def main(argv=None):
    p=argparse.ArgumentParser(description="Merge non-overlapping original source human proposal fields only; never authorize")
    p.add_argument("--original-manifest",required=True)
    p.add_argument("--original-choices",required=True)
    p.add_argument("--original-agenda",required=True)
    p.add_argument("--proposal",action="append",required=True,help="PRIVATE human proposal; 2–12 for the SAME original")
    p.add_argument("--output",required=True,help="New owner-private ZIP, no overwrite")
    a=p.parse_args(argv)
    try:
        result,status,changed=build(a.original_manifest,a.original_choices,
                                    a.original_agenda,a.proposal)
        publish(a.output,result)
        print(f"DISJOINT_PRIVATE_HUMAN_PROPOSALS_PACKAGED human_slots={changed} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("HUMAN_MERGE_HOLD — invalid original sources or conflicting human slots",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
