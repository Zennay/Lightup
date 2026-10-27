#!/usr/bin/env python3
"""Offline original-schema return of multiple independent human review proposals.

Never alters original sources, persistent grants, models, target access or scans.
"""
from __future__ import annotations
import argparse
from base64 import b64encode
from collections import Counter
from hashlib import sha256
from html import escape
from io import BytesIO
from zipfile import ZipFile, ZipInfo, ZIP_STORED
import sys

from portfolio import FLAGS, Hold, decode_json, encode, publish
from proposal_return import reconcile

SCHEMA="lightup.assessment_portfolio_multi_human_return.v1"
STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;background:#091725;color:#e8f7fe;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1000px;margin:0 auto;padding:25px}
header{background:linear-gradient(125deg,#18485a,#15253d);padding:31px;border:1px solid #3d637a;border-radius:20px}
small{color:#a0e8cc;letter-spacing:.13em;font-weight:800}
h1{font-size:clamp(2rem,5vw,3.3rem)}p{color:#baccdf}strong{color:#eedba0}
.card{border:1px solid #3d5d70;border-radius:13px;background:#172e42;padding:19px;margin:22px 0}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:12px;border-bottom:1px solid #30556e}
th{color:#9ce6cf}tr:nth-child(even){background:#1c3848}
.warn{border-left:4px solid #e4c68a;padding:14px;background:#312c37}
footer{color:#aec1cf;font-size:.83rem}
@media print{body,header,.card{background:white;color:#222}p{color:#222}}
"""

def _page(records, overall):
    h=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    items="".join(
        "<tr><td>"+str(item["slot"])+"</td><td>"+str(item["human_updates"])+
        "</td><td>"+escape(item["claimed_status"])+"</td><td><code>"+
        escape(item["output_member"])+"</code></td></tr>"
        for item in records)
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
            " style-src 'sha256-"+h+"'; img-src 'none'; connect-src 'none'; script-src 'none';"
            " object-src 'none'; form-action 'none'; base-uri 'none'\">"
            "<title>LightUp · Private Original Human Return</title><style>"+
            STYLE+"</style></head><body><header><small>LIGHTUP / ORIGINAL HUMAN REVIEW</small>"
            "<h1>Private multi-source review return.</h1>"
            "<p>Original, unaltered human choices are transformed into NEW original-schema choices, "
            "only after individual original manifest/choices/agenda/proposal consistency validation.</p>"
            "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · "+escape(overall)+
            " · DRAFT/HOLD · NO GO</strong></header>"
            "<section class='card'><h2>Human-only return inventory</h2>"
            "<table><thead><tr><th>Local source</th><th>Changed human slots</th>"
            "<th>Original source state</th><th>New private original-schema file</th></tr></thead><tbody>"+
            items+"</tbody></table></section><aside class='warn'><strong>No inferred trust or completion.</strong>"
            "<p>Each source belongs to an explicit original private manifest and unchanged earlier human choices. "
            "Neither a private SHA-256 nor a human stage verifies evidence, resolves findings, authenticates the source, "
            "authorizes client work or releases a model. Opening or extracting these files creates no approvals. "
            "Review, privacy/security, real independent current consent, original exact-head hosted/named VPS CI, "
            "action-time revocation and HUMAN GO remain mandatory.</p></aside>"
            "<footer>Static offline · private original human records · no client findings/targets, scripts, network or scanner</footer>"
            "</body></html>").encode("utf-8")

def _zip(files):
    output=BytesIO()
    with ZipFile(output,"w",compression=ZIP_STORED) as archive:
        for name,bytes_value in files.items():
            member=ZipInfo(name,(2026,10,18,0,0,0))
            member.external_attr=0o600<<16
            archive.writestr(member,bytes_value)
    return output.getvalue()

def build(manifests,choices,agendas,proposals):
    groups=(manifests,choices,agendas,proposals)
    count=len(agendas)
    if not 2<=count<=12 or any(len(group)!=count for group in groups):
        raise Hold("mismatched original input groups")
    files={}
    records=[]
    originals=set()
    total=0
    for i,group in enumerate(zip(*groups),1):
        result,state,changed=reconcile(*group)
        original_choice=decode_json(result)
        manifest_digest=original_choice["manifest_sha256"]
        # The same original archive cannot receive conflicting multi-source human returns.
        if manifest_digest in originals:
            raise Hold("duplicate original human manifest")
        originals.add(manifest_digest)
        filename=f"original-human-choices-{i:02d}.json"
        files[filename]=result
        records.append({"slot":i,"output_member":filename,
                        "original_manifest_sha256":manifest_digest,
                        "new_choices_sha256":sha256(result).hexdigest(),
                        "human_updates":changed,"claimed_status":state})
        total+=changed
    overall="HOLD" if any(row["claimed_status"]=="HOLD" for row in records) else "REVIEW_ONLY"
    manifest={"schema":SCHEMA,"source_count":count,"total_human_updates":total,
              "claimed_status":overall,"sources":records,
              "planning_not_permission":True,
              **{flag:False for flag in FLAGS}}
    # Output ready only after ALL independent human proposals were reconciled.
    files["private-manifest.json"]=encode(manifest)
    files["index.html"]=_page(records,overall)
    files["START-HERE.txt"]=(
        "LIGHTUP PRIVATE MULTI-HUMAN RETURN · DRAFT/HOLD · NO GO\n"
        "Each original-human-choices-NN.json is in the unchanged ORIGINAL "
        "lightup.archive_human_followup.v1 schema for its matching original manifest.\n"
        "No original manifest, findings/evidence CSV, target information, "
        "operator credentials or lab cases are included.\n"
        "private-manifest.json has unsalted private source SHA-256 correlations; "
        "the full ZIP is CONFIDENTIAL.\n"
        "Apply NOTHING automatically: the real original human owner must choose "
        "a matching original manifest and explicitly render each independent file "
        "through original assessment-archive/agenda.py after checking source context.\n"
        "Original HOLD remains HOLD. A human proposal neither certifies provenance "
        "nor grants consent, execution or release.\n"
    ).encode("utf-8")
    return _zip(files),overall,total

def main(argv=None):
    p=argparse.ArgumentParser(description="Private multi-source ORIGINAL human-choices return, no authorization")
    p.add_argument("--original-manifest",action="append",required=True)
    p.add_argument("--original-choices",action="append",required=True)
    p.add_argument("--original-agenda",action="append",required=True)
    p.add_argument("--proposal",action="append",required=True)
    p.add_argument("--output",required=True,help="NEW owner-private ZIP path, never overwritten")
    a=p.parse_args(argv)
    try:
        archive,state,count=build(a.original_manifest,a.original_choices,
                                  a.original_agenda,a.proposal)
        publish(a.output,archive)
        print(f"PRIVATE_MULTI_SOURCE_HUMAN_RETURN_CREATED changed_human_slots={count} — NO GO")
        return 3 if state=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            OverflowError,RecursionError):
        print("MULTI_SOURCE_HUMAN_RETURN_HOLD — invalid or conflicting original sources",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
