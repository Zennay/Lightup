#!/usr/bin/env python3
"""Merge 2–12 complete original-bound private human proposal bundles safely.

All original sources are independently re-admitted through the established
workspace return path; same source-slot edits from two contributors HOLD.
No client authority, scanner, target, grant, model, or write to originals.
"""
from __future__ import annotations

import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
from io import BytesIO
import sys
from zipfile import ZipFile

from portfolio import FLAGS, Hold, MAX_BYTES, decode_json, encode, publish, read_regular
from archive import MAX_MANIFEST
from followup import manifest_identity, load_choices
from workspace_return import _workspace, build as return_build, MAX_PACKAGE
from multi_return import _zip

SCHEMA="lightup.assessment_portfolio_collaborative_human_bundle_merge.v1"
BUNDLE_SCHEMA="lightup.assessment_portfolio_human_proposal_bundle.v1"
PROPOSAL_SCHEMA="lightup.assessment_portfolio_human_proposal.v1"
MAX_CONTRIBUTORS=12
MAX_PRIVATE_BUNDLE=4*1024*1024
STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;background:#091829;color:#e7f5fb;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1180px;margin:auto;padding:24px}
header{padding:33px;border:1px solid #457083;border-radius:18px;background:linear-gradient(123deg,#164c5a,#19283d)}
small{font-weight:800;color:#a0e9d2;letter-spacing:.13em}h1{font-size:clamp(2rem,5vw,3.4rem)}
p{color:#bed4e1}h2{margin:0 0 12px}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin:18px 0}
.stats section,section{padding:20px;background:#152e43;border:1px solid #3b6276;border-radius:12px;margin:17px 0}
.stats b{font-size:2rem;display:block}.stats span{color:#bcd5e2}
table{width:100%;border-collapse:collapse}td,th{text-align:left;padding:10px;border-bottom:1px solid #33566c}
th{color:#a8ead7}tr:nth-child(even){background:#1b3a50}
.warning{background:#302d3a;border-left:4px solid #e8cd8a;padding:17px}
footer{font-size:.82rem;color:#a8c3d3}@media(max-width:760px){.stats{display:block}body{padding:13px}}
@media print{body,header,section{background:white;color:black}p{color:#222}}
"""


def page(rows, counts, status):
    digest=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    records="".join("<tr>"+"".join("<td>"+escape(str(item))+"</td>" for item in (
        row["agenda"],row["source_slot"],row["contributor"],", ".join(row["changed_fields"])))+
        "</tr>" for row in rows)
    if not records:
        records="<tr><td colspan='4'>No contributor changed any human planning slot.</td></tr>"
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta name='referrer' content='no-referrer'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
        "style-src 'sha256-"+digest+"'; script-src 'none'; img-src 'none'; "
        "connect-src 'none'; object-src 'none'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp · Private collaborative human review</title><style>"+STYLE+"</style></head><body>"
        "<header><small>LIGHTUP / OFFLINE ORIGINAL HUMAN REVIEW / PRIVATE</small>"
        "<h1>Independent human proposals, one complete handoff.</h1>"
        "<p>All contributor inputs match the exact prior original source state; no overlapping edits "
        "to any original agenda/slot were silently selected.</p>"
        "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "+
        escape(status)+" · NO GO</strong></header>"
        "<div class='stats'><section><b>"+str(counts["contributor_count"])+
        "</b><span>Independent private input bundles</span></section><section><b>"+
        str(counts["agenda_count"])+"</b><span>Original agenda sources</span></section>"
        "<section><b>"+str(counts["changed_human_slots"])+
        "</b><span>Human-only changed slots</span></section></div>"
        "<section><h2>Source-neutral proposed edits</h2>"
        "<p>Contributor numbers reflect only the ordering of local private input files. "
        "They are NOT authenticated reviewer identities.</p>"
        "<table><thead><tr><th>Agenda</th><th>Original slot</th>"
        "<th>Local contributor #</th><th>Human planning fields</th></tr></thead>"
        "<tbody>"+records+"</tbody></table></section>"
        "<aside class='warning'><strong>Only a private human proposal, never a clearance.</strong>"
        "<p>No findings, evidence, target, credentials, client identity or actual task assignment "
        "is processed. Human stage/date changes are NOT verified fixes or completed reviews; "
        "SHA-256 correlations are unsigned and do not prove source authenticity. "
        "Existing original source owner, separate security/privacy, genuine client/operator "
        "consent with action-time revocation, exact-head hosted/named VPS CI and "
        "explicit HUMAN GO remain mandatory for any real action or release.</p></aside>"
        "<footer>Static offline source-neutral view · private bundle · no network/scans/grants/scripts</footer>"
        "</body></html>").encode("utf-8")


def build(workspace_path, manifest_paths, choice_paths, bundle_paths):
    count=len(bundle_paths)
    if not 2<=count<=MAX_CONTRIBUTORS:
        raise Hold("two to twelve private human contributors required")
    original_workspace=read_regular(workspace_path,MAX_PACKAGE)
    source_map,original_agendas=_workspace(original_workspace)
    n=source_map["source_count"]
    if len(manifest_paths)!=n or len(choice_paths)!=n:
        raise Hold("all unchanged original manifests/choices must be supplied")
    baselines=[]
    before_sources=[]
    for index,(mp,cp) in enumerate(zip(manifest_paths,choice_paths),1):
        original,mhash=manifest_identity(mp)
        current=load_choices(cp,original,mhash)
        expected=source_map["sources"][index-1]
        choices_raw=read_regular(cp,MAX_MANIFEST)
        if (mhash!=expected["original_manifest_sha256"]
                or sha256(choices_raw).hexdigest()!=expected["original_choices_sha256"]
                or original["status"]!=expected["claimed_status"]
                or len(current)!=expected["original_source_count"]):
            raise Hold("original manifest/choices mismatch before collaborating")
        baselines.append(current)
        before_sources.append((mhash,sha256(choices_raw).hexdigest()))
    contributors=[]
    sources_seen=set()
    decisions={}
    slot_contributions=[]
    for reviewer_index,path in enumerate(bundle_paths,1):
        raw=read_regular(path,MAX_PRIVATE_BUNDLE)
        fingerprint=sha256(raw).hexdigest()
        if fingerprint in sources_seen:
            raise Hold("same human contributor bundle supplied multiple times")
        sources_seen.add(fingerprint)
        # Reuses unchanged strict full all-source admission, byte-bound original
        # agenda renderer, original human prior fields and all false-only flags.
        returned,claimed_status,_=return_build(
            workspace_path,manifest_paths,choice_paths,
            proposal_bundle_path=path)
        if claimed_status!=source_map["claimed_status"]:
            raise Hold("original HOLD status drifted in contributor return")
        with ZipFile(BytesIO(returned),"r") as z:
            updated=[decode_json(z.read(f"original-human-choices-{i:02d}.json"))
                     for i in range(1,n+1)]
        changes=0
        for agenda,(prior,doc) in enumerate(zip(baselines,updated),1):
            if (type(doc) is not dict or type(doc.get("items")) is not list
                    or len(doc["items"])!=len(prior)
                    or doc.get("manifest_sha256")!=before_sources[agenda-1][0]):
                raise Hold("complete original returned human choices mismatch")
            for old,new in zip(prior,doc["items"]):
                if old["slot"]!=new["slot"] or old["source_sha256"]!=new["source_sha256"]:
                    raise Hold("original human slot or source identity changed")
                fields=[field for field in ("stage","next_role","review_date")
                        if old[field]!=new[field]]
                if not fields:
                    continue
                key=(agenda,old["slot"])
                if key in decisions:
                    # Conflict even if both contributors propose an identical
                    # value or different fields: human choice cannot be inferred.
                    raise Hold("conflicting contributor edits on one original human slot")
                decisions[key]=new
                slot_contributions.append({
                    "agenda":agenda,"source_slot":old["slot"],
                    "contributor":reviewer_index,"changed_fields":fields})
                changes+=1
        contributors.append({"local_contributor":reviewer_index,
                             "private_bundle_sha256":fingerprint,
                             "changed_human_slots":changes})
    # Freeze ORIGINAL source references against input changes during merge.
    for index,(mp,cp) in enumerate(zip(manifest_paths,choice_paths)):
        new_manifest=manifest_identity(mp)[1]
        new_choices=sha256(read_regular(cp,MAX_MANIFEST)).hexdigest()
        if (new_manifest,new_choices)!=before_sources[index]:
            raise Hold("original human sources changed during collaboration")
    if sha256(read_regular(workspace_path,MAX_PACKAGE)).hexdigest()!=sha256(original_workspace).hexdigest():
        raise Hold("original human workspace changed during collaboration")
    rows=[]
    updated_total=0
    for i,(baseline,agenda_raw) in enumerate(zip(baselines,original_agendas),1):
        changes=[]
        for old in baseline:
            replacement=decisions.get((i,old["slot"]),old)
            changes.append({"slot":old["slot"],"prior_stage":old["stage"],
                            "prior_next_role":old["next_role"],"prior_review_date":old["review_date"],
                            "stage":replacement["stage"],"next_role":replacement["next_role"],
                            "review_date":replacement["review_date"]})
        updated_total+=sum((i,item["slot"]) in decisions for item in changes)
        proposal={"schema":PROPOSAL_SCHEMA,
                  "source_agenda_sha256":sha256(agenda_raw).hexdigest(),
                  "reference_date":source_map["reference_date"],
                  "source_count":len(changes),"items":changes,
                  **{flag:False for flag in FLAGS}}
        rows.append({"slot":i,"source_agenda_sha256":sha256(agenda_raw).hexdigest(),
                     "proposal":proposal})
    if updated_total!=len(slot_contributions):
        raise Hold("merged human slot totals disagree")
    merged={"schema":BUNDLE_SCHEMA,"reference_date":source_map["reference_date"],
            "source_count":n,"sources":rows,"planning_not_permission":True,
            **{flag:False for flag in FLAGS}}
    source_contributions=sorted(slot_contributions,key=lambda row:(row["agenda"],row["source_slot"]))
    manifest={"schema":SCHEMA,"source_count":n,"contributor_count":count,
              "original_reference_date":source_map["reference_date"],
              "claimed_status":source_map["claimed_status"],
              "original_workspace_sha256":sha256(original_workspace).hexdigest(),
              "changed_human_slots":updated_total,
              "contributors":contributors,
              "source_changes":source_contributions,
              "planning_not_permission":True,
              **{flag:False for flag in FLAGS}}
    package={
        "merged-private-all-human-proposals.json":encode(merged),
        "private-collaboration-manifest.json":encode(manifest),
        "index.html":page(source_contributions,{
            "contributor_count":count,"agenda_count":n,
            "changed_human_slots":updated_total},source_map["claimed_status"]),
        "START-HERE.txt":(
            "LIGHTUP / PRIVATE ORIGINAL HUMAN COLLABORATION / NO GO\n"
            "2-12 complete original-bound human bundles merged only for disjoint source slots.\n"
            "Open index.html for local PRIVATE source-neutral change provenance.\n"
            "Use merged-private-all-human-proposals.json via the existing\n"
            "workspace_return.py OR review_cycle.py --proposal-bundle with exactly\n"
            "the unchanged ORIGINAL workspace/manifests/choices.\n"
            "A repeated original slot from multiple contributors caused full HOLD.\n"
            "Contributor ordinals are NOT authenticated reviewer identities.\n"
            "Original sources remain unchanged; no real actions, grants or consent.\n"
            "Original review, CI and human authorization gates remain mandatory.\n"
            "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.\n").encode("utf-8"),
    }
    return _zip(package),source_map["claimed_status"],updated_total


def main(argv=None):
    p=argparse.ArgumentParser(
        description="Merge multiple complete original human portfolio bundles by disjoint slot; NO GO")
    p.add_argument("--workspace",required=True,help="Original private one-command workspace ZIP")
    p.add_argument("--original-manifest",action="append",required=True)
    p.add_argument("--original-choices",action="append",required=True)
    p.add_argument("--proposal-bundle",action="append",required=True,
                   help="Private all-agenda JSON from each independent reviewer; repeat 2–12")
    p.add_argument("--output",required=True,help="NEW owner-private ZIP; never overwrite")
    a=p.parse_args(argv)
    try:
        blob,status,changed=build(a.workspace,a.original_manifest,
                                   a.original_choices,a.proposal_bundle)
        publish(a.output,blob)
        print(f"PRIVATE_PORTFOLIO_HUMAN_COLLABORATION_CREATED original_human_slots={changed} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("PRIVATE_PORTFOLIO_HUMAN_MERGE_HOLD — original sources or human slots conflict",
              file=sys.stderr)
        return 3


if __name__=="__main__":
    raise SystemExit(main())
