#!/usr/bin/env python3
"""Create an offline human conflict-resolution Studio from ORIGINAL bound bundles.

The browser must explicitly resolve EVERY contested source slot. No grant, GO,
reviewer identity authentication, scan, or automatic conflict winner.
"""
from __future__ import annotations
import argparse
from base64 import b64encode
from hashlib import sha256
from io import BytesIO
import json
from pathlib import Path
import sys
from zipfile import ZipFile

from portfolio import FLAGS, Hold, decode_json, publish, read_regular
from archive import MAX_MANIFEST
from followup import manifest_identity, load_choices
from portfolio_merge import MAX_PRIVATE_BUNDLE, MAX_CONTRIBUTORS
from workspace_return import _workspace, build as original_return, MAX_PACKAGE

ROOT=Path(__file__).resolve().parent
SCHEMA="lightup.assessment_portfolio_private_human_conflict_studio.v1"


def _digest(value):
    return b64encode(sha256(value.encode("utf-8")).digest()).decode("ascii")


def make_document(workspace, manifests, choices, proposals):
    if not 2<=len(proposals)<=MAX_CONTRIBUTORS:
        raise Hold("human conflict Studio requires 2-12 full contributor bundles")
    raw_workspace=read_regular(workspace,MAX_PACKAGE)
    source_map,agendas=_workspace(raw_workspace)
    n=source_map["source_count"]
    if len(manifests)!=n or len(choices)!=n:
        raise Hold("missing original cohort manifest/choices")
    originals=[]
    baseline_fingerprints=[]
    for i,(mp,cp) in enumerate(zip(manifests,choices),1):
        original,mhash=manifest_identity(mp)
        prior=load_choices(cp,original,mhash)
        chash=sha256(read_regular(cp,MAX_MANIFEST)).hexdigest()
        expected=source_map["sources"][i-1]
        if (expected["original_manifest_sha256"]!=mhash
                or expected["original_choices_sha256"]!=chash
                or original["status"]!=expected["claimed_status"]
                or len(prior)!=expected["original_source_count"]):
            raise Hold("original human source differs from saved original workspace")
        originals.append(prior)
        baseline_fingerprints.append((mhash,chash))
    all_edits={}
    seen=set()
    contributors=[]
    for index,path in enumerate(proposals,1):
        contribution=read_regular(path,MAX_PRIVATE_BUNDLE)
        digest=sha256(contribution).hexdigest()
        if digest in seen:
            raise Hold("duplicate private human reviewer file")
        seen.add(digest)
        returned,status,_=original_return(
            workspace,manifests,choices,proposal_bundle_path=path)
        if status!=source_map["claimed_status"]:
            raise Hold("original HOLD differs between contributor returns")
        with ZipFile(BytesIO(returned),"r") as z:
            revisions=[decode_json(z.read(f"original-human-choices-{i:02d}.json"))
                       for i in range(1,n+1)]
        changes=0
        for agenda,(before,new_doc) in enumerate(zip(originals,revisions),1):
            if (type(new_doc) is not dict or
                    new_doc.get("manifest_sha256")!=baseline_fingerprints[agenda-1][0]
                    or type(new_doc.get("items")) is not list
                    or len(new_doc["items"])!=len(before)):
                raise Hold("human source changed before conflict review")
            for old,later in zip(before,new_doc["items"]):
                if (old["slot"]!=later["slot"]
                        or old["source_sha256"]!=later["source_sha256"]):
                    raise Hold("original human source membership changed")
                changed=[key for key in ("stage","next_role","review_date")
                         if old[key]!=later[key]]
                if not changed:
                    continue
                all_edits.setdefault((agenda,old["slot"]),[]).append({
                    "contributor":index,"stage":later["stage"],
                    "next_role":later["next_role"],"review_date":later["review_date"],
                    "changed_fields":changed})
                changes+=1
        contributors.append({"slot":index,"input_sha256":digest,
                             "changed_slots":changes})
    # Human source files must stay fixed across all independent source passes.
    for i,(mp,cp) in enumerate(zip(manifests,choices)):
        if (manifest_identity(mp)[1],sha256(read_regular(cp,MAX_MANIFEST)).hexdigest()
                )!=baseline_fingerprints[i]:
            raise Hold("original human source drifted while opening reviewer proposals")
    if sha256(read_regular(workspace,MAX_PACKAGE)).hexdigest()!=sha256(raw_workspace).hexdigest():
        raise Hold("original human workspace changed while opening contributor proposals")
    conflicts=sum(len(candidates)>1 for candidates in all_edits.values())
    affected=sum(1 for _ in all_edits)
    groups=[]
    for i,(original,agenda_raw) in enumerate(zip(originals,agendas),1):
        rows=[]
        for item in original:
            rows.append({
                "slot":item["slot"],
                "prior_stage":item["stage"],"prior_next_role":item["next_role"],
                "prior_review_date":item["review_date"],
                "candidates":all_edits.get((i,item["slot"]),[])
            })
        groups.append({"slot":i,"source_agenda_sha256":sha256(agenda_raw).hexdigest(),
                       "rows":rows})
    return {
        "schema":SCHEMA,"reference_date":source_map["reference_date"],
        "source_count":n,"sources":groups,
        "contributor_count":len(proposals),"contributors":contributors,
        "edited_slots":affected,"conflict_slots":conflicts,
        "claimed_status":source_map["claimed_status"],
        "planning_not_permission":True,**{f:False for f in FLAGS}
    }


def build(workspace,manifests,choices,proposals):
    data=make_document(workspace,manifests,choices,proposals)
    template=(ROOT/"mediation.template.html").read_text(encoding="utf-8")
    css=(ROOT/"mediation.css").read_text(encoding="utf-8")
    js=(ROOT/"mediation.js").read_text(encoding="utf-8")
    payload=json.dumps(data,sort_keys=True,ensure_ascii=True,allow_nan=False,
                       separators=(",",":")).replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e")
    csp=("<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
         "script-src 'sha256-"+_digest(js)+"'; style-src 'sha256-"+_digest(css)+
         "'; connect-src 'none'; img-src 'none'; font-src 'none'; "
         "form-action 'none'; object-src 'none'; base-uri 'none'\">")
    for marker,body in (("@@CSP@@",csp),("@@CSS@@",css),
                        ("@@PAYLOAD@@",payload),("@@SCRIPT@@",js)):
        if template.count(marker)!=1:
            raise Hold("invalid private human mediation template")
        template=template.replace(marker,body)
    return template.encode("utf-8"),data["claimed_status"],data["conflict_slots"]


def main(argv=None):
    p=argparse.ArgumentParser(description="Private browser conflict resolution for independently validated original human proposals; no GO")
    p.add_argument("--workspace",required=True)
    p.add_argument("--original-manifest",action="append",required=True)
    p.add_argument("--original-choices",action="append",required=True)
    p.add_argument("--proposal-bundle",action="append",required=True,
                   help="Original all-agenda human proposal; repeat 2-12")
    p.add_argument("--output",required=True,help="NEW private 0600 standalone offline HTML, no overwrite")
    a=p.parse_args(argv)
    try:
        html,status,conflicts=build(a.workspace,a.original_manifest,
                                    a.original_choices,a.proposal_bundle)
        publish(a.output,html)
        print(f"PRIVATE_ORIGINAL_HUMAN_MEDIATION_CREATED contested_human_slots={conflicts} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("ORIGINAL_HUMAN_MEDIATION_HOLD — changed or incompatible original private source",
              file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
