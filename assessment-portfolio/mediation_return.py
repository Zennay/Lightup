#!/usr/bin/env python3
"""Receive a human-resolved multi-reviewer bundle only from known original choices.

The source-bound receiver remains mandatory; conflict mediation is no authority.
"""
from __future__ import annotations
import argparse
from base64 import b64encode
from hashlib import sha256
from html import escape
from io import BytesIO
import sys
from zipfile import ZipFile

from portfolio import FLAGS, Hold, decode_json, encode, publish, read_regular
from workspace_return import _workspace, MAX_PACKAGE, build as original_return
from proposal_bundle import load as load_original_bundle
from portfolio_mediation import make_document
from review_cycle import build as build_next
from multi_return import _zip

SCHEMA="lightup.assessment_portfolio_private_human_mediation_return.v1"
STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;background:#0a1829;color:#e9f5fc;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1100px;margin:0 auto;padding:28px}
header{padding:31px;background:linear-gradient(130deg,#17525f,#19283f);border-radius:19px;border:1px solid #477084}
small{color:#9be8ce;font-weight:800;letter-spacing:.14em}h1{font-size:clamp(2rem,5vw,3.5rem)}
p{color:#bdd5df}section{background:#152e43;padding:20px;border-radius:13px;border:1px solid #40677b;margin:17px 0}
table{border-collapse:collapse;width:100%}th,td{text-align:left;padding:11px;border-bottom:1px solid #3a5b6e}
th{color:#abebd8}tr:nth-child(even){background:#1c374d}
.note{border-left:4px solid #efd08b;background:#302c3d;padding:19px}
footer{color:#adc8d5;font-size:.86rem}
@media(max-width:760px){body{padding:12px}}
@media print{body,header,section{background:white;color:#222}p{color:#222}}
"""

def _html(rows, original_status):
    css=b64encode(sha256(STYLE.encode()).digest()).decode()
    body="".join("<tr>"+"".join("<td>"+escape(str(v))+"</td>" for v in (
        row["agenda"],row["slot"],row["disposition"],
        ", ".join(str(i) for i in row["matching_contributors"]) or "—"
    ))+"</tr>" for row in rows)
    if not body:
        body="<tr><td colspan='4'>No contested source slots were present.</td></tr>"
    return ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "style-src 'sha256-"+css+"'; connect-src 'none'; img-src 'none'; "
            "script-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'\">"
            "<title>LightUp · Private human conflict choices</title><style>"+STYLE+"</style></head><body>"
            "<header><small>LIGHTUP / ORIGINAL HUMAN REVIEW / PRIVATE</small>"
            "<h1>Conflicts resolved as human proposals.</h1>"
            "<p>Each contested original agenda/slot has a source-bound proposal value "
            "matching either the prior human values or one of the independently admitted proposals. "
            "This report does not authenticate who made the choice.</p>"
            "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "+
            escape(original_status)+" · NO GO</strong></header>"
            "<section><h2>Contested original human slots</h2>"
            "<table><thead><tr><th>Agenda</th><th>Original slot</th>"
            "<th>Human-only disposition</th><th>Matching local contributor numbers</th>"
            "</tr></thead><tbody>"+body+"</tbody></table></section>"
            "<aside class='note'><strong>Never proof of an approved finding, consent or action.</strong>"
            "<p>Retaining the original or matching a proposal does not attest an actual human identity "
            "or review. Byte SHA values and reviewer ordinals are unsigned. "
            "Original exact-head hosted/named VPS CI, source-owner approval, "
            "independent privacy/security, genuine separate authenticated client/operator "
            "consent with action-time revocation and explicit HUMAN GO remain mandatory.</p></aside>"
            "<footer>Static private offline human planning · no model, scanner, network, grant or real target.</footer>"
            "</body></html>").encode("utf-8")


def build(workspace_path,manifests,choices,contributions,resolved_path,next_day,
          previous_capacity=None,reconfirmed_capacity=False):
    source=make_document(workspace_path,manifests,choices,contributions)
    mapping,agendas=_workspace(read_regular(workspace_path,MAX_PACKAGE))
    resolved_raw=read_regular(resolved_path,4*1024*1024)
    accepted=load_original_bundle(None,mapping,agendas,raw=resolved_raw)
    n=source["source_count"]
    if len(accepted)!=n or n!=len(source["sources"]):
        raise Hold("original reviewed source group count changed")
    decisions=[]
    modified=0
    conflicts=0
    for src,raw in zip(source["sources"],accepted):
        proposed=decode_json(raw)
        originals=src["rows"]
        if len(proposed["items"])!=len(originals):
            raise Hold("mediation final source slots not complete")
        for before,choice in zip(originals,proposed["items"]):
            if (before["slot"]!=choice["slot"]
                    or any(choice["prior_"+field]!=before["prior_"+field]
                           for field in ("stage","next_role","review_date"))):
                raise Hold("human mediation no longer matches ORIGINAL prior choices")
            old=tuple(before["prior_"+k] for k in ("stage","next_role","review_date"))
            latest=tuple(choice[k] for k in ("stage","next_role","review_date"))
            candidates=before["candidates"]
            possibilities=[tuple(candidate[k] for k in ("stage","next_role","review_date"))
                           for candidate in candidates]
            if latest!=old and latest not in possibilities:
                raise Hold("human mediation introduced a value no contributor proposed")
            if latest!=old:
                modified+=1
            if len(candidates)>1:
                conflicts+=1
                contributors=[cand["contributor"] for cand,payload in zip(candidates,possibilities)
                              if payload==latest]
                decisions.append({
                    "agenda":src["slot"],"slot":before["slot"],
                    "disposition":"ORIGINAL_HUMAN_PRIOR" if latest==old
                                  else "HUMAN_SELECTED_SOURCE_PROPOSAL",
                    "matching_contributors":contributors
                })
    if conflicts!=source["conflict_slots"]:
        raise Hold("human contributor conflict membership changed")
    # The original strict return path re-checks all immutable originals and
    # every resolved prior/new human field before the new cycle is created.
    _verified_return,old_status,returned_count=original_return(
        workspace_path,manifests,choices,proposal_bundle_raw=resolved_raw)
    if returned_count!=modified or old_status!=source["claimed_status"]:
        raise Hold("resolved original human changes do not match original return")
    next_zip,new_status,next_count=build_next(
        workspace_path,manifests,choices,None,next_day,
        previous_capacity_path=previous_capacity,
        capacity_reconfirmed=reconfirmed_capacity,
        proposal_bundle_raw=resolved_raw)
    if next_count!=modified or new_status!=old_status:
        raise Hold("next human review cycle did not preserve resolved original source")
    if read_regular(resolved_path,4*1024*1024)!=resolved_raw:
        raise Hold("human-resolved proposal changed during source binding")
    summary={
        "schema":SCHEMA,
        "original_reference_date":source["reference_date"],
        "new_reference_date":next_day,
        "source_count":n,"contributor_count":source["contributor_count"],
        "contested_human_slots":conflicts,
        "proposed_human_changes":modified,
        "claimed_status":source["claimed_status"],
        "resolutions":decisions,
        "planning_not_permission":True,
        **{flag:False for flag in FLAGS}
    }
    output={
        "index.html":_html(decisions,old_status),
        "private-human-mediation-record.json":encode(summary),
        "resolved-original-human-proposals.json":resolved_raw,
        "new-private-human-review-cycle.zip":next_zip,
        "START-HERE.txt":(
            "LIGHTUP / PRIVATE ORIGINAL HUMAN MEDIATION RETURN / NO GO\n"
            "All human proposal selections matched original or contributing draft values.\n"
            "No reviewer identity/authentication, fix, grant or consent was proven.\n"
            "Open index.html for private human conflict disposition.\n"
            "The NEW complete offline human review cycle is nested in\n"
            "new-private-human-review-cycle.zip and retains original HOLD.\n"
            "Neither original manifests, choices, source ZIP nor contributor files changed.\n"
            "Keep original CI, independent review, actual revocable client/operator\n"
            "permission and HUMAN GO unchanged. No active targets/scans.\n"
        ).encode("utf-8")
    }
    return _zip(output),old_status,conflicts


def main(argv=None):
    p=argparse.ArgumentParser(description="Return human-resolved original portfolio conflicts and prepare next offline source-bound cycle; no GO")
    p.add_argument("--workspace",required=True)
    p.add_argument("--original-manifest",action="append",required=True)
    p.add_argument("--original-choices",action="append",required=True)
    p.add_argument("--proposal-bundle",action="append",required=True,help="Each independent original human contributor")
    p.add_argument("--resolved-bundle",required=True,help="One PRIVATE JSON exported after individual human mediation")
    p.add_argument("--next-as-of",required=True)
    p.add_argument("--previous-private-capacity-plan")
    p.add_argument("--reconfirm-human-capacity",action="store_true")
    p.add_argument("--output",required=True,help="NEW owner-private 0600 ZIP, no overwrite")
    a=p.parse_args(argv)
    try:
        result,status,conflicts=build(
            a.workspace,a.original_manifest,a.original_choices,a.proposal_bundle,
            a.resolved_bundle,a.next_as_of,a.previous_private_capacity_plan,
            a.reconfirm_human_capacity)
        publish(a.output,result)
        print(f"PRIVATE_HUMAN_MEDIATION_NEXT_CYCLE_CREATED contested_original_slots={conflicts} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("PRIVATE_HUMAN_MEDIATION_RETURN_HOLD — incompatible original contributor choices",
              file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
