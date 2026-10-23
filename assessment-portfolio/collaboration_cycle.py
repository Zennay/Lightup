#!/usr/bin/env python3
"""One-command multi-contributor human review -> next original offline workspace.

Only a separate private atomic ZIP is created; no original source is mutated.
"""
from __future__ import annotations
import argparse
from io import BytesIO
from zipfile import ZipFile
import sys

from portfolio import Hold, decode_json, encode, publish, FLAGS
from portfolio_merge import build as merge_independent_bundles
from review_cycle import build as create_next_human_cycle
from multi_return import _zip

SCHEMA="lightup.assessment_portfolio_collaborative_human_cycle.v1"


def build(workspace, manifests, choices, bundles, next_reference,
          previous_capacity=None, reconfirm_capacity=False):
    # Admission of every independent human contributor and every ORIGINAL
    # source occurs before the next independent original revision is generated.
    previous_blob,previous_state,source_edits = merge_independent_bundles(
        workspace,manifests,choices,bundles)
    with ZipFile(BytesIO(previous_blob),"r") as z:
        proposal_raw=z.read("merged-private-all-human-proposals.json")
        merged_source_manifest=z.read("private-collaboration-manifest.json")
        human_overview=z.read("index.html")
    changed,overall,new_total=create_next_human_cycle(
        workspace,manifests,choices,None,next_reference,
        previous_capacity_path=previous_capacity,
        capacity_reconfirmed=reconfirm_capacity,
        proposal_bundle_raw=proposal_raw)
    if overall!=previous_state or new_total!=source_edits:
        raise Hold("original human source merge / next revision disagreement")
    manifest=decode_json(merged_source_manifest)
    summary={
        "schema":SCHEMA,
        "original_reference_date":manifest["original_reference_date"],
        "next_reference_date":next_reference,
        "source_count":manifest["source_count"],
        "contributor_count":manifest["contributor_count"],
        "changed_human_slots":source_edits,
        "claimed_status":previous_state,
        "includes_hypothetical_capacity":previous_capacity is not None,
        "planning_not_permission":True,
        **{f:False for f in FLAGS}
    }
    output={
        "index.html":human_overview,
        "merged-private-all-human-proposals.json":proposal_raw,
        "private-collaboration-manifest.json":merged_source_manifest,
        "new-private-human-review-cycle.zip":changed,
        "private-cycle-bridge.json":encode(summary),
        "START-HERE.txt":(
            "LIGHTUP / ORIGINAL PRIVATE MULTI-REVIEWER HUMAN NEXT CYCLE / NO GO\n"
            "Open index.html for disjoint changed human planning slot contributions.\n"
            "new-private-human-review-cycle.zip includes a ready NEXT complete offline\n"
            "workspace, NEW original-schema human choices, source-neutral history\n"
            "comparison and optional separately reconfirmed hypothetical capacity.\n"
            "Extract NEXT human-workspace.zip from inside the next-cycle ZIP to\n"
            "open workspace-home.html. No original manifests or files were altered.\n"
            "merged-private-all-human-proposals.json can be restored in the\n"
            "old original Review Studio; unverified human changes do not grant consent.\n"
            "No conflict was automatically resolved: overlapping original human slots HOLD.\n"
            "Contributor numbers are not authenticated identities.\n"
            "Retain original source-owner, independent security/privacy,\n"
            "exact-head CI, real client/operator at-use revocable consent and HUMAN GO.\n"
            "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.\n"
        ).encode("utf-8")
    }
    return _zip(output),overall,source_edits


def main(argv=None):
    p=argparse.ArgumentParser(
        description="One private collaborative original human review -> new offline workspace; NO GO")
    p.add_argument("--workspace",required=True)
    p.add_argument("--original-manifest",action="append",required=True)
    p.add_argument("--original-choices",action="append",required=True)
    p.add_argument("--proposal-bundle",action="append",required=True,
                   help="Independent original full human proposal bundle, 2–12")
    p.add_argument("--next-as-of",required=True,
                   help="Explicit human-only date for next source-bound review")
    p.add_argument("--previous-private-capacity-plan",
                   help="Optional previous original-bound hypothetical role capacity")
    p.add_argument("--reconfirm-human-capacity",action="store_true",
                   help="Required alongside previous role plan: independent human reconfirmation")
    p.add_argument("--output",required=True,help="NEW private 0600 ZIP; never overwrite")
    args=p.parse_args(argv)
    try:
        result,status,changed=build(
            args.workspace,args.original_manifest,args.original_choices,
            args.proposal_bundle,args.next_as_of,args.previous_private_capacity_plan,
            args.reconfirm_human_capacity)
        publish(args.output,result)
        print(f"PRIVATE_COLLABORATIVE_ORIGINAL_HUMAN_REVIEW_CYCLE_CREATED changes={changed} — NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("COLLABORATIVE_HUMAN_REVIEW_HOLD — invalid original sources or overlapping human changes",
              file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
