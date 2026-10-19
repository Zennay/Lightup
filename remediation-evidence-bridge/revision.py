#!/usr/bin/env python3
"""Safely carry source-identical HUMAN work through an authenticated source revision.

A revised source is not remediation proof. Old encrypted history stays untouched;
changed/absent finding notes remain in that old source rather than being promoted.
"""
from __future__ import annotations

import argparse
import csv
import io
import importlib.util
import json
from pathlib import Path
import sys

SPEC=importlib.util.spec_from_file_location("_lightup_human_workspace",Path(__file__).with_name("workspace.py"))
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Original PRIVATE HUMAN workspace module missing.")
work=importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(work)
bridge=work.bridge


def _rows(raw: bytes) -> dict[str,dict[str,str]]:
    bridge.original._strict_summary(raw.decode("utf-8","strict"))
    it=csv.DictReader(io.StringIO(raw.decode("utf-8","strict"),newline=""),strict=True)
    if tuple(it.fieldnames or ())!=bridge.original.COLUMNS:
        raise ValueError("Unexpected original-source columns.")
    source={}
    for row in it:
        if None in row or row.get(None) is not None:
            raise ValueError("Invalid original-source row.")
        key=row["finding_id"]
        if key in source:
            raise ValueError("Duplicate original finding identity.")
        source[key]=row
    return source


def _summarize(old: dict[str,dict], new: dict[str,dict]) -> tuple[set[str],dict[str,int]]:
    identical={key for key in old.keys()&new.keys() if old[key]==new[key]}
    diff={
        "unchanged":len(identical),
        "changed":len((old.keys()&new.keys())-identical),
        "absent_from_new_source":len(old.keys()-new.keys()),
        "new_source_findings":len(new.keys()-old.keys())
    }
    return identical,diff


def _rebuild_human(old_packet: dict, keep: set[str], new_raw: bytes, old_ids: set[str]) -> tuple[bytes,dict[str,int]]:
    new_source=_rows(new_raw)
    source_digest,count=work._native_digest(new_raw)
    old_casework=old_packet["casework"]
    if old_casework is not None:
        old_cases={row["finding_id"]:row for row in old_casework}
        if len(old_cases)!=len(old_casework) or set(old_cases)!=old_ids:
            raise ValueError("Original HUMAN Casework source membership incomplete or ambiguous.")
        retained=[]
        for finding_id in new_source:
            if finding_id in keep and finding_id in old_cases:
                retained.append(old_cases[finding_id])
            else:
                retained.append({
                    "finding_id":finding_id, "owner":"", "status":"unassigned",
                    "due_date":None, "next_action":"", "verification_plan":"",
                    "blocker":"", "note":"", "updated_utc":None
                })
    else:
        retained=None
    attachments=old_packet["attachments"]
    if any(type(row) is not dict or type(row.get("finding_id")) is not str for row in attachments):
        raise ValueError("Malformed previous evidence attachment identity.")
    if any(row["finding_id"] not in old_ids for row in attachments):
        raise ValueError("Original PRIVATE artifact references an unknown finding.")
    new_attachments=[row for row in attachments if row["finding_id"] in keep]
    requests=old_packet.get("human_requests",[])
    if type(requests) is not list or any(type(row) is not dict or
                                      type(row.get("finding_id")) is not str for row in requests):
        raise ValueError("Malformed previous HUMAN request identity.")
    if any(row["finding_id"] not in old_ids for row in requests):
        raise ValueError("Original PRIVATE HUMAN request references an unknown finding.")
    old_request_ids=[row.get("request_id") for row in requests]
    if len(set(old_request_ids))!=len(old_request_ids):
        raise ValueError("Repeated original HUMAN request identity.")
    evidence=old_packet["evidence_review"]
    if evidence is not None and (type(evidence) is not list or
        {item.get("finding_id") for item in evidence if type(item) is dict}!=old_ids):
        raise ValueError("Incomplete original Evidence Review membership.")
    kept_requests=[row for row in requests if row["finding_id"] in keep]
    next_packet={
        "kind":"lightup.private_unified_human_evidence_workspace",
        "schema_version":2,
        "disposition":"PRIVATE_HUMAN_REVIEW_ONLY",
        "source_contract":"lightup.finding_export._COLUMNS_v1",
        "source_sha256":source_digest,
        "source_count":count,
        "client_reference":old_packet["client_reference"],
        "engagement_reference":old_packet["engagement_reference"],
        "casework":retained,
        # Old evidence review is source-snapshot-wide: never treat it as a new-source review.
        "evidence_review":None,
        "attachments":new_attachments,
        "human_requests":kept_requests,
        "warning":"Source-revision HUMAN carry ONLY for identical complete original rows. "
                  "Changed/absent original HUMAN history stays in preserved old encrypted .ltv. "
                  "New or changed Casework stays UNASSIGNED. Original Evidence Review is detached. "
                  "No verified finding, remediation, retest, grant, consent, scan or release.",
        **{flag:False for flag in work.FLAGS}
    }
    data=json.dumps(next_packet,ensure_ascii=False,separators=(",",":")).encode("utf-8")
    work._packet(data,source_digest=source_digest,count=count,
                 client=old_packet["client_reference"],engagement=old_packet["engagement_reference"])
    return data,{
        "local_artifacts_retained":len(new_attachments),
        "local_artifacts_held_in_original":len(attachments)-len(new_attachments),
        "human_requests_retained":len(kept_requests),
        "human_requests_held_in_original":len(requests)-len(kept_requests),
        "human_casework_retained":len(keep) if old_casework is not None else 0,
        "old_evidence_review_detached":int(old_packet["evidence_review"] is not None)
    }


def main(argv: list[str]|None=None) -> int:
    ap=argparse.ArgumentParser(description=__doc__)
    mode=ap.add_subparsers(dest="mode",required=True)
    for name in ("preview","carry"):
        p=mode.add_parser(name)
        p.add_argument("--input",required=True,type=Path,help="Original encrypted HUMAN source/workspace .ltv")
        p.add_argument("--db",required=True)
        p.add_argument("--email",required=True)
        p.add_argument("--client-id",required=True)
        p.add_argument("--engagement-id",required=True)
        if name=="carry":
            p.add_argument("--output",required=True,type=Path)
            p.add_argument("--ack-preserve-original",required=True,action="store_true",
                help="I will retain my original encrypted source and manually review the proposed new workspace.")
    args=ap.parse_args(argv)
    try:
        if args.input.suffix.lower()!=".ltv":
            raise ValueError("Original encrypted HUMAN source required.")
        if args.mode=="carry" and (
            args.output.suffix.lower()!=".ltv" or
            args.output.expanduser().absolute()==args.input.expanduser().absolute()
        ):
            raise ValueError("Carry requires a NEW non-overwriting private .ltv output.")
        # The revised original source is read only through the original real auth/tenant boundary.
        current=bridge.original._authorized_summary(db=args.db,email=args.email,
            client_id=args.client_id,engagement_id=args.engagement_id)
        new_raw=current.encode("utf-8","strict")
        vault=bridge.original._vault()
        old_ciphertext=vault._private_input(args.input.expanduser().absolute(),vault.MAX_VAULT)
        old_secret=vault._password("Previous encrypted HUMAN source passphrase: ",fresh=False)
        encoded,mime,_=vault._open(old_ciphertext,old_secret)
        if mime!="application/json":
            raise ValueError("Unsupported HUMAN source vault.")
        manifest,old_raw,old_human=work._admit_workspace(encoded)
        if (manifest["client_reference"]!=args.client_id or
                manifest["engagement_reference"]!=args.engagement_id):
            raise ValueError("Current account context not bound to previous private HUMAN source.")
        old_source=_rows(old_raw)
        new_source=_rows(new_raw)
        if old_raw==new_raw:
            raise ValueError("Same exact source bytes; no revision carry required.")
        identical,changes=_summarize(old_source,new_source)
        old_packet=work._packet(old_human,source_digest=work._native_digest(old_raw)[0],
                                count=len(old_source),client=args.client_id,engagement=args.engagement_id)
        updated,counts=_rebuild_human(old_packet,identical,new_raw,set(old_source))
        # Aggregate-only human review preview; never expose source IDs, names or hashes.
        for label,value in {**changes,**counts}.items():
            print(label.replace("_"," ")+":",value)
        print("HOLD: Original source labels are unverified. Changed/absent HUMAN records are NOT fixed.")
        print("Retain the OLD encrypted source indefinitely unless independently archived and approved.")
        if args.mode=="preview":
            print("No new file created. Carry requires separate explicit operator choice.")
            return 0
        packed=work._make_workspace(new_raw,updated,args.client_id,args.engagement_id)
        new_secret=vault._password("New revised PRIVATE HUMAN workspace passphrase: ",fresh=True)
        vault._exclusive_output(args.output.expanduser().absolute(),
                                vault._seal(vault._inner(packed,"application/json"),new_secret))
        print("New source-bound encrypted HUMAN workroom created: safe SAME-ROW carry only.")
        print("Previous encrypted source and original HUMAN history preserved as independent file.")
        return 0
    except Exception:
        print("HOLD: No source-revision HUMAN carry performed. Review original account, exact source and private archive.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
