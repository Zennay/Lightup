#!/usr/bin/env python3
"""Return an edited offline human proposal to ORIGINAL archive follow-up choices.

This is not client authorization, remediation evidence or a target executor.
"""
from __future__ import annotations
import argparse
from hashlib import sha256
from pathlib import Path
import sys

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "assessment-archive"))
from archive import (FLAGS, Hold, MAX_MANIFEST, decode_json, encode,
                     publish, read_regular, reject_authority)
from followup import (CHOICES_SCHEMA, STAGES, ROLES, _validate_date,
                      manifest_identity, load_choices)
from portfolio import load_one, MAX_BYTES

SCHEMA="lightup.assessment_portfolio_human_proposal.v1"
FIELDS={"schema","source_agenda_sha256","reference_date","source_count",
        "items",*FLAGS}
ROW_FIELDS={"slot","prior_stage","prior_next_role","prior_review_date",
            "stage","next_role","review_date"}

def reconcile(manifest_path, choices_path, agenda_path, proposal_path, *, agenda_raw=None, proposal_raw=None):
    # Original validators handle immutable source membership and manifest binding.
    original,manifest_fingerprint=manifest_identity(manifest_path)
    choices=load_choices(choices_path, original, manifest_fingerprint)
    if agenda_raw is None:
        agenda_raw=read_regular(agenda_path,MAX_BYTES)
    elif type(agenda_raw) is not bytes or not 0 < len(agenda_raw) <= MAX_BYTES:
        raise Hold("invalid original in-memory agenda")
    agenda_document=decode_json(agenda_raw)
    if type(agenda_document) is not dict or type(agenda_document.get("reference_date")) is not str:
        raise Hold("agenda missing original day")
    agenda=load_one(agenda_path,agenda_document["reference_date"],raw=agenda_raw)
    if proposal_raw is None:
        proposal_raw=read_regular(proposal_path,MAX_BYTES)
    elif type(proposal_raw) is not bytes or not 0 < len(proposal_raw) <= MAX_BYTES:
        raise Hold("invalid private in-memory proposal")
    proposed=decode_json(proposal_raw)
    reject_authority(proposed)
    if (type(proposed) is not dict or set(proposed)!=FIELDS
            or proposed["schema"]!=SCHEMA
            or type(proposed["source_agenda_sha256"]) is not str
            or proposed["source_agenda_sha256"]!=sha256(agenda_raw).hexdigest()
            or proposed["reference_date"]!=agenda_document["reference_date"]
            or type(proposed["source_count"]) is not int
            or proposed["source_count"]!=len(choices)
            or type(proposed["items"]) is not list
            or len(proposed["items"])!=len(choices)
            or len(agenda["rows"])!=len(choices)
            or agenda["status"]!=original["status"]
            or any(proposed[flag] is not False for flag in FLAGS)):
        raise Hold("original source/proposal mismatch")
    updates={}
    for item in proposed["items"]:
        if type(item) is not dict or set(item)!=ROW_FIELDS:
            raise Hold("unrecognized human update field")
        slot=item["slot"]
        if type(slot) is not int or slot in updates or not 1<=slot<=len(choices):
            raise Hold("ambiguous human source slot")
        updates[slot]=item
    if set(updates)!=set(range(1,len(choices)+1)):
        raise Hold("incomplete original human source membership")
    # Original agenda.py sorts rows by human priority/date; source membership is
    # keyed by immutable original slot, NEVER by display/priority list order.
    source_rows={item["slot"]:item for item in agenda["rows"]}
    fresh=[]
    changed=0
    for row, prior in zip(original["entries"],choices):
        slot=row["slot"]
        source_row=source_rows[slot]
        item=updates[slot]
        if (source_row["slot"]!=slot
                or source_row["source_kind"]!=row["kind"]
                or source_row["stage"]!=prior["stage"]
                or source_row["next_role"]!=prior["next_role"]
                or source_row["review_date"]!=prior["review_date"]
                or item["prior_stage"]!=prior["stage"]
                or item["prior_next_role"]!=prior["next_role"]
                or item["prior_review_date"]!=prior["review_date"]
                or type(item["stage"]) is not str or item["stage"] not in STAGES
                or type(item["next_role"]) is not str or item["next_role"] not in ROLES):
            raise Hold("stale or invalid human review proposal")
        _validate_date(item["review_date"])
        values={"stage":item["stage"],"next_role":item["next_role"],
                "review_date":item["review_date"]}
        changed+=int(any(values[key]!=prior[key] for key in values))
        fresh.append({"slot":slot,"source_sha256":row["sha256"],**values})
    document={"schema":CHOICES_SCHEMA,"manifest_sha256":manifest_fingerprint,
              "items":fresh,**{f:False for f in FLAGS}}
    return encode(document),original["status"],changed

def main(argv=None):
    p=argparse.ArgumentParser(description="Human-only private portfolio proposal return to ORIGINAL follow-up schema")
    p.add_argument("--original-manifest",required=True)
    p.add_argument("--original-choices",required=True)
    p.add_argument("--original-agenda",required=True)
    p.add_argument("--proposal",required=True,help="Private proposal exported from local Studio")
    p.add_argument("--output",required=True,help="NEW original-schema human choices file, no overwrite")
    args=p.parse_args(argv)
    try:
        result,state,changed=reconcile(args.original_manifest,args.original_choices,
                                        args.original_agenda,args.proposal)
        publish(args.output,result)
        print(f"ORIGINAL_SOURCE_BOUND_HUMAN_CHOICES_CREATED changed_human_slots={changed} — NO GO")
        return 3 if state=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("HUMAN_PROPOSAL_HOLD — changed or incompatible original human sources",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
