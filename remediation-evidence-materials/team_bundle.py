#!/usr/bin/env python3
"""PRIVATE encrypted multi-recipient HUMAN desk continuity, original-source bound.

Seal an already original-authenticated 2–12 reply portfolio directly to an
owner-private encrypted .ltv with NO plaintext intermediate. Reopen only after
CURRENT original LightUp account/tenant/engagement READ with matching source
and attachment index. Original evidence file bytes are NEVER in the bundle.
"""
from __future__ import annotations

import argparse
from collections import Counter
from pathlib import Path
import sys

import reply
import team
import transfer

KIND="lightup.private_source_bound_human_material_team_bundle"
FLAGS=transfer.human.FLAGS
MAX_BUNDLE= 256 * 1024
FIELDS={
    "kind","schema_version","disposition","source_contract","source_sha256",
    "source_csv_sha256","source_count","client_reference",
    "engagement_reference","inventory_sha256","packet_count","human_items",
    "warning",*FLAGS
}
ITEM={"packet","finding_id","sha256","human_stage","human_reviewer","human_note","recorded_utc"}
WARNING=("Encrypted local HUMAN multi-recipient review is not a signed reviewer "
         "identity, true evidence provenance, vulnerability finding, fixed system, "
         "authorized scan, verified retest, client consent or release.")


def packet_from_current(meta: dict, human: dict, rows: list[dict]) -> bytes:
    if not 2 <= len({r["packet"] for r in rows}) <= team.MAX_PAIRS or (
            len(rows) > team.MAX_ITEMS):
        raise ValueError("Human portfolio packet membership incomplete or oversized.")
    obj={
        "kind":KIND,"schema_version":1,
        "disposition":"PRIVATE_HUMAN_TEAM_REVIEW_NOT_VERIFIED",
        "source_contract":"lightup.finding_export._COLUMNS_v1",
        "source_sha256":human["source_sha256"],
        "source_csv_sha256":meta["original_csv_sha256"],
        "source_count":human["source_count"],
        "client_reference":human["client_reference"],
        "engagement_reference":human["engagement_reference"],
        "inventory_sha256":transfer.digest(transfer.canonical(human["attachments"])),
        "packet_count":len({r["packet"] for r in rows}),
        "human_items":rows,
        "warning":WARNING,
        **{field:False for field in FLAGS},
    }
    raw=transfer.canonical(obj)
    if len(raw)>MAX_BUNDLE:
        raise ValueError("PRIVATE HUMAN team bundle exceeds original bounded limit.")
    return raw


def admit(raw: bytes, meta: dict, human: dict, indexed: dict) -> list[dict]:
    obj=transfer.human._json(raw,MAX_BUNDLE)
    if (set(obj)!=FIELDS or transfer.canonical(obj)!=raw
            or obj.get("kind")!=KIND
            or type(obj.get("schema_version")) is not int or obj["schema_version"]!=1
            or obj.get("disposition")!="PRIVATE_HUMAN_TEAM_REVIEW_NOT_VERIFIED"
            or obj.get("source_contract")!="lightup.finding_export._COLUMNS_v1"
            or obj.get("source_sha256")!=human["source_sha256"]
            or obj.get("source_csv_sha256")!=meta["original_csv_sha256"]
            or type(obj.get("source_count")) is not int
            or obj["source_count"]!=human["source_count"]
            or obj.get("client_reference")!=human["client_reference"]
            or obj.get("engagement_reference")!=human["engagement_reference"]
            or obj.get("inventory_sha256")!=transfer.digest(
                 transfer.canonical(human["attachments"]))
            or obj.get("warning")!=WARNING
            or any(obj[flag] is not False for flag in FLAGS)):
        raise ValueError("Encrypted HUMAN team bundle is not bound to CURRENT original source.")
    rows=obj["human_items"]
    if type(rows) is not list or not 2<=len(rows)<=team.MAX_ITEMS:
        raise ValueError("Invalid original encrypted HUMAN team rows.")
    packets=set()
    per_packet=Counter()
    keys=set()
    for row in rows:
        if type(row) is not dict or set(row)!=ITEM:
            raise ValueError("Invalid original HUMAN team item structure.")
        if type(row["packet"]) is not int or not 1<=row["packet"]<=team.MAX_PAIRS:
            raise ValueError("HUMAN team input ordinals invalid.")
        if any(type(row[k]) is not str for k in ITEM-{"packet"}):
            raise ValueError("HUMAN team item fields must be exact text.")
        if row["human_stage"] not in reply.STAGES:
            raise ValueError("Unknown HUMAN-only receipt status.")
        # Preserve the exact original recipient canonical HUMAN text contract.
        # Escaped HTML alone is not adequate input admission for portable vaults.
        reply._human_text(row["human_reviewer"],reply.MAX_LABEL,"reviewer")
        reply._human_text(row["human_note"],reply.MAX_NOTE,"note")
        transfer.native._stamp(row["recorded_utc"])
        key=(row["finding_id"],row["sha256"])
        if key not in indexed:
            raise ValueError("HUMAN team row no longer matches original file inventory.")
        uniqueness=(row["packet"],*key)
        if uniqueness in keys:
            raise ValueError("Repeated identical original HUMAN packet/file identity.")
        keys.add(uniqueness)
        packets.add(row["packet"])
        per_packet[row["packet"]]+=1
        if per_packet[row["packet"]]>transfer.MAX_FILES:
            raise ValueError("Encrypted team packet has more HUMAN files than native source allows.")
    if (type(obj["packet_count"]) is not int or not 2<=obj["packet_count"]<=team.MAX_PAIRS
        or sorted(packets)!=list(range(1,obj["packet_count"]+1))):
        raise ValueError("HUMAN team portfolio packet membership not complete.")
    return rows


def seal(args,vault):
    original_key_fingerprints=set()
    meta,human,originals,rows=team.collect(args,vault,
                        key_fingerprints=original_key_fingerprints)
    indexed=transfer.native._records(human,transfer._current_rows(
        transfer.human._unb64(meta["original_csv_base64"],transfer.ORIGINAL.MAX_CSV_BYTES)))["attachments"]
    raw=packet_from_current(meta,human,rows)
    admit(raw,meta,human,indexed)
    destination=args.output.expanduser().absolute()
    reserved={args.human.expanduser().absolute(),
              *(v.expanduser().absolute() for v in args.transfer),
              *(v.expanduser().absolute() for v in args.reply)}
    if destination.suffix.lower()!=".ltv" or destination in reserved:
        raise ValueError("NEW distinct encrypted private team bundle .ltv required.")
    password=vault._password("NEW PRIVATE HUMAN team bundle passphrase: ",fresh=True)
    if transfer.digest(password) in original_key_fingerprints:
        raise ValueError("Encrypted HUMAN team bundle needs a distinct passphrase from every original source and reply.")
    vault._exclusive_output(destination,vault._seal(vault._inner(raw,"application/json"),password))
    print("Created NEW 0600 source-bound encrypted PRIVATE HUMAN team .ltv.")
    print("Human-only source-bound packets:",len({r["packet"] for r in rows}),
          "; reviewer status conflicts:",team.overview(originals,rows)["human_conflict_findings"])
    print("No plaintext source data, original evidence file bytes or browser HTML stored.")


def current_bundle(args,vault) -> tuple:
    """Source reauthentication and native HUMAN + encrypted team admission once.

    Other tools can consume the admitted HUMAN notes without any original
    materials or replies, never as a grant, verified fix or signed source.
    """
    meta,human,indexed,original_key_hash=reply._source(args,vault)
    originals=team.inbox._source_rows(meta,transfer.ORIGINAL)
    original=transfer.required_private_file(args.input,".ltv",vault,vault.MAX_VAULT)
    password=vault._password("Existing PRIVATE HUMAN team bundle passphrase: ",fresh=False)
    plain,mime,_=vault._open(original,password)
    if mime!="application/json":
        raise ValueError("Original encrypted PRIVATE team content type invalid.")
    rows=admit(plain,meta,human,indexed)
    return meta,human,originals,rows,(original_key_hash,transfer.digest(password))


def rehydrate(args,vault):
    meta,human,originals,rows,_=current_bundle(args,vault)
    summary=team.overview(originals,rows)
    print("CURRENT ORIGINAL-SOURCE BOUND PRIVATE HUMAN TEAM BUNDLE")
    print("Human receipt packets:",summary["packet_count"])
    print("Human conflict findings:",summary["human_conflict_findings"])
    if args.action=="inspect":
        print("HUMAN counts only. No private HTML generated.")
        return
    page=team.render(originals,rows,summary)
    team.publish(args.output_dir,vault,page,summary)
    print("Created NEW private owner-only 0700 HTML + anonymous counts directory.")
    print("Original source labels/reviewer notes stay inside 0600 offline HTML.")
    print("No original Apply, scan, consent, verified security result or remediation.")


def main(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="action",required=True)
    for action in ("seal","open-current","inspect"):
        cmd=sub.add_parser(action)
        for name in ("db","email","client-id","engagement-id"):
            cmd.add_argument("--"+name,required=True)
        cmd.add_argument("--human",type=Path,required=True)
        if action=="seal":
            cmd.add_argument("--transfer",type=Path,action="append",required=True)
            cmd.add_argument("--reply",type=Path,action="append",required=True)
            cmd.add_argument("--output",type=Path,required=True)
        else:
            cmd.add_argument("--input",type=Path,required=True)
            if action=="open-current":
                cmd.add_argument("--output-dir",type=Path,required=True)
        cmd.add_argument("--ack-private-team",action="store_true")
    args=p.parse_args(argv)
    try:
        if not args.ack_private_team or not sys.stdin.isatty():
            raise ValueError("PRIVATE HUMAN bundle requires explicit acknowledgement and private TTY.")
        vault=transfer.ORIGINAL._vault()
        (seal if args.action=="seal" else rehydrate)(args,vault)
        return 0
    except Exception:
        print("HUMAN HOLD: no original-current source-bound encrypted HUMAN team operation "
              "completed; no original HUMAN records, scans or permissions changed.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
