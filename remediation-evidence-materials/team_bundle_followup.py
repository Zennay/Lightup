#!/usr/bin/env python3
"""Stage ORIGINAL HUMAN draft follow-up from an encrypted source-bound TEAM bundle.

Recipient needs its own genuine present LightUp account/engagement read and a
matching original encrypted HUMAN file index. The original evidence bytes and
historical recipient transfers/replies are NOT needed to draft HUMAN questions.
Only the original native Ledger's separate Preview+manual Apply may restore.
"""
from __future__ import annotations

import argparse
from pathlib import Path
import sys

import team_bundle
import team_followup
import transfer


def operate(args, vault) -> int:
    meta, original, originals, rows, old_key_hashes=team_bundle.current_bundle(args,vault)
    candidates,counts=team_followup.proposals(original,rows)
    print("CURRENT SOURCE-BOUND ENCRYPTED TEAM → ORIGINAL HUMAN REQUEST DESK")
    for key,value in counts.items():
        print(key.replace("_"," ")+":",value)
    print("HUMAN-only source labels and conflict notes. Never a security or identity verdict.")
    if args.action=="preview":
        print("HUMAN PREVIEW ONLY: no original workspace changed or published.")
        return 0
    if not candidates:
        raise ValueError("No safe independent original HUMAN follow-up is available.")
    answer=input('Type "STAGE SEALED TEAM FOLLOWUP" to create NEW encrypted native HUMAN drafts: ')
    if answer!="STAGE SEALED TEAM FOLLOWUP":
        raise ValueError("Operator did not affirm original HUMAN draft-only operation.")
    source=transfer.human._unb64(meta["original_csv_base64"],
                                 transfer.ORIGINAL.MAX_CSV_BYTES)
    new_packet=dict(original)
    new_packet["schema_version"]=2
    new_packet["human_requests"]=[*original.get("human_requests",[]),*candidates]
    ids=transfer._current_rows(source)
    transfer.native._records(new_packet,ids)
    body=transfer.canonical(new_packet)
    native_container=transfer.human._make_workspace(
        source,body,new_packet["client_reference"],new_packet["engagement_reference"])
    output=args.output.expanduser().absolute()
    if output.suffix.lower()!=".ltv" or output in {
            args.human.expanduser().absolute(),args.input.expanduser().absolute()}:
        raise ValueError("NEW distinct owner-private encrypted HUMAN workspace required.")
    password=vault._password("NEW PRIVATE team-to-original-HUMAN staging passphrase: ",fresh=True)
    if transfer.digest(password) in old_key_hashes:
        raise ValueError("New original-HUMAN draft vault passphrase must differ from existing encrypted sources.")
    protected=vault._seal(vault._inner(native_container,"application/json"),password)
    vault._exclusive_output(output,protected)
    print("Created NEW original-compatible source-bound PRIVATE encrypted HUMAN workspace.")
    print("Added original HUMAN draft questions:",len(candidates))
    print("Previous Casework, Evidence Review, artifact index and human requests preserved verbatim.")
    print("Unchanged original browser separately requires human Preview and manual Apply.")
    print("No target, grant, client consent, confirmed vulnerability, remediation or retest.")
    return 0


def main(argv: list[str] | None=None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    sub=p.add_subparsers(dest="action",required=True)
    for action in ("preview","stage"):
        cmd=sub.add_parser(action)
        for name in ("db","email","client-id","engagement-id"):
            cmd.add_argument("--"+name,required=True)
        cmd.add_argument("--human",type=Path,required=True,
                         help="CURRENT original source-bound private HUMAN .ltv")
        cmd.add_argument("--input",type=Path,required=True,
                         help="Existing original-encrypted PRIVATE multi-recipient team bundle .ltv")
        if action=="stage":
            cmd.add_argument("--output",type=Path,required=True,
                             help="NEW encrypted native ORIGINAL HUMAN workspace with draft requests")
        cmd.add_argument("--ack-private-team-followup",action="store_true")
    args=p.parse_args(argv)
    try:
        if not args.ack_private_team_followup or not sys.stdin.isatty():
            raise ValueError("Explicit private HUMAN acknowledgement and terminal required.")
        return operate(args,transfer.ORIGINAL._vault())
    except Exception:
        print("HUMAN HOLD: no original HUMAN data, authority or evidence changed. "
              "Require current authenticated source and exact original encrypted team packet.",
              file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
