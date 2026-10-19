#!/usr/bin/env python3
"""Authenticated private, multi-recipient HUMAN material collaboration desk.

Reads 2–12 distinct original encrypted evidence-transfer/recipient-reply pairs,
compares them against ONE original current tenant/engagement source and intact
HUMAN attachment inventory, then creates a PRIVATE offline conflict desk.
No scan, grant, native Apply, verified finding, remediation or retest.
"""
from __future__ import annotations

import argparse
from collections import Counter, defaultdict
import base64
import hashlib
import html
import json
import os
from pathlib import Path
import stat
import sys

import inbox
import reply
import transfer

MAX_PAIRS = 12
MAX_ITEMS = MAX_PAIRS * transfer.MAX_FILES
MAX_HTML = 900_000
STAGES = ("human_hold", "needs_human_followup", "received_unverified")
STAGE_NAME = {
    "human_hold": "HUMAN HOLD",
    "needs_human_followup": "Needs HUMAN follow-up",
    "received_unverified": "Received but unverified",
}
SEVERITY = {"critical":0, "high":1, "medium":2, "low":3, "info":4}
CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;color:#17243a;background:#f3f6fb}
*{box-sizing:border-box}body{margin:0}header{background:#152b47;color:white;padding:32px 20px}
header>div,main{max-width:1150px;margin:auto}main{padding:22px 20px 70px}
h1{margin:5px 0 10px;font-size:clamp(25px,4vw,42px)}h2{margin:20px 0 10px}
p{line-height:1.55}.eyebrow{font-size:12px;font-weight:800;letter-spacing:.16em;color:#86dad0}
.notice{padding:17px;border:1px solid #c4a174;border-radius:10px;background:#fff7e9}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(168px,1fr));gap:12px;margin:20px 0}
.metric{background:white;border:1px solid #d2dce7;border-radius:12px;padding:15px}
.metric b{display:block;font-size:28px}.metric small{font-size:12px;color:#4e5e72}
nav{display:flex;flex-wrap:wrap;gap:10px;margin:15px 0}
nav a{border-radius:10px;padding:10px 12px;background:#e4eefd;text-decoration:none;color:#184f82;font-weight:700}
details{border:1px solid #c6d3e0;background:white;border-radius:12px;margin:11px 0;overflow:hidden}
summary{cursor:pointer;padding:18px;font-weight:800;background:#eaf0f9;overflow-wrap:anywhere}
.entry{padding:15px 18px;border-top:1px solid #d7e0ea}
.entry h3{margin:0 0 10px;font-size:16px}.meta{display:flex;flex-wrap:wrap;gap:8px;margin:10px 0}
.meta span{font-size:12px;color:#334c64;background:#f1f5fa;border-radius:8px;padding:6px 9px;overflow-wrap:anywhere}
blockquote{background:#f2f6fb;border-left:4px solid #6a8cae;margin:12px 0 0;padding:12px;white-space:pre-wrap;overflow-wrap:anywhere;line-height:1.55}
.warn{color:#834d12}.section{padding-top:12px}
footer{border-top:1px solid #ccd8e2;margin-top:25px;padding-top:18px;color:#536579}
@media print{header{background:white;color:black}nav{display:none}details{break-inside:avoid}}
"""


def _escape(v: object) -> str:
    return html.escape(str(v), quote=True)


def _pairs(args) -> list[tuple[Path, Path]]:
    if len(args.transfer) != len(args.reply) or not 2 <= len(args.reply) <= MAX_PAIRS:
        raise ValueError("Require two to twelve matching PRIVATE transfer/reply pairs.")
    selected = []
    seen_transfer, seen_reply = set(), set()
    source = args.human.expanduser().absolute()
    for a,b in zip(args.transfer,args.reply,strict=True):
        a,b = a.expanduser().absolute(),b.expanduser().absolute()
        if a==b or a==source or b==source or b in seen_reply:
            raise ValueError("Duplicate or aliased original PRIVATE material/return path.")
        if a.suffix.lower()!=".ltv" or b.suffix.lower()!=".ltv":
            raise ValueError("Original encrypted material and recipient replies require .ltv.")
        seen_transfer.add(a)
        seen_reply.add(b)
        selected.append((a,b))
    return selected


def collect(args, vault) -> tuple[dict, dict, dict, list[dict]]:
    pairs=_pairs(args)
    meta,packet,indexed,_=reply._source(args,vault)
    originals=inbox._source_rows(meta,transfer.ORIGINAL)
    all_entries=[]
    seen_responses=set()
    for index,(material_path, reply_path) in enumerate(pairs, 1):
        # reuse original native source + cryptographic material/return binding;
        # only the current receiver's packet and sender-readable source counts
        # are used; raw original evidence bytes are never written here.
        local=argparse.Namespace(transfer=material_path)
        plaintext,files,material_key=reply._transfer(local,vault,meta,packet)
        ciphertext=transfer.required_private_file(reply_path,".ltv",vault,vault.MAX_VAULT)
        key=vault._password(f"PRIVATE HUMAN response #{index} passphrase: ",fresh=False)
        returned,mime,_=vault._open(ciphertext,key)
        if mime!="application/json":
            raise ValueError("Original recipient HUMAN reply is not private JSON.")
        rows=reply._reply_packet(returned,plaintext,files,meta,packet)
        pair_id=(transfer.digest(plaintext),transfer.digest(returned))
        if pair_id in seen_responses:
            raise ValueError("Identical source-bound HUMAN reply submitted twice.")
        seen_responses.add(pair_id)
        for row in rows:
            # Keep per-packet separate HUMAN decisions. No majority voting,
            # false collective signoff, recipient identity claim or auto-merge.
            if row["finding_id"] not in originals:
                raise ValueError("Unknown original finding in private HUMAN reply.")
            all_entries.append({**row,"packet":index})
        if len(all_entries)>MAX_ITEMS:
            raise ValueError("Private source-bound collaborative replies exceed bound.")
    return meta,packet,originals,all_entries


def overview(originals: dict, rows: list[dict]) -> dict:
    per_finding=defaultdict(list)
    for row in rows:
        per_finding[row["finding_id"]].append(row)
    disagreements={fid for fid,items in per_finding.items()
                   if len({r["human_stage"] for r in items})>1}
    count=Counter(r["human_stage"] for r in rows)
    cases=Counter()
    for fid, items in per_finding.items():
        if fid in disagreements: cases["human_conflict"]+=1
        if any(r["human_stage"]=="human_hold" for r in items): cases["has_human_hold"]+=1
        if any(r["human_stage"]=="needs_human_followup" for r in items): cases["needs_human_followup"]+=1
    return {
        "packet_count":len({r["packet"] for r in rows}),
        "human_entry_count":len(rows),
        "original_findings_reviewed":len(per_finding),
        "human_conflict_findings":cases["human_conflict"],
        "findings_with_human_hold":cases["has_human_hold"],
        "findings_needing_human_followup":cases["needs_human_followup"],
        "status_counts":{stage:count[stage] for stage in STAGES},
        "source_claimed_high_or_critical_findings_in_conflict":sum(
            originals[fid]["severity"] in ("high","critical") for fid in disagreements),
        "disposition":"PRIVATE_HUMAN_REVIEW_ONLY",
        **{flag:False for flag in transfer.human.FLAGS},
    }


def render(originals: dict, rows: list[dict], counts: dict) -> bytes:
    by_finding=defaultdict(list)
    for row in rows:
        by_finding[row["finding_id"]].append(row)
    conflict = {fid for fid,items in by_finding.items()
                if len({r["human_stage"] for r in items})>1}
    css_hash=base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    csp=("default-src 'none'; script-src 'none'; connect-src 'none'; "
         "form-action 'none'; base-uri 'none'; img-src 'none'; font-src 'none'; "
         "style-src 'sha256-"+css_hash+"'")
    chunks=[
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="'+_escape(csp)+'">',
        '<title>LightUp PRIVATE collaborative evidence desk</title>',
        '<style>'+CSS+'</style></head><body><header><div>',
        '<div class="eyebrow">LIGHTUP / PRIVATE OFFLINE / HUMAN-ONLY COLLABORATION</div>',
        '<h1>Evidence receipt · team HUMAN desk</h1>',
        '<p>Exact original LightUp source, client/engagement and encrypted original HUMAN file index matched at publication time. Multiple independent local HUMAN replies are displayed side-by-side. No note is a security result.</p>',
        '</div></header><main>',
        '<p class="notice"><strong>HUMAN HOLD / NON-AUTHORIZING.</strong> Source severity and retest labels, SHA-256, received local bytes, timestamps and HUMAN statuses are not vulnerability proof, remediation verification, client consent, signed identity, grants or scanning permission. Conflicting HUMAN responses are never resolved by majority vote or silently merged.</p>',
        '<section class="grid" aria-label="Anonymous counts only">'
    ]
    labels=[
        ("packet_count","Reply packets"),
        ("human_entry_count","Local HUMAN entries"),
        ("original_findings_reviewed","Original findings referenced"),
        ("human_conflict_findings","Conflicting HUMAN finding statuses"),
        ("findings_needing_human_followup","Findings needing HUMAN follow-up"),
        ("findings_with_human_hold","Findings with HUMAN HOLD"),
    ]
    for key,label in labels:
        chunks.append('<div class="metric"><b>'+str(counts[key])+'</b><small>'+_escape(label)+'</small></div>')
    chunks.append('</section><nav aria-label="Review categories">')
    for path,title in (("conflicts","Conflicting HUMAN replies"),("followup","Follow-up"),("other","Other received")):
        chunks.append('<a href="#'+path+'">'+_escape(title)+'</a>')
    chunks.append('</nav>')
    ordered=sorted(by_finding,
        key=lambda fid:(0 if fid in conflict else 1,
                        SEVERITY.get(originals[fid]["severity"],99), fid))
    groups={
        "conflicts":[fid for fid in ordered if fid in conflict],
        "followup":[fid for fid in ordered if fid not in conflict and any(
            r["human_stage"]=="needs_human_followup" for r in by_finding[fid])],
        "other":[fid for fid in ordered if fid not in conflict and not any(
            r["human_stage"]=="needs_human_followup" for r in by_finding[fid])],
    }
    for name,label in (("conflicts","Conflicting HUMAN replies"),
                       ("followup","Needs HUMAN follow-up"),
                       ("other","Other received / HUMAN HOLD")):
        chunks.append('<section class="section" id="'+name+'"><h2>'+_escape(label)+' · '+str(len(groups[name]))+'</h2>')
        if not groups[name]: chunks.append('<p>No private HUMAN replies in this group.</p>')
        for fid in groups[name]:
            original=originals[fid]
            entries=sorted(by_finding[fid],key=lambda x:(x["packet"],x["sha256"]))
            chunks.append('<details><summary>'+_escape(original["title"])+' · '+
                          _escape(original["severity"])+' · '+str(len(entries))+
                          ' independent HUMAN entries'+(' · CONFLICT' if fid in conflict else '')+'</summary>')
            for row in entries:
                chunks.append('<article class="entry"><h3>PRIVATE HUMAN packet '+str(row["packet"])+
                              ' · '+_escape(STAGE_NAME[row["human_stage"]])+'</h3><div class="meta">')
                for val in ("Original finding: "+fid,
                            "Original severity CLAIM: "+original["severity"],
                            "Original retest LABEL: "+original["retest_status"],
                            "File SHA-256: "+row["sha256"],
                            "HUMAN reviewer (unverified): "+(row["human_reviewer"] or "(unassigned)"),
                            "Recorded UTC as supplied: "+row["recorded_utc"]):
                    chunks.append('<span>'+_escape(val)+'</span>')
                chunks.append('</div><blockquote>'+_escape(row["human_note"] or "No HUMAN note entered.")+
                              '</blockquote></article>')
            chunks.append('</details>')
        chunks.append('</section>')
    chunks.append('<footer>PRIVATE 0600 offline HTML. Original findings and HUMAN notes are confidential. Do not upload, host, execute extracted evidence files or treat HUMAN labels as authenticated client/operator consent or independent security judgments. No script, network, browser storage, grant or automatic original HUMAN Apply.</footer>')
    chunks.append('</main></body></html>')
    page="".join(chunks).encode("utf-8")
    if (len(page)>MAX_HTML or _escape(csp).encode("utf-8") not in page
        or b"<script" in page.lower()):
        raise ValueError("Private offline HUMAN desk exceeds bounded CSP/HTML contract.")
    return page


def publish(output: Path, vault, page: bytes, summary: dict) -> None:
    destination=transfer.private_directory(output)
    payload=transfer.canonical(summary)
    os.mkdir(destination,0o700)
    created=[]
    try:
        for name,raw in (("index.html",page),("anonymous-counts.json",payload)):
            vault._exclusive_output(destination / name,raw)
            created.append(name)
    except BaseException:
        for name in created:
            (destination / name).unlink(missing_ok=True)
        destination.rmdir()
        raise


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for key in ("db","email","client-id","engagement-id"):
        p.add_argument("--"+key,required=True)
    p.add_argument("--human",type=Path,required=True)
    p.add_argument("--transfer",type=Path,action="append",required=True,
                   help="Repeat, in same order as --reply, for 2–12 original encrypted transfers")
    p.add_argument("--reply",type=Path,action="append",required=True,
                   help="Repeat, in same order as --transfer, for 2–12 encrypted HUMAN replies")
    p.add_argument("--output-dir",type=Path,required=True,
                   help="NEW PRIVATE owner-only desk folder under 0700 parent")
    p.add_argument("--ack-private-team-html",action="store_true")
    args=p.parse_args(argv)
    try:
        if not args.ack_private_team_html or not sys.stdin.isatty():
            raise ValueError("PRIVATE team HTML requires explicit human acknowledgement and TTY.")
        vault=transfer.ORIGINAL._vault()
        meta,packet,originals,rows=collect(args,vault)
        counts=overview(originals,rows)
        page=render(originals,rows,counts)
        publish(args.output_dir,vault,page,counts)
        print("Created NEW PRIVATE original-source-bound offline HUMAN team inbox.")
        print("Packets:",counts["packet_count"],"; findings with HUMAN status conflicts:",counts["human_conflict_findings"])
        print("Private directory contains 0600 scriptless index.html and anonymous-counts.json.")
        print("No majority voting, original HUMAN Apply, scan, grant, remediation or verified retest.")
        return 0
    except Exception:
        print("HUMAN HOLD: No complete PRIVATE source-bound team inbox published. "
              "Recheck original current tenant access and all matching encrypted HUMAN replies.",
              file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
