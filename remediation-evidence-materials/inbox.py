#!/usr/bin/env python3
"""Publish a PRIVATE, scriptless, offline HUMAN receipt inbox.

The original tenant/engagement/current-source read is checked immediately before
rendering. HTML is local-sensitive 0600; it is not authorization or proof.
"""
from __future__ import annotations

import argparse
import base64
from collections import Counter
import csv
import hashlib
import html
import io
from pathlib import Path
import sys

import reply
import transfer

MAX_HTML = 250000
CSS = """
:root{font-family:system-ui,-apple-system,sans-serif;color:#16213a;background:#f3f6fb}
*{box-sizing:border-box}body{margin:0}main{max-width:1120px;margin:auto;padding:30px 18px 70px}
header{background:#132340;color:white;padding:30px 18px}header>div{max-width:1080px;margin:auto}
h1{font-size:clamp(25px,4vw,40px);line-height:1.15;margin:8px 0}
.eyebrow{color:#8bd2d2;font-size:12px;letter-spacing:.17em;font-weight:800}
.intro{line-height:1.55;max-width:78ch}nav{display:flex;gap:10px;flex-wrap:wrap;margin:22px 0}
a{color:#174d80}nav a{padding:10px 13px;border-radius:10px;background:#e6efff;text-decoration:none;font-weight:700}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}
.count{padding:17px;background:white;border:1px solid #cad4df;border-radius:12px}
.count b{display:block;font-size:29px;margin-bottom:3px}.count small{font-size:12px;color:#4b5e73}
section{margin:25px 0}h2{font-size:22px}.group{border:1px solid #c8d3e0;border-radius:15px;overflow:hidden;background:white;margin:14px 0}
.group>summary{cursor:pointer;padding:16px 20px;background:#eaf0f9;font-weight:800}
article{padding:16px 20px;border-top:1px solid #d6deea}
article h3{font-size:17px;margin:0 0 12px;overflow-wrap:anywhere}
.metadata{display:flex;gap:10px;flex-wrap:wrap;margin:5px 0 15px}
.meta{background:#f2f5fb;color:#3b4a5f;padding:5px 9px;border-radius:6px;font-size:12px;overflow-wrap:anywhere}
.note{border-left:4px solid #7588a9;background:#f3f6fb;white-space:pre-wrap;overflow-wrap:anywhere;padding:12px;line-height:1.6}
.warn{border:1px solid #bd9367;background:#fff8eb;border-radius:12px;padding:16px;line-height:1.6}
footer{border-top:1px solid #c8d3df;padding-top:18px;color:#4e5d70;line-height:1.6}
@media print{header{background:white;color:black}nav{display:none}main{padding:0}details{break-inside:avoid}details>*{display:block}}
"""

STAGES = (
    ("human_hold", "HUMAN HOLD — independent review needed"),
    ("needs_human_followup", "Needs HUMAN follow-up"),
    ("received_unverified", "Locally received — unverified"),
)
LABEL = {"critical":0, "high":1, "medium":2, "low":3, "info":4}


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


def _source_rows(meta: dict, vault_owner) -> dict[str,dict]:
    raw=transfer.human._unb64(
        meta["original_csv_base64"], transfer.ORIGINAL.MAX_CSV_BYTES)
    transfer.ORIGINAL._strict_summary(raw.decode("utf-8","strict"))
    original=csv.DictReader(io.StringIO(raw.decode("utf-8","strict"),newline=""),strict=True)
    return {row["finding_id"]:row for row in original}


def render(rows: list[dict], original: dict[str,dict]) -> bytes:
    counts=Counter(r["human_stage"] for r in rows)
    css_hash=base64.b64encode(hashlib.sha256(CSS.encode()).digest()).decode("ascii")
    csp=("default-src 'none'; script-src 'none'; connect-src 'none'; form-action 'none'; "
         "img-src 'none'; font-src 'none'; base-uri 'none'; style-src 'sha256-"+css_hash+"'")
    chunks=[
        "<!doctype html><html lang='en'><head><meta charset='utf-8'>",
        '<meta name="viewport" content="width=device-width, initial-scale=1">',
        '<meta http-equiv="Content-Security-Policy" content="'+esc(csp)+'">',
        '<title>LightUp · PRIVATE HUMAN Material Reply</title>',
        '<style>'+CSS+'</style></head><body><header><div>',
        '<div class="eyebrow">LIGHTUP / PRIVATE OFFLINE / HUMAN RECEIPT ONLY</div>',
        '<h1>Evidence material · human follow-up inbox</h1>',
        '<p class="intro">Original LightUp account, tenant, engagement, material transfer and original HUMAN inventory matched at file creation. This is a PRIVATE offline snapshot; later access, remediation, proof and client consent are NOT verified.</p>',
        '</div></header><main>',
        '<div class="warn"><b>HUMAN HOLD / UNVERIFIED:</b> Source-reported finding and severity labels, file SHA-256, local receipt status and private notes do not authenticate a vulnerability, authorize a scan, prove chain of custody, confirm a fix, or validate a retest. No native HUMAN Apply is performed.</div>',
        '<section class="grid" aria-label="Human-only receipt counts">'
    ]
    for stage,label in STAGES:
        chunks.append('<div class="count"><b>'+str(counts[stage])+'</b><small>'+esc(label)+'</small></div>')
    chunks.append('</section><nav aria-label="Navigate human receipt statuses">')
    for stage, label in STAGES:
        chunks.append('<a href="#'+esc(stage)+'">'+esc(label)+'</a>')
    chunks.append('</nav>')
    for stage,label in STAGES:
        chosen = [r for r in rows if r["human_stage"]==stage]
        chosen.sort(key=lambda r:(LABEL.get(original[r["finding_id"]]["severity"],9),
                                  r["finding_id"], r["sha256"]))
        chunks.append('<section id="'+esc(stage)+'"><h2>'+esc(label)+' · '+str(len(chosen))+'</h2>')
        if not chosen:
            chunks.append('<p>No private HUMAN entries with this status.</p>')
        else:
            chunks.append('<details class="group" open><summary>View '+str(len(chosen))+' PRIVATE HUMAN follow-up entries</summary>')
            for row in chosen:
                origin=original[row["finding_id"]]
                chunks.append('<article><h3>'+esc(origin["title"])+'</h3><div class="metadata">')
                for txt in ("Finding: "+row["finding_id"],
                            "Original severity claim: "+origin["severity"],
                            "Original retest label: "+origin["retest_status"],
                            "Local SHA-256: "+row["sha256"],
                            "HUMAN reviewer: "+(row["human_reviewer"] or "(unassigned)"),
                            "HUMAN recorded UTC: "+row["recorded_utc"]):
                    chunks.append('<span class="meta">'+esc(txt)+'</span>')
                chunks.append('</div><p><strong>PRIVATE HUMAN note</strong></p>')
                chunks.append('<div class="note">'+esc(row["human_note"] or "No additional human note.")+'</div></article>')
            chunks.append('</details>')
        chunks.append('</section>')
    chunks += ['<footer>PRIVATE local review only. This file contains potentially identifying original finding labels and HUMAN notes. Do not upload or circulate publicly. No automatic sharing, HTML scripts, browser storage, network, grant, scanner, retest or security verdict.</footer>',
               '</main></body></html>']
    value="".join(chunks).encode("utf-8")
    if (len(value)>MAX_HTML or esc(csp).encode("utf-8") not in value
            or b"<script" in value.lower()):
        raise ValueError("PRIVATE local HUMAN inbox exceeds offline policy bounds.")
    return value


def main(argv: list[str] | None = None) -> int:
    p=argparse.ArgumentParser(description=__doc__)
    for name in ("db","email","client-id","engagement-id"):
        p.add_argument("--"+name,required=True)
    p.add_argument("--human",type=Path,required=True,
                   help="Original current encrypted HUMAN workspace .ltv")
    p.add_argument("--transfer",type=Path,required=True,
                   help="Original source-bound material transfer .ltv")
    p.add_argument("--reply",type=Path,required=True,
                   help="Encrypted HUMAN recipient reply .ltv")
    p.add_argument("--output",type=Path,required=True,
                   help="NEW owner-private 0600 browser inbox HTML")
    p.add_argument("--ack-private-html",action="store_true",
                   help="Deliberate disclosure of original source labels in private HTML")
    args=p.parse_args(argv)
    try:
        if not args.ack_private_html or not sys.stdin.isatty():
            raise ValueError("Explicit private HTML output acknowledgment and terminal required.")
        if args.output.suffix.lower() != ".html":
            raise ValueError("NEW PRIVATE HTML destination required.")
        vault=transfer.ORIGINAL._vault()
        meta, packet, indexed, _=reply._source(args,vault)
        material, files, _=reply._transfer(args,vault,meta,packet)
        response, _=reply._decrypt(args.reply,"PRIVATE HUMAN reply passphrase: ",vault)
        items=reply._reply_packet(response,material,files,meta,packet)
        source=_source_rows(meta,vault)
        if any(row["finding_id"] not in source for row in items):
            raise ValueError("Unknown original finding in HUMAN receipt.")
        output=render(items,source)
        vault._exclusive_output(args.output.expanduser().absolute(),output)
        print("Created NEW PRIVATE 0600 scriptless offline HUMAN receipt inbox.")
        print("Human-only material entries:",len(items))
        print("Open locally on a trusted owner workstation only; no automatic Apply or security verification.")
        return 0
    except Exception:
        print("HUMAN HOLD: No PRIVATE HTML inbox published. Current original account and exact receipt source required.",file=sys.stderr)
        return 2


if __name__=="__main__":
    raise SystemExit(main())
