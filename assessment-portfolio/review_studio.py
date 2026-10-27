#!/usr/bin/env python3
"""Produce an owner-private offline original-source-bound human editing Studio."""
from __future__ import annotations
import argparse
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import sys
from portfolio import load, summarize, publish, Hold

ROOT=Path(__file__).resolve().parent

def _hash(src):
    return b64encode(sha256(src.encode("utf-8")).digest()).decode("ascii")

def build(agendas, summary):
    html=(ROOT/"review.template.html").read_text(encoding="utf-8")
    css=(ROOT/"review.css").read_text(encoding="utf-8")
    js=(ROOT/"review.js").read_text(encoding="utf-8")
    source={"schema":"lightup.assessment_portfolio_review_studio.v1",
            "reference_date":summary["reference_date"],
            "sources":[{"slot":index,
                        "claimed_status":src["status"],
                        "source_sha256":src["sha256"],
                        "rows":[{"source_slot":item["slot"],
                                 "source_kind":item["source_kind"],
                                 "stage":item["stage"],
                                 "next_role":item["next_role"],
                                 "review_date":item["review_date"]}
                                for item in src["rows"]]}
                       for index,src in enumerate(agendas,1)],
            "authorized":False,"consent_verified":False,
            "dispatch_allowed":False,"release_allowed":False}
    json_source=json.dumps(source,sort_keys=True,separators=(",",":"),
                           ensure_ascii=True,allow_nan=False)
    # Never let untrusted original JSON close the inert script element.
    json_source=json_source.replace("&","\\u0026").replace("<","\\u003c").replace(">","\\u003e")
    csp=("<meta http-equiv=\"Content-Security-Policy\" content=\""
         "default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; "
         "form-action 'none'; object-src 'none'; base-uri 'none'; "
         "style-src 'sha256-"+_hash(css)+"'; script-src 'sha256-"+_hash(js)+"'\">")
    for token,body in {"@@CSP@@":csp,"@@CSS@@":css,
                       "@@SCRIPT@@":js,"@@PAYLOAD@@":json_source}.items():
        if html.count(token)!=1:
            raise Hold("invalid review Studio source template")
        html=html.replace(token,body)
    return html.encode("utf-8")

def main(argv=None):
    p=argparse.ArgumentParser(description="Original-source-bound, offline PRIVATE human editor; no authorization")
    p.add_argument("--agenda",action="append",required=True)
    p.add_argument("--as-of",required=True)
    p.add_argument("--output",required=True,help="NEW owner-private HTML, no overwrite")
    a=p.parse_args(argv)
    try:
        agendas=load(a.agenda,a.as_of)
        summary=summarize(agendas,a.as_of)
        publish(a.output,build(agendas,summary))
        print("PRIVATE_HUMAN_EDITOR_CREATED — PROPOSALS ONLY; NO GO")
        return 3 if summary["claimed_status"]=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            OverflowError,RecursionError):
        print("PRIVATE_REVIEW_STUDIO_HOLD — invalid original source or output",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
