#!/usr/bin/env python3
"""Build a completely offline, source-bound, interactive human capacity board."""
from __future__ import annotations
import argparse
from base64 import b64encode
from hashlib import sha256
import json
from pathlib import Path
import sys
from portfolio import load, summarize, publish, Hold

ROOT=Path(__file__).resolve().parent

def digest(value):
    return b64encode(sha256(value.encode("utf-8")).digest()).decode("ascii")

def build(agendas, summary):
    template=(ROOT/"studio.template.html").read_text(encoding="utf-8")
    css=(ROOT/"studio.css").read_text(encoding="utf-8")
    js=(ROOT/"strict-json.js").read_text(encoding="utf-8") + "\n" + (ROOT/"studio.js").read_text(encoding="utf-8") + "\n" + (ROOT/"studio-plan.js").read_text(encoding="utf-8")
    source={
        "schema":"lightup.assessment_portfolio_live_capacity.v1",
        "reference_date":summary["reference_date"],
        "claimed_status":summary["claimed_status"],
        "sources":[{
            "slot":index,
            "source_sha256":source["sha256"],
            "claimed_status":source["status"],
            "rows":[{
                "source_slot":row["slot"],
                "source_kind":row["source_kind"],
                "stage":row["stage"],
                "next_role":row["next_role"],
                "review_date":row["review_date"],
                "date_bucket":row["date_bucket"]
            } for row in source["rows"]]
        } for index,source in enumerate(agendas,1)],
        "authorized":False,"consent_verified":False,
        "dispatch_allowed":False,"release_allowed":False
    }
    safe_json=json.dumps(source,ensure_ascii=True,allow_nan=False,
                         sort_keys=True,separators=(",",":"))
    # Safe script data: no HTML terminator, untrusted source text cannot create markup.
    safe_json=(safe_json.replace("&","\\u0026").replace("<","\\u003c")
              .replace(">","\\u003e"))
    csp=("<meta http-equiv=\"Content-Security-Policy\" content=\""
         "default-src 'none'; connect-src 'none'; img-src 'none'; font-src 'none'; "
         "form-action 'none'; object-src 'none'; base-uri 'none'; "
         "style-src 'sha256-"+digest(css)+"'; script-src 'sha256-"+digest(js)+"'\">")
    parts={"@@CSP@@":csp,"@@CSS@@":css,"@@PAYLOAD@@":safe_json,"@@SCRIPT@@":js}
    for placeholder,content in parts.items():
        if template.count(placeholder)!=1:
            raise Hold("standalone template malformed")
        template=template.replace(placeholder,content)
    return template.encode("utf-8")

def main(argv=None):
    p=argparse.ArgumentParser(description="Build private offline interactive human role capacity Studio — NO GO")
    p.add_argument("--agenda",required=True,action="append")
    p.add_argument("--as-of",required=True)
    p.add_argument("--output",required=True,help="NEW owner-private HTML file")
    a=p.parse_args(argv)
    try:
        sources=load(a.agenda,a.as_of)
        summary=summarize(sources,a.as_of)
        publish(a.output,build(sources,summary))
        print("PRIVATE_OFFLINE_CAPACITY_STUDIO_CREATED — NOT AUTHORIZED")
        return 3 if summary["claimed_status"]=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):
        print("CAPACITY_STUDIO_HOLD — invalid, inaccessible or unbound private source",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
