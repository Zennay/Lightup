#!/usr/bin/env python3
"""Private history of original human review cycle receipts; no source authority."""
from __future__ import annotations

import argparse
from collections import Counter
from hashlib import sha256
from html import escape
from base64 import b64encode
import sys

from portfolio import FLAGS, Hold, decode_json, encode, publish, read_regular, reject_authority
from agenda import selected_day
from multi_return import _zip

SCHEMA="lightup.assessment_portfolio_private_revision_cycle.v1"
PRIVATE_SCHEMA="lightup.assessment_portfolio_human_history_private.v1"
AGG_SCHEMA="lightup.assessment_portfolio_human_history_aggregate.v1"
FIELDS={"schema","previous_reference_date","new_reference_date","source_count",
        "human_changed_slots","claimed_status","sources","planning_not_permission",*FLAGS}
SOURCE_FIELDS={"slot","original_manifest_sha256","previous_choices_sha256",
               "new_choices_sha256","previous_agenda_sha256","new_agenda_sha256",
               "human_changed_slots","claimed_status"}
STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;background:#0b1b2b;color:#e8f5fd;color-scheme:dark}
*{box-sizing:border-box}body{margin:0 auto;max-width:1250px;padding:24px}
header{background:linear-gradient(115deg,#164d5d,#17283e);padding:32px;border-radius:18px;border:1px solid #40677a}
small{letter-spacing:.14em;color:#9fe6c9;font-weight:800}h1{font-size:clamp(2rem,5vw,3.4rem)}
p{color:#bbd1dd}section{padding:21px;background:#132c41;border-radius:12px;border:1px solid #385e74;margin:18px 0}
.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:12px}
.stats section b{font-size:2rem;display:block}.stats section span{color:#c6d7df}
table{border-collapse:collapse;width:100%}td,th{padding:10px;border-bottom:1px solid #395668;text-align:left}
th{color:#a0e7d3}tr:nth-child(even){background:#1b374a}
.warn{border-left:4px solid #e9cb84;background:#2f2c3a;padding:19px}
footer{font-size:.86rem;color:#b8cddd}@media(max-width:720px){body{padding:12px}.stats{display:block}}
@media print{body,header,section{background:white;color:black}p{color:#333}}
"""

def _digest(v):
    return (type(v) is str and len(v)==64 and
            all(letter in "0123456789abcdef" for letter in v))

def load_raw(raw):
    doc=decode_json(raw)
    reject_authority(doc)
    if (type(doc) is not dict or set(doc)!=FIELDS or doc["schema"]!=SCHEMA
            or type(doc["source_count"]) is not int
            or not 1<=doc["source_count"]<=12
            or type(doc["human_changed_slots"]) is not int
            or not 0<=doc["human_changed_slots"]<=768
            or type(doc["sources"]) is not list
            or len(doc["sources"])!=doc["source_count"]
            or doc["planning_not_permission"] is not True
            or doc["claimed_status"] not in ("HOLD","REVIEW_ONLY")
            or any(doc[flag] is not False for flag in FLAGS)):
        raise Hold("noncanonical original human review cycle receipt")
    for field in ("previous_reference_date","new_reference_date"):
        selected_day(doc[field])
    seen=set()
    changes=0
    statuses=[]
    for index,source in enumerate(doc["sources"],1):
        if (type(source) is not dict or set(source)!=SOURCE_FIELDS
                or type(source["slot"]) is not int or source["slot"]!=index
                or type(source["human_changed_slots"]) is not int
                or not 0<=source["human_changed_slots"]<=64
                or source["claimed_status"] not in ("HOLD","REVIEW_ONLY")
                or any(not _digest(source[name]) for name in (
                    "original_manifest_sha256","previous_choices_sha256",
                    "new_choices_sha256","previous_agenda_sha256",
                    "new_agenda_sha256"))):
            raise Hold("invalid source member or change count")
        if source["original_manifest_sha256"] in seen:
            raise Hold("duplicated original human source manifest")
        seen.add(source["original_manifest_sha256"])
        changes+=source["human_changed_slots"]
        statuses.append(source["claimed_status"])
    expected="HOLD" if "HOLD" in statuses else "REVIEW_ONLY"
    if changes!=doc["human_changed_slots"] or doc["claimed_status"]!=expected:
        raise Hold("inconsistent original human source HOLD or change count")
    return doc, sha256(raw).hexdigest()

def load(path):
    return load_raw(read_regular(path,131072))

def history(paths, *, complete_zip=False):
    if not 2<=len(paths)<=12:
        raise Hold("history requires two to twelve complete original review cycles")
    if complete_zip:
        from revision_zip import read_cycle_zip
        read=[read_cycle_zip(path) for path in paths]
    else:
        read=[load(path) for path in paths]
    if len({digest for _,digest in read})!=len(read):
        raise Hold("duplicate original human revision receipt")
    original=read[0][0]
    baseline=[source["original_manifest_sha256"] for source in original["sources"]]
    previous=None
    for doc,_ in read:
        if doc["source_count"]!=len(baseline) or [
            src["original_manifest_sha256"] for src in doc["sources"]] != baseline:
            raise Hold("human history mixes original source cohorts")
        if previous is not None:
            if doc["previous_reference_date"]!=previous["new_reference_date"]:
                raise Hold("original human history has a reference date gap")
            for old,new in zip(previous["sources"],doc["sources"]):
                if (old["new_choices_sha256"]!=new["previous_choices_sha256"]
                        or old["new_agenda_sha256"]!=new["previous_agenda_sha256"]
                        or old["claimed_status"]!=new["claimed_status"]):
                    raise Hold("original human history has an unresolved source lineage gap")
        previous=doc
    total=sum(row["human_changed_slots"] for row,_ in read)
    states=[row["claimed_status"] for row,_ in read]
    overall="HOLD" if "HOLD" in states else "REVIEW_ONLY"
    timeline=[{
        "step":i,"from_date":row["previous_reference_date"],
        "to_date":row["new_reference_date"],
        "human_changed_slots":row["human_changed_slots"],
        "claimed_status":row["claimed_status"],
        "source_count":row["source_count"]
    } for i,(row,_) in enumerate(read,1)]
    aggregate={"schema":AGG_SCHEMA,"cycle_count":len(read),
               "source_count":len(baseline),"total_human_changes":total,
               "claimed_status":overall,"timeline":timeline,
               "planning_not_permission":True,**{f:False for f in FLAGS}}
    private={"schema":PRIVATE_SCHEMA,"aggregate":aggregate,
             "original_sources":[{"slot":i,"original_manifest_sha256":digest}
                                 for i,digest in enumerate(baseline,1)],
             "cycles":[{"step":i,"receipt_sha256":digest,
                        "sources":row["sources"]} for i,(row,digest) in enumerate(read,1)],
             **{f:False for f in FLAGS}}
    return aggregate,private

def render(aggregate, private=False):
    style=b64encode(sha256(STYLE.encode()).digest()).decode()
    lines="".join("<tr>"+"".join("<td>"+escape(str(v))+"</td>" for v in (
        row["step"], row["from_date"],row["to_date"],
        row["human_changed_slots"],row["claimed_status"]))+"</tr>"
        for row in aggregate["timeline"])
    html=("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<meta name='referrer' content='no-referrer'>"
          "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
          " style-src 'sha256-"+style+"'; script-src 'none'; connect-src 'none';"
          " img-src 'none'; form-action 'none'; base-uri 'none'; object-src 'none'\">"
          "<title>LightUp · Human review lineage</title><style>"+STYLE+"</style></head><body>"
          "<header><small>LIGHTUP / OFFLINE ORIGINAL HUMAN REVIEW HISTORY</small>"
          "<h1>From one human review to the next.</h1>"
          "<p>Local source-neutral human planning changes over explicitly supplied original review cycles.</p>"
          "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "+
          escape(aggregate["claimed_status"])+" · NO GO</strong></header>"
          "<div class='stats'><section><b>"+str(aggregate["cycle_count"])+"</b>"
          "<span>Consecutive human reviews</span></section><section><b>"+
          str(aggregate["source_count"])+"</b><span>Original source agendas</span></section>"
          "<section><b>"+str(aggregate["total_human_changes"])+"</b>"
          "<span>Total human-only edits, not unique fixes</span></section></div>"
          "<section><h2>Source-bound review sequence</h2><p>"+(
              "PRIVATE operator lineage: associated original SHA fingerprints live in separate private JSON."
              if private else
              "Aggregate-only: no source fingerprints, agenda IDs, targets or original findings.")+
          "</p><table><thead><tr><th>Step</th><th>From planning date</th>"
          "<th>Next planning date</th><th>Human slots revised</th>"
          "<th>Original status</th></tr></thead><tbody>"+lines+"</tbody></table></section>"
          "<aside class='warn'><strong>Not a security finding trend or audit of actual actions.</strong>"
          "<p>A human edit count does not prove executed assessment, verified remediation,"
          " actual staff work, client permission or continuity of cryptographic origin."
          " The original review receipts are UNSIGNED, and this timeline compares only their"
          " self-reported byte correlations. Source-owner, privacy/security, exact-head CI,"
          " independent authenticated client/operator consent with at-use revocation and"
          " HUMAN GO remain mandatory before any active execution or release.</p></aside>"
          "<footer>Offline scriptless history · no network, target data, scanner or grant</footer></body></html>")
    return html.encode("utf-8")

def build(paths, *, complete_zip=False):
    aggregate,private=history(paths,complete_zip=complete_zip)
    rows=["step,from_planning_date,to_planning_date,human_changed_slots,original_state"]
    for x in aggregate["timeline"]:
        rows.append(",".join(str(x[key]) for key in ("step","from_date","to_date",
                                                     "human_changed_slots","claimed_status")))
    files={
        "index.html":render(aggregate,True),
        "aggregate.html":render(aggregate,False),
        "aggregate.json":encode(aggregate),
        "aggregate.csv":("\r\n".join(rows)+"\r\n").encode("ascii"),
        "private-source-lineage.json":encode(private),
        "START-HERE.txt":(
            "LIGHTUP / PRIVATE ORIGINAL HUMAN REVIEW HISTORY / NO GO\n"
            "This ZIP describes ONLY 2–12 locally supplied original human review receipts.\n"
            "Open index.html for source-neutral visual history, not actual review outcomes.\n"
            "aggregate.html/json/csv have counts, not original identities; review privacy.\n"
            "private-source-lineage.json holds sensitive unsigned SHA correlations.\n"
            "All sources/previous/new choices/agenda fingerprints were chain-compared.\n"
            "No original findings, evidence, real owner names, target or secrets included.\n"
            "Never regard byte correlations as authenticity, consent or a GO.\n"
            "INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.\n").encode("utf-8"),
    }
    return _zip(files),aggregate["claimed_status"]

def main(argv=None):
    p=argparse.ArgumentParser(description="Standalone original private human review history; no GO")
    source=p.add_mutually_exclusive_group(required=True)
    source.add_argument("--cycle",action="append",
                        help="Original private revision record JSON; repeat 2–12 in sequence")
    source.add_argument("--cycle-zip",action="append",
                        help="Original complete private human review cycle ZIP; repeat 2–12 in sequence")
    p.add_argument("--output",required=True,help="NEW private offline history ZIP, never overwrite")
    args=p.parse_args(argv)
    try:
        blob,status=build(args.cycle_zip or args.cycle, complete_zip=args.cycle_zip is not None)
        publish(args.output,blob)
        print("ORIGINAL_HUMAN_HISTORY_CREATED — UNSIGNED PRIVATE REVIEW ONLY; NO GO")
        return 3 if status=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            RecursionError,OverflowError):
        print("ORIGINAL_HUMAN_HISTORY_HOLD — missing, changed or unbound original cycle",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
