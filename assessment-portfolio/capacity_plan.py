#!/usr/bin/env python3
"""Replay exact original-source-bound HUMAN capacity assumptions without execution."""
from __future__ import annotations
import argparse
import sys

from portfolio import (FLAGS, Hold, decode_json, read_regular, reject_authority,
                       load, summarize, publish)
from capacity import plan, html_report, csv_report, ROLES

SCHEMA="lightup.assessment_portfolio_capacity_plan.v1"
FIELDS={"schema","reference_date","source_count","sources","hypothetical_weeks",
        "role_capacities",*FLAGS}
SOURCE_FIELDS={"slot","source_sha256","claimed_status"}
MAX_PLAN=65536

def admitted_plan(path,agendas,reference):
    src=decode_json(read_regular(path,MAX_PLAN))
    reject_authority(src)
    if (type(src) is not dict or set(src)!=FIELDS or src["schema"]!=SCHEMA or
            src["reference_date"]!=reference or type(src["source_count"]) is not int or
            src["source_count"]!=len(agendas) or
            type(src["sources"]) is not list or len(src["sources"])!=len(agendas) or
            type(src["hypothetical_weeks"]) is not int or
            not 1<=src["hypothetical_weeks"]<=12 or
            any(src[flag] is not False for flag in FLAGS)):
        raise Hold("private original source plan mismatched")
    for index,(old,new) in enumerate(zip(agendas,src["sources"]),1):
        if (type(new) is not dict or set(new)!=SOURCE_FIELDS or
                type(new["slot"]) is not int or new["slot"]!=index or
                new["source_sha256"]!=old["sha256"] or
                new["claimed_status"]!=old["status"]):
            raise Hold("original human agenda has changed")
    budgets=src["role_capacities"]
    if (type(budgets) is not dict or set(budgets)!=set(ROLES) or
            any(type(value) is not int or not 0<=value<=100 for value in budgets.values())):
        raise Hold("invalid original human role capacity")
    return budgets,src["hypothetical_weeks"]

def main(argv=None):
    p=argparse.ArgumentParser(description="Render source-bound PRIVATE human role-capacity plan; not an assessment")
    p.add_argument("--agenda",action="append",required=True,help="Original PRIVATE agenda JSON; 1–12 exact order")
    p.add_argument("--as-of",required=True,help="Original YYYY-MM-DD source reference date")
    p.add_argument("--private-plan",required=True,help="PRIVATE source-bound browser Studio plan")
    p.add_argument("--format",choices=("private-html","aggregate-html","aggregate-csv"),default="private-html")
    p.add_argument("--output",required=True,help="NEW owner-private 0600 file")
    a=p.parse_args(argv)
    try:
        agendas=load(a.agenda,a.as_of)
        budgets,weeks=admitted_plan(a.private_plan,agendas,a.as_of)
        summary=summarize(agendas,a.as_of)
        schedule,counts=plan(agendas,a.as_of,budgets,weeks)
        formats={"private-html":lambda:html_report(summary,schedule,counts,weeks,False),
                 "aggregate-html":lambda:html_report(summary,schedule,counts,weeks,True),
                 "aggregate-csv":lambda:csv_report(summary,counts)}
        publish(a.output,formats[a.format]())
        print("SOURCE_BOUND_PRIVATE_HUMAN_CAPACITY_RENDERED — PLANNING ONLY, NO GO")
        return 3 if summary["claimed_status"]=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,RecursionError,OverflowError):
        print("CAPACITY_PLAN_HOLD — original agenda drift or invalid private plan",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
