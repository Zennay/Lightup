#!/usr/bin/env python3
"""Human-only weekly review capacity planner using original private lab agendas.

Projected attention slots are not verified reviews, remediation, SLAs or consent.
"""
from __future__ import annotations
import argparse
from collections import Counter,defaultdict
from datetime import timedelta
from hashlib import sha256
from base64 import b64encode
from html import escape
import sys
from portfolio import load, summarize, STAGES, ROLES, publish, Hold

STYLE="""
:root{font:16px/1.5 system-ui,sans-serif;color:#edf6fc;background:#091623;color-scheme:dark}
*{box-sizing:border-box}body{max-width:1250px;margin:0 auto;padding:30px}
header{border:1px solid #426276;border-radius:22px;padding:29px;background:linear-gradient(130deg,#1a4d57,#16283d)}
small{letter-spacing:.16em;color:#99edca;font-weight:800}
h1{font-size:clamp(2.2rem,5vw,3.6rem);line-height:1.1}
p{color:#bacfde}strong{color:#f1dfa4}
.grid{display:grid;grid-template-columns:repeat(3,1fr);gap:13px;margin:20px 0}
.card,section{padding:20px;border:1px solid #385b6c;background:#142b40;border-radius:13px;margin:18px 0}
.card b{display:block;font-size:2.1rem}
.card span{color:#c1d2dd}table{width:100%;border-collapse:collapse;font-size:.9rem}
td,th{text-align:left;padding:11px;border-bottom:1px solid #36556c}
th{color:#9becd1}tr:nth-child(even){background:#1a3447}
.warn{border-left:4px solid #e7c68a;padding:18px;background:#2e2f3e}
footer{font-size:.8rem;color:#a5bdcf}code{color:#c3fbd5}
@media(max-width:750px){.grid{grid-template-columns:1fr}body{padding:15px}}
@media print{body,header,section,.card{color:#141414;background:white}p{color:#333}}
"""

BUCKET_ORDER={"PAST_PLANNED_DATE":0,"PLANNED_FOR_REFERENCE_DAY":1,
              "FUTURE_PLANNED_DATE":2,"UNSCHEDULED":3}
STAGE_ORDER={name:i for i,name in enumerate(STAGES)}

def capacity_values(values):
    budgets={role:0 for role in ROLES}
    used=set()
    for entry in values:
        if "=" not in entry:
            raise Hold("capacity needs role=integer")
        role,value=entry.split("=",1)
        if role not in ROLES or role in used or not value.isascii() or not value.isdecimal():
            raise Hold("unsupported or duplicate role capacity")
        used.add(role)
        number=int(value)
        if not 0 <= number <= 100:
            raise Hold("capacity out of bounds")
        budgets[role]=number
    return budgets

def plan(agendas, as_of, budgets, weeks):
    from agenda import selected_day
    ref=selected_day(as_of)
    queues=defaultdict(list)
    for ix,agenda in enumerate(agendas,1):
        for row in agenda["rows"]:
            queues[row["next_role"]].append({"agenda":ix,"slot":row["slot"],
                "stage":row["stage"],"role":row["next_role"],
                "proposed_date":row["review_date"],
                "bucket":row["date_bucket"],
                "source_status":agenda["status"]})
    schedule=[]
    counts={}
    for role in ROLES:
        queue=queues[role]
        queue.sort(key=lambda r:(BUCKET_ORDER[r["bucket"]],
                                r["proposed_date"] or "9999-12-31",
                                STAGE_ORDER[r["stage"]],r["agenda"],r["slot"]))
        budget=budgets[role]
        for pos,row in enumerate(queue):
            week=pos//budget if budget else None
            if week is not None and week < weeks:
                start=ref+timedelta(days=7*week)
                label=f"Week {week+1}: {start.isoformat()}"
                allocated=True
            else:
                label="NO PROPOSED REVIEW SLOT"
                allocated=False
            schedule.append({**row,"week":week+1 if allocated else None,
                             "week_label":label,"allocated":allocated})
        allocated=sum(item["allocated"] for item in schedule if item["role"]==role)
        counts[role]={"planned_human_actions":len(queue),"weekly_hypothetical_capacity":budget,
                      "hypothetical_scheduled":allocated,"needs_human_resourcing":len(queue)-allocated}
    schedule.sort(key=lambda r:(not r["allocated"],r["week"] or 999,
                                BUCKET_ORDER[r["bucket"]],r["role"],r["agenda"],r["slot"]))
    return schedule,counts

def _table(rows,headings):
    return "<table><thead><tr>"+"".join("<th>"+escape(str(h))+"</th>" for h in headings)+        "</tr></thead><tbody>"+"".join("<tr>"+"".join("<td>"+escape(str(v))+"</td>" for v in row)+
        "</tr>" for row in rows)+"</tbody></table>"

def html_report(summary, schedule, counts, weeks, aggregate):
    css=b64encode(sha256(STYLE.encode()).digest()).decode()
    scheduled=sum(n["hypothetical_scheduled"] for n in counts.values())
    not_allocated=sum(n["needs_human_resourcing"] for n in counts.values())
    cards=[("Review actions",summary["human_item_count"]),("Hypothetical slots",scheduled),
           ("No simulated slot",not_allocated)]
    cards_html="".join("<div class='card'><b>"+str(value)+"</b><span>"+escape(key)+"</span></div>"
                       for key,value in cards)
    by_role=_table(((role,n["planned_human_actions"],n["weekly_hypothetical_capacity"],
                     n["hypothetical_scheduled"],n["needs_human_resourcing"]) for role,n in counts.items()),
                     ("Human role","Original actions","Slots / week","Hypothetically slotted","No slot"))
    if aggregate:
        queue="<section><h2>Anonymous capacity report</h2><p>No source slots, source digests, stage records or private review dates.</p></section>"
    else:
        queue="<section><h2>Private human attention sequence</h2><p>Numbers refer to local source agenda and slot only. No activity has been assigned, performed or completed.</p>"+_table(
            ((item["agenda"],item["slot"],item["role"],item["stage"],
              item["bucket"],item["proposed_date"] or "—",item["week_label"],
              item["source_status"]) for item in schedule),
            ("Agenda","Source slot","Role","Human stage","Planning category","Original proposed date","Hypothetical review slot","Original source status"))+"</section>"
    html=("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<meta name='referrer' content='no-referrer'>"
          "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none';"
          " connect-src 'none'; img-src 'none'; script-src 'none'; object-src 'none';"
          " form-action 'none'; base-uri 'none'; style-src 'sha256-"+css+"'\">"
          "<title>LightUp · Human Review Capacity Outlook</title><style>"+STYLE+"</style></head><body>"
          "<header><small>LIGHTUP / ORIGINAL LAB / HUMAN CAPACITY</small>"
          "<h1>Review capacity, not clearance.</h1>"
          "<p>"+str(weeks)+" hypothetical 7-day windows from "+escape(summary["reference_date"])+
          ". All role capacities are operator-supplied planning assumptions.</p>"
          "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · "+escape(summary["claimed_status"])+
          " · DRAFT/HOLD · NO GO</strong></header>"
          "<div class='grid'>"+cards_html+"</div><section><h2>Role capacity outlook</h2>"+
          by_role+"</section>"+queue+
          "<aside class='warn'><strong>Human planning only.</strong><p>Original proposed dates are not legal deadlines. "
          "A hypothetical review slot is not a real assignment, completed validation, vulnerability fix, grant, "
          "authenticated client permission, SLA or execution authority. Original offline sources are unsigned; "
          "portfolio counts can double-count the same evidence across distinct original agendas. "
          "Source-owner and privacy/security review, exact-head hosted and named VPS CI, genuine independent "
          "client/operator consent with action-time revocation, and HUMAN GO remain necessary.</p></aside>"
          "<footer>Offline · no network, storage, target code, scan, reviewer impersonation or automatic dispatch</footer>"
          "</body></html>")
    return html.encode()

def csv_report(summary, counts):
    lines=["role,original_human_actions,hypothetical_weekly_capacity,hypothetical_slotted,needs_human_resourcing"]
    for role,n in counts.items():
        lines.append(f'{role},{n["planned_human_actions"]},{n["weekly_hypothetical_capacity"]},'
                     f'{n["hypothetical_scheduled"]},{n["needs_human_resourcing"]}')
    return ("\r\n".join(lines)+"\r\n").encode("ascii")

def main(argv=None):
    p=argparse.ArgumentParser(description="No-action/offline hypothetical human review capacity, never release")
    p.add_argument("--agenda",action="append",required=True)
    p.add_argument("--as-of",required=True)
    p.add_argument("--role-capacity",action="append",required=True,help="Human actions per week, e.g. operator=4; repeat")
    p.add_argument("--weeks",type=int,default=8,help="1–12 hypothetical 7-day planning windows")
    p.add_argument("--format",choices=("private-html","aggregate-html","aggregate-csv"),default="private-html")
    p.add_argument("--output",required=True,help="New private file, never overwritten")
    a=p.parse_args(argv)
    try:
        if type(a.weeks) is not int or not 1 <= a.weeks <= 12: raise Hold("weeks out of range")
        agendas=load(a.agenda,a.as_of)
        summary=summarize(agendas,a.as_of)
        budgets=capacity_values(a.role_capacity)
        schedule,counts=plan(agendas,a.as_of,budgets,a.weeks)
        payload={"private-html":lambda:html_report(summary,schedule,counts,a.weeks,False),
                 "aggregate-html":lambda:html_report(summary,schedule,counts,a.weeks,True),
                 "aggregate-csv":lambda:csv_report(summary,counts)}[a.format]()
        publish(a.output,payload)
        print("HUMAN_REVIEW_CAPACITY_OUTLOOK_CREATED — HYPOTHETICAL, NO GO")
        return 3 if summary["claimed_status"]=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            OverflowError,RecursionError):
        print("HUMAN_CAPACITY_HOLD — invalid source, budget or output",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
