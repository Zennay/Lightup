#!/usr/bin/env python3
"""Offline portfolio of original LightUp human assessment agendas; no runtime authority."""
from __future__ import annotations
import argparse
from collections import Counter
from datetime import date
from hashlib import sha256
from html import escape
from io import BytesIO
from pathlib import Path
import sys
from zipfile import ZipFile, ZipInfo, ZIP_STORED

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "assessment-archive"))
from archive import FLAGS, Hold, decode_json, encode, publish, read_regular, reject_authority
from followup import GUIDANCE, STAGES, ROLES
from agenda import DATE_BUCKETS, date_bucket, selected_day

SOURCE_SCHEMA = "lightup.archive_human_agenda.v1"
SHARED_SCHEMA = "lightup.assessment_portfolio_aggregate.v1"
PRIVATE_SCHEMA = "lightup.assessment_portfolio_private.v1"
MAX_BYTES = 262144
SOURCE_FIELDS = {"schema","claimed_status","reference_date","source_count",
                 "human_stage_counts","neutral_role_counts","date_bucket_counts",
                 "planning_not_permission","items",*FLAGS}
ROW_FIELDS = {"slot","source_kind","stage","next_role","review_date",
              "date_bucket","suggested_human_question"}
STYLE = """
:root{color-scheme:dark;font:16px/1.45 system-ui,sans-serif;background:#0a1523;color:#e8f4fc}
*{box-sizing:border-box}body{max-width:1300px;padding:32px;margin:0 auto}
.hero{background:linear-gradient(125deg,#15475b,#142338);border:1px solid #406476;border-radius:22px;padding:30px}
small{color:#9becd3;letter-spacing:2px;text-transform:uppercase;font-weight:800}
h1{font-size:clamp(2.3rem,5vw,4rem);line-height:1.06;margin:15px 0}
p{color:#bbcede}strong{color:#eed79a}
.stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin:22px 0}
.stat,.panel{background:#152a3f;border:1px solid #365067;border-radius:14px;padding:19px}
.stat b{display:block;font-size:2.2rem}.stat span{color:#b3cbd9}
main{display:grid;grid-template-columns:1fr 1fr;gap:18px}h2{margin:6px 0 15px}
.wide{grid-column:1/-1}table{border-collapse:collapse;width:100%;font-size:.88rem}
th,td{padding:10px;border-bottom:1px solid #355267;text-align:left}th{color:#99edd1}
tr:nth-child(even){background:#1c3448}
.warning{border-left:4px solid #e9cf8e;padding:18px;background:#2c2b3b;margin-top:22px}
footer{margin-top:20px;font-size:.8rem;color:#a3bdd0}
@media(max-width:820px){main{display:block}.panel{margin:16px 0}.stats{grid-template-columns:repeat(2,1fr)}body{padding:15px}}
@media print{body{color:black;background:white}.hero,.stat,.panel{background:white;color:black;border:1px solid #777}p{color:black}}
"""

def exact_counts(value, keys, actual):
    if (type(value) is not dict or set(value) != set(keys)
            or any(type(value[k]) is not int or value[k] != actual[k] for k in keys)):
        raise Hold("original count disagreement")

def load_one(path, selected, *, raw=None):
    if raw is None:
        raw = read_regular(path, MAX_BYTES)
    doc = decode_json(raw)
    reject_authority(doc)
    if (type(doc) is not dict or set(doc) != SOURCE_FIELDS
            or doc["schema"] != SOURCE_SCHEMA
            or doc["reference_date"] != selected
            or doc["claimed_status"] not in ("REVIEW_ONLY","HOLD")
            or doc["planning_not_permission"] is not True
            or type(doc["source_count"]) is not int
            or not 1 <= doc["source_count"] <= 64
            or any(doc[flag] is not False for flag in FLAGS)
            or type(doc["items"]) is not list
            or len(doc["items"]) != doc["source_count"]):
        raise Hold("not an original private agenda")
    slots = set()
    stage_count, role_count, date_count = Counter(),Counter(),Counter()
    for row in doc["items"]:
        if type(row) is not dict or set(row) != ROW_FIELDS:
            raise Hold("wrong original row shape")
        slot, kind, stage, role, day = (row[k] for k in
                       ("slot","source_kind","stage","next_role","review_date"))
        if (type(slot) is not int or not 1 <= slot <= doc["source_count"]
                or slot in slots or type(kind) is not str or kind not in GUIDANCE
                or type(stage) is not str or stage not in STAGES
                or type(role) is not str or role not in ROLES
                or row["suggested_human_question"] != GUIDANCE[kind]):
            raise Hold("original row identity invalid")
        slots.add(slot)
        if day is not None:
            selected_day(day)
        bucket = date_bucket(day, selected_day(selected))
        if row["date_bucket"] != bucket:
            raise Hold("original date bucket disagrees")
        stage_count[stage] += 1
        role_count[role] += 1
        date_count[bucket] += 1
    if slots != set(range(1, doc["source_count"] + 1)):
        raise Hold("incomplete original membership")
    exact_counts(doc["human_stage_counts"],STAGES,stage_count)
    exact_counts(doc["neutral_role_counts"],ROLES,role_count)
    exact_counts(doc["date_bucket_counts"],DATE_BUCKETS,date_count)
    return {"sha256":sha256(raw).hexdigest(),
            "status":doc["claimed_status"],"rows":doc["items"]}

def load(paths, selected):
    selected_day(selected)
    if not 1 <= len(paths) <= 12: raise Hold("bounded source count")
    agendas = [load_one(path, selected) for path in paths]
    if len({a["sha256"] for a in agendas}) != len(agendas):
        raise Hold("duplicate agenda bytes")
    return agendas

def summarize(agendas, selected):
    stages,roles,dates = Counter(),Counter(),Counter()
    for source in agendas:
        for row in source["rows"]:
            stages[row["stage"]] += 1
            roles[row["next_role"]] += 1
            dates[row["date_bucket"]] += 1
    return {"schema":SHARED_SCHEMA,
            "reference_date":selected,
            "agenda_count":len(agendas),
            "human_item_count":sum(len(a["rows"]) for a in agendas),
            "claimed_status":"HOLD" if any(a["status"] == "HOLD" for a in agendas) else "REVIEW_ONLY",
            "stage_counts":{k:stages[k] for k in STAGES},
            "role_counts":{k:roles[k] for k in ROLES},
            "date_bucket_counts":{k:dates[k] for k in DATE_BUCKETS},
            "planning_not_permission":True,
            **{key:False for key in FLAGS}}

def private(agendas, summary):
    return {"schema":PRIVATE_SCHEMA,"summary":summary,
            "sources":[{"slot":i,"source_sha256":a["sha256"],
                        "claimed_status":a["status"],
                        "rows":[{"source_slot":row["slot"],
                                 "source_kind":row["source_kind"],
                                 "stage":row["stage"],
                                 "next_role":row["next_role"],
                                 "review_date":row["review_date"],
                                 "date_bucket":row["date_bucket"]}
                                for row in a["rows"]]}
                       for i,a in enumerate(agendas,1)],
            **{key:False for key in FLAGS}}

def table(rows, headings):
    return "<table><thead><tr>" + "".join("<th>" + escape(str(s)) + "</th>" for s in headings) + "</tr></thead><tbody>" + "".join(
        "<tr>" + "".join("<td>" + escape(str(s)) + "</td>" for s in row) + "</tr>" for row in rows
        ) + "</tbody></table>"

def render(agendas, summary, aggregate=False):
    from base64 import b64encode
    style_digest=b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    stats=[("Agendas",summary["agenda_count"]),
           ("Human actions",summary["human_item_count"]),
           ("Past planned dates",summary["date_bucket_counts"]["PAST_PLANNED_DATE"]),
           ("Unscheduled",summary["date_bucket_counts"]["UNSCHEDULED"])]
    cards="".join("<div class='stat'><b>"+str(n)+"</b><span>"+escape(label)+"</span></div>" for label,n in stats)
    stages=table([(k,v) for k,v in summary["stage_counts"].items()],("Human stage","Items"))
    roles=table([(k,v) for k,v in summary["role_counts"].items()],("Next role","Items"))
    if aggregate:
        board="<section class='panel wide'><h2>Aggregate-only handoff</h2><p>No source slots, digests, client labels, targets, records, assignments or dates.</p></section>"
    else:
        rows=[]
        for ix,a in enumerate(agendas,1):
            for row in a["rows"]:
                rows.append((row["date_bucket"],row["review_date"] or "—",
                             ix,row["slot"],row["stage"],row["next_role"],
                             row["source_kind"],a["status"]))
        priority={"PAST_PLANNED_DATE":0,"PLANNED_FOR_REFERENCE_DAY":1,
                  "UNSCHEDULED":2,"FUTURE_PLANNED_DATE":3}
        rows.sort(key=lambda r:(priority[r[0]],r[1],r[2],r[3]))
        board="<section class='panel wide'><h2>Private human work queue</h2><p>Local agenda/slot numbers only. Planned dates are proposals, never legal deadlines.</p>"+table(
            [(x[2],x[3],x[4],x[5],x[1],x[0],x[6],x[7]) for x in rows],
            ("Agenda","Slot","Human stage","Next role","Planned date","Date bucket","Source type","Original status")
        )+"</section>"
    html=("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
          "<meta name='viewport' content='width=device-width,initial-scale=1'>"
          "<meta name='referrer' content='no-referrer'>"
          "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; connect-src 'none'; script-src 'none'; img-src 'none'; form-action 'none'; object-src 'none'; base-uri 'none'; style-src 'sha256-"
          +style_digest+"'\"/>"
          "<title>LightUp · Agenda Portfolio</title><style>"+STYLE+"</style></head><body>"
          "<header class='hero'><small>LIGHTUP / ASSESSMENT RUNTIME / OFFLINE</small>"
          "<h1>Across agendas.<br>Within human review.</h1>"
          "<p>Private cross-source human planning as of "+escape(summary["reference_date"])+".</p>"
          "<strong>INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · "+escape(summary["claimed_status"])+" · NO GO</strong></header>"
          "<div class='stats'>"+cards+"</div><main><section class='panel'><h2>Human stages</h2>"+stages+
          "</section><section class='panel'><h2>Next roles</h2>"+roles+"</section>"+board+"</main>"
          "<aside class='warning'><strong>Not authorization, source verification or remediation clearance.</strong>"
          "<p>Source agendas are unsigned. Cross-agenda items may refer to the same original artifacts, so totals are workload counts, not deduplicated vulnerabilities. "
          "Missing items do not mean fixed vulnerabilities. Existing exact-head CI, independent source owner/privacy/security review, "
          "real independently authenticated client/operator consent with action-time revocation, and HUMAN GO remain mandatory.</p></aside>"
          "<footer>Local offline human review · no JavaScript, network, scanner, grants, browser storage or target code</footer>"
          "</body></html>")
    return html.encode("utf-8")

def csv_report(summary):
    rows=["category,item,count",
          "portfolio,agendas,"+str(summary["agenda_count"]),
          "portfolio,human_actions,"+str(summary["human_item_count"])]
    for kind,key in (("stage","stage_counts"),("role","role_counts"),("date","date_bucket_counts")):
        for name,n in summary[key].items(): rows.append(f"{kind},{name},{n}")
    return ("\r\n".join(rows)+"\r\n").encode("ascii")

def package(agendas, summary):
    from browser_studio import build as build_interactive_studio
    from review_studio import build as build_private_review_studio
    from navigation import build as build_workspace_home
    from collaboration_guide import build as build_private_collaboration_guide
    public=encode(summary)
    files={"workspace-home.html":build_workspace_home(summary),
           "collaboration-guide.html":build_private_collaboration_guide(summary),
           "START-HERE.txt":("LIGHTUP PRIVATE HUMAN PORTFOLIO. Open workspace-home.html offline.\n"
          "private-source-bindings.json includes source SHA hashes and human item slots; keep private.\n"
          "aggregate.html/json/csv contain counts only; review before sharing.\n"
          "interactive-capacity-studio.html changes only local hypothetical role budgets.\n"
          "original-human-review-studio.html edits human-only fields and exports a PRIVATE proposal.\n"
          "Human plans are not an original verified finding, consent, a release or GO.\n").encode(),
          "index.html":render(agendas,summary),
          "interactive-capacity-studio.html":build_interactive_studio(agendas,summary),
          "original-human-review-studio.html":build_private_review_studio(agendas,summary),
          "private-source-bindings.json":encode(private(agendas,summary)),
          "aggregate.html":render(agendas,summary,True),
          "aggregate.json":public,"aggregate.csv":csv_report(summary)}
    from content_map import build as build_private_content_map
    files["private-workspace-content-map.json"]=build_private_content_map(files,summary)
    buffer=BytesIO()
    with ZipFile(buffer,"w",compression=ZIP_STORED) as zip_file:
        for name,blob in files.items():
            meta=ZipInfo(name,(2026,10,18,0,0,0))
            meta.external_attr=0o600<<16
            zip_file.writestr(meta,blob)
    return buffer.getvalue()

def main(argv=None):
    parser=argparse.ArgumentParser(description="Private offline multi-agenda human work queue — NO GO")
    parser.add_argument("--agenda",action="append",required=True,help="Original private agenda JSON; repeat up to 12")
    parser.add_argument("--as-of",required=True,help="Same original planning day YYYY-MM-DD")
    parser.add_argument("--format",choices=("workspace-zip","private-html","private-json","aggregate-html",
                                            "aggregate-json","aggregate-csv"),default="workspace-zip")
    parser.add_argument("--output",required=True,help="New private output path; no overwrite")
    args=parser.parse_args(argv)
    try:
        agendas=load(args.agenda,args.as_of)
        summary=summarize(agendas,args.as_of)
        renderers={"workspace-zip":lambda:package(agendas,summary),
                   "private-html":lambda:render(agendas,summary),
                   "private-json":lambda:encode(private(agendas,summary)),
                   "aggregate-html":lambda:render(agendas,summary,True),
                   "aggregate-json":lambda:encode(summary),
                   "aggregate-csv":lambda:csv_report(summary)}
        publish(args.output,renderers[args.format]())
        print("PRIVATE_OFFLINE_HUMAN_PORTFOLIO_CREATED — NOT AUTHORIZED")
        return 3 if summary["claimed_status"]=="HOLD" else 2
    except (Hold,OSError,ValueError,TypeError,KeyError,UnicodeError,
            OverflowError,RecursionError):
        print("ASSESSMENT_PORTFOLIO_HOLD — invalid, changed or missing private source",file=sys.stderr)
        return 3

if __name__=="__main__":
    raise SystemExit(main())
