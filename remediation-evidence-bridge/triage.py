"""Source-bound PRIVATE HUMAN action board for the offline LightUp workspace.

Everything comes from an existing authorised original five-column read and an
optional separately decrypted HUMAN packet. No grants, retests or actions occur.
"""
from __future__ import annotations

from collections import defaultdict
from datetime import date, datetime, timezone
import base64
import hashlib
from html import escape
import importlib.util
from pathlib import Path

HERE = Path(__file__).resolve().parent
SPEC = importlib.util.spec_from_file_location("_lightup_ledger_merge_admission", HERE / "merge.py")
if SPEC is None or SPEC.loader is None:
    raise ValueError("Original source-bound HUMAN record admission unavailable.")
ADMIT = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ADMIT)

MAX_BOARD = 4 * 1024 * 1024
SEVERITIES = ("critical", "high", "medium", "low", "info")
CSS = """
:root{color-scheme:dark;font-family:system-ui,-apple-system,Segoe UI,sans-serif}
*{box-sizing:border-box}html{scroll-behavior:smooth}body{margin:0;color:#eaf2f5;background:#0a1620;line-height:1.55}
main{max-width:1250px;margin:auto;padding:2rem 1.4rem 5rem}header{background:#102635;border-bottom:1px solid #355061}
nav{max-width:1250px;margin:auto;padding:1rem 1.4rem;display:flex;align-items:center;justify-content:space-between;gap:1rem;flex-wrap:wrap}
a{color:#9cf6e4}nav a{text-decoration:none;font-weight:700}h1{font-size:clamp(1.75rem,4vw,3rem);line-height:1.15}
h2{font-size:1.3rem}h3{font-size:1.05rem;margin:.25rem 0}.lede{color:#b6ccd6;max-width:910px}
.kicker{font-size:.79rem;letter-spacing:.13em;text-transform:uppercase;color:#79dacc;font-weight:760}
.notice{background:#212a35;border-left:4px solid #d0ad75;padding:1rem 1.3rem;border-radius:0 10px 10px 0;margin:1.5rem 0}
.stats{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:.8rem}
.stat{padding:1rem;border-radius:14px;border:1px solid #344e5e;background:#152c3a}
.stat strong{display:block;font-size:2rem}.stat span{font-size:.82rem;color:#b1c6d0}
.pills{display:flex;gap:.5rem;flex-wrap:wrap;margin:1.3rem 0}.pills a{padding:.5rem .8rem;border-radius:999px;text-decoration:none;background:#183746;border:1px solid #3a5966;font-size:.82rem}
.owner{padding:1rem 1.2rem;background:#122b3a;border:1px solid #355466;border-radius:14px;margin:.9rem 0}
.owner p{color:#b0c8d2;margin:.2rem 0;font-size:.87rem}
.row{background:#122735;border:1px solid #304d5e;border-radius:14px;padding:1rem 1.2rem;margin:.8rem 0;overflow-wrap:anywhere}
.row:focus-within{border-color:#8bded2}.row .head{display:flex;gap:.8rem;justify-content:space-between;align-items:flex-start;flex-wrap:wrap}
.chip{display:inline-block;border:1px solid #5c8190;padding:.17rem .5rem;border-radius:8px;color:#c5dce4;font-size:.76rem;letter-spacing:.025em}
.meta{color:#afc3cf;font-size:.86rem;margin:.55rem 0}.reasons{margin:.6rem 0;color:#e9d2a8}
details{border-top:1px solid #38505d;margin-top:.75rem;padding-top:.7rem}summary{cursor:pointer;color:#9fe6dc;font-weight:700}
dl{display:grid;grid-template-columns:180px minmax(0,1fr);gap:.55rem 1rem}dt{color:#a8c2cf;font-size:.88rem}dd{margin:0;white-space:pre-wrap;overflow-wrap:anywhere}
.requests{margin:.5rem 0 0;padding-left:1.15rem}.requests li{padding:.35rem 0}
.empty{color:#acc6cf}.foot{border-top:1px solid #2e4656;padding:1.4rem 0 0;margin-top:2.5rem;font-size:.87rem;color:#a5beca}
@media(max-width:730px){.stats{grid-template-columns:repeat(2,minmax(0,1fr))}main{padding:1.2rem .9rem 4rem}dl{grid-template-columns:1fr;gap:.15rem}dd{margin-bottom:.7rem}}
@media(prefers-reduced-motion:reduce){html{scroll-behavior:auto}}
"""


def _h(value: object) -> str:
    return escape(str(value), quote=True)


def _limited(value: str, n: int) -> str:
    """Make long source text an explicitly abbreviated preview, never a new finding."""
    return value if len(value) <= n else value[:n] + " … [source excerpt; open original review]"


def _table(source: list[dict[str, str]], packet: dict | None, utc_today: date) -> tuple[list[dict], dict]:
    if type(source) is not list or not 1 <= len(source) <= 350:
        raise ValueError("Current original five-column source required.")
    ids = set()
    for row in source:
        if type(row) is not dict or set(row) != {
            "finding_id", "title", "severity", "retest_status", "remediation"
        } or any(type(v) is not str for v in row.values()):
            raise ValueError("Noncanonical original finding columns.")
        if not row["finding_id"] or row["finding_id"] in ids or row["severity"] not in SEVERITIES:
            raise ValueError("Duplicate/invalid original finding identity.")
        ids.add(row["finding_id"])
    # The original Ledger still independently validates the private packet,
    # then original HUMAN-only browser preview+Apply after explicit user action.
    maps = ADMIT._records(packet, ids) if packet is not None else {
        "casework": None, "evidence_review": None,
        "attachments": {}, "human_requests": {}
    }
    files = defaultdict(list)
    for artifact in maps["attachments"].values():
        files[artifact["finding_id"]].append(artifact)
    requests = defaultdict(list)
    for req in maps["human_requests"].values():
        requests[req["finding_id"]].append(req)
    cases, evidence = maps["casework"], maps["evidence_review"]
    items = []
    for f in source:
        fid=f["finding_id"]
        c=cases[fid] if cases is not None else None
        e=evidence[fid] if evidence is not None else None
        attached=files[fid]
        human_reqs=sorted(requests[fid],key=lambda v:(v["due_date"] or "9999-12-31",v["request_id"]))
        open_reqs=[r for r in human_reqs if r["human_stage"]!="closed_human"]
        attention=[]
        if c is not None and not c["owner"].strip():
            attention.append("No LOCAL HUMAN owner")
        if c is not None and c["blocker"].strip():
            attention.append("HUMAN Casework blocker")
        if c is not None and c["due_date"] and date.fromisoformat(c["due_date"]) < utc_today:
            attention.append("Tentative HUMAN due date has passed (UTC clock, NOT authority)")
        if not attached:
            attention.append("No LOCAL evidence fingerprint")
        if open_reqs:
            attention.append(str(len(open_reqs))+" unresolved PRIVATE HUMAN request(s)")
        if any(a["human_stage"]=="follow_up" for a in attached):
            attention.append("LOCAL fingerprint marked HUMAN follow-up")
        if e is not None and e["stage"] in ("missing", "needs_changes"):
            attention.append("Imported original HUMAN Evidence Review needs follow-up")
        items.append({
            "finding": f, "case":c, "evidence":e,
            "artifacts":attached, "requests":human_reqs, "open_requests":open_reqs,
            "attention":attention
        })
    items.sort(key=lambda x: (
        SEVERITIES.index(x["finding"]["severity"]),
        -len(x["attention"]),
        x["case"]["due_date"] or "9999-12-31" if x["case"] is not None else "9999-12-31",
        x["finding"]["finding_id"]
    ))
    # Stable, globally unique in-document navigation across every severity.
    # A repeated rank per severity silently pointed owners to the wrong finding.
    for rank, item in enumerate(items, 1):
        item["rank"] = rank
    counters = {
        "original_findings":len(items),
        "source_critical_high":sum(i["finding"]["severity"] in ("critical","high") for i in items),
        "local_unlinked":sum(not i["artifacts"] for i in items),
        "open_human_requests":sum(len(i["open_requests"]) for i in items),
        "passed_human_due":sum(
            i["case"] is not None and i["case"]["due_date"] is not None
            and date.fromisoformat(i["case"]["due_date"]) < utc_today
            for i in items),
        "human_packet_present":packet is not None
    }
    return items, counters


def _row(item: dict, n: int) -> str:
    f=item["finding"]
    c=item["case"]
    e=item["evidence"]
    attention=item["attention"]
    parts=[
        ("Original source remediation excerpt",_limited(f["remediation"],1400)),
        ("Original source retest LABEL (not verified)",f["retest_status"]),
        ("HUMAN owner",c["owner"] if c is not None else "Not imported"),
        ("Tentative HUMAN due date",c["due_date"] or "not set" if c is not None else "Not imported"),
        ("Casework HUMAN stage",c["status"] if c is not None else "Not imported"),
        ("HUMAN next action",_limited(c["next_action"],1000) if c is not None else "Not imported"),
        ("HUMAN blocker",_limited(c["blocker"],800) if c is not None else "Not imported"),
        ("HUMAN note",_limited(c["note"],800) if c is not None else "Not imported"),
        ("Original Evidence Review HUMAN stage",e["stage"] if e is not None else "Not imported"),
        ("LOCAL artifact fingerprints",str(len(item["artifacts"]))+" (file bytes are NOT included)"),
    ]
    detail="".join("<dt>"+_h(k)+"</dt><dd>"+_h(v)+"</dd>" for k,v in parts)
    req=""
    for request in item["requests"]:
        req+=('<li><span class="chip">'+_h(request["request_kind"])+'</span> '+
              'HUMAN '+_h(request["human_stage"])+
              ' · assigned '+_h(request["assignee"] or "not assigned")+
              ' · tentative '+_h(request["due_date"] or "no date")+
              '<br>'+_h(_limited(request["instructions"],500))+'</li>')
    label=" · ".join(attention) if attention else "No currently flagged LOCAL HUMAN gap; not evidence of completion"
    return (
        '<article class="row" id="finding-'+str(n)+'">'
        '<div class="head"><div><span class="chip">'+_h(f["severity"].upper())+
        ' · original source LABEL</span><h3>'+_h(_limited(f["title"],600))+
        '</h3></div><span class="chip">PRIVATE HUMAN</span></div>'
        '<p class="meta">Original ID: '+_h(f["finding_id"])+
        ' · LOCAL HUMAN owner: '+_h(c["owner"] or "not assigned" if c is not None else "not imported")+
        ' · LOCAL files: '+str(len(item["artifacts"]))+
        ' · OPEN HUMAN requests: '+str(len(item["open_requests"]))+'</p>'
        '<p class="reasons">'+_h(label)+'</p>'
        '<details><summary>View confidential original-source and HUMAN notes</summary><dl>'+detail+
        '</dl>'+('<h4>HUMAN requests (not sent by this report)</h4><ul class="requests">'+req+'</ul>' if req else '')+
        '</details></article>'
    )


def build_board(original_source: list[dict[str,str]], human_packet: dict | None) -> bytes:
    utc_today = datetime.now(timezone.utc).date()
    items, counts = _table(original_source,human_packet,utc_today)
    css_hash=base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp=("default-src 'none'; connect-src 'none'; script-src 'none'; "
         "style-src 'sha256-"+css_hash+"'; img-src 'none'; font-src 'none'; "
         "object-src 'none'; form-action 'none'; frame-src 'none'; base-uri 'none'")
    by_owner=defaultdict(list)
    for item in items:
        owner=(item["case"]["owner"].strip() or "Unassigned") if item["case"] is not None else "Casework not imported"
        by_owner[owner].append(item)
    by_owner_html="".join(
        '<section class="owner"><h3>'+_h(name)+'</h3><p>'+
        str(len(group))+' original references in PRIVATE HUMAN planning; no verified assignment authority.</p>'+
        '<ul class="requests">'+
        "".join('<li><a href="#finding-'+str(item["rank"])+'">'+
                _h(_limited(item["finding"]["title"],110))+'</a>'+
                ' <span class="chip">'+_h(item["finding"]["severity"].upper())+
                ' · SOURCE LABEL</span> · '+str(len(item["attention"]))+
                ' LOCAL HUMAN attention signal(s)</li>' for item in group)+
        '</ul></section>'
        for name,group in sorted(by_owner.items(), key=lambda r:(r[0].lower(),r[0]))
    )
    summary="".join(
        '<div class="stat"><strong>'+str(counts[key])+'</strong><span>'+label+'</span></div>'
        for key,label in (
            ("original_findings","Original findings · unverified claims"),
            ("source_critical_high","Source-labelled critical/high · unverified"),
            ("local_unlinked","No LOCAL file fingerprints · external unknown"),
            ("open_human_requests","OPEN local HUMAN requests · not sent"),
        )
    )
    sections=[]
    for severity in SEVERITIES:
        rows=[i for i in items if i["finding"]["severity"]==severity]
        if not rows:
            continue
        sections.append(
            '<section id="severity-'+severity+'"><h2>'+_h(severity.title())+
            ' · '+str(len(rows))+' source-labelled finding(s)</h2>'+
            ''.join(_row(item,item["rank"]) for item in rows)+
            '</section>'
        )
    tabs="".join('<a href="#severity-'+s+'">'+s.title()+'</a>'
                 for s in SEVERITIES if any(i["finding"]["severity"]==s for i in items))
    html=(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="'+_h(csp)+'">'
        '<title>LightUp · PRIVATE HUMAN action board</title>'
        '<style>'+CSS+'</style></head><body><header><nav>'
        '<strong>LIGHTUP / PRIVATE HUMAN ACTION BOARD</strong>'
        '<a href="index.html">← Workroom home</a></nav></header><main>'
        '<p class="kicker">Original source + optional locally decrypted HUMAN notes · offline · generated '+utc_today.isoformat()+' UTC</p>'
        '<h1>Remediation follow-up, organised by original source.</h1>'
        '<p class="lede">This is a human coordination view of source-reported findings, local file '
        'fingerprints and optional PRIVATE notes. It is not a security verdict, verified fix, '
        'authorized retest, scan plan, grant or client consent.</p>'
        '<aside class="notice" role="note"><strong>DRAFT/HOLD · INCUBATE M3/M7</strong><br>'
        "Tentative HUMAN dates are compared to this export's UTC calendar date only. "
        'LOCAL absence is NOT missing external evidence. Completed and fixed are unverified '
        'source/HUMAN labels. No finding is confirmed resolved or ready to scan by this screen.'
        '</aside><section class="stats" aria-label="Source and LOCAL attention counts">'+summary+'</section>'
        '<h2>Private HUMAN ownership overview</h2>'+by_owner_html+
        '<nav class="pills" aria-label="Jump to original source severity labels">'+tabs+'</nav>'+
        ''.join(sections)+
        '<div class="foot">Private 0600 standalone HTML on one trusted device. '
        'Do not publish this folder, screenshot confidential notes into shared channels, '
        'or infer actual authority to act. Return to the original Evidence Ledger to preview '
        'and separately confirm any human handoff. This report cannot edit source or notes.'
        '</div></main></body></html>'
    )
    data=html.encode("utf-8", "strict")
    if len(data)>MAX_BOARD or "</script" in html.lower() or "<link " in html.lower():
        raise ValueError("PRIVATE static HUMAN action board out of bounds.")
    return data
