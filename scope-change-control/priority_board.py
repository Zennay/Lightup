"""Original-source-bound PRIVATE human scope priority board — no permissions.

Compose the original Casebook delta, unchanged grant/request dependencies and
original unmodified Window Review agenda into ONE useful human follow-up queue.
Never reads clients, contacts a target, grants access, writes original domain
records or claims original source authenticity/current consent/STOP clearance.
"""
from __future__ import annotations

from collections import defaultdict
from hashlib import sha256
from html import escape
import base64
import json

from refresh import ReviewHold, _admit

STYLE = """*{box-sizing:border-box}body{font:15px/1.55 system-ui,sans-serif;background:#0c1423;color:#ecf4fe;max-width:1150px;padding:28px;margin:auto}h1{font-size:clamp(2rem,4vw,3.3rem);line-height:1.1}p{color:#b9cee2}.eyebrow{color:#96f2cf;font-weight:800;letter-spacing:.12em;font-size:.76rem}.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(180px,1fr));gap:12px}.stat,article{background:#15243a;border:1px solid #2b425d;border-radius:16px;padding:18px;margin:12px 0}.stat strong{display:block;font-size:2rem;color:#aaf7dc}.tag{color:#ffe0a8;font-size:.85rem;font-weight:800}input{width:100%;border:1px solid #56728d;background:#091626;color:#f7fcff;border-radius:10px;padding:14px;font:inherit}input:focus-visible{outline:3px solid #aeffdb;outline-offset:2px}article.hold{border-left:5px solid #f3ae86}article.review{border-left:5px solid #8adddb}article h2{font-size:1.15rem;overflow-wrap:anywhere;margin:0 0 7px}dl{display:grid;grid-template-columns:minmax(115px,180px) 1fr;gap:4px 15px}dt{color:#a6c4e0}dd{margin:0;overflow-wrap:anywhere}ul{margin:10px 0}li{margin:5px 0}footer{margin-top:36px;padding:20px 0;border-top:1px solid #314660;color:#d2e3ee}.hide{display:none}.counts{font-weight:bold;color:#a2e5cf}"""
SCRIPT = """'use strict';(()=>{const q=document.getElementById('q');const list=[...document.querySelectorAll('article.entry')];const result=document.getElementById('visible');const draw=()=>{const term=q.value.trim().toLocaleLowerCase();let shown=0;for(const item of list){const yes=!term||item.textContent.toLocaleLowerCase().includes(term);item.hidden=!yes;if(yes)shown++}result.textContent=shown};q.addEventListener('input',draw);draw()})();"""
FLAGS = (
    "source_authenticated", "client_consent_verified",
    "operator_consent_verified", "authorization_granted",
    "execution_allowed", "release_approved",
)


def _eligible(doc: dict, family: str) -> None:
    if type(doc) is not dict or any(doc.get(flag) is not False for flag in FLAGS):
        raise ReviewHold("original review falsely claims authority")
    allowed = {
        "native": ("lightup.casebook_change_private_review.v1", "HOLD_HUMAN_REVIEW"),
        "agenda": ("lightup.scope_window_review.v1", None),
    }
    expected, disposition = allowed[family]
    if doc.get("schema") != expected:
        raise ReviewHold("unexpected original human review schema")
    if disposition is not None and doc.get("disposition") != disposition:
        raise ReviewHold("original follow-up not held")


def _label(value: object) -> str:
    return escape(str(value), quote=True)


def compose(native: dict, agenda: dict, current: dict) -> tuple[bytes, dict]:
    _eligible(native, "native")
    _eligible(agenda, "agenda")
    indexed = _admit(current)
    if (native.get("tenant_original_id") != current["client_id"] or
            agenda.get("client_id") != current["client_id"] or
            agenda.get("original_source_sha256") != native.get("source_sha256_unsigned", [None, None])[1] or
            agenda.get("status") not in ("HOLD", "REVIEW_ONLY") or
            not isinstance(agenda.get("items"), list) or
            not isinstance(native.get("changes"), list) or
            not isinstance(native.get("unchanged_grant_request_dependencies"), list)):
        raise ReviewHold("private integrated source relationships unavailable")
    # Categories are original source families, not new synthetic authority.
    tasks: dict[tuple[str,str], dict] = {}

    def item(family: str, original_id: str, engagement_id: str | None = None) -> dict:
        if type(original_id) is not str or not 1 <= len(original_id) <= 180:
            raise ReviewHold("noncanonical original identity in priority source")
        key = (family, original_id)
        if key not in tasks:
            tasks[key] = {
                "family": family, "id": original_id, "engagement": engagement_id,
                "reason": set(), "review_day": None, "source_attention": None,
            }
        return tasks[key]

    for change in native["changes"]:
        if type(change) is not dict or change.get("family") not in (
                "requests", "engagements", "grants", "risk_approvals", "case_overview"):
            raise ReviewHold("unknown original change family")
        family, id = change["family"], change.get("original_id")
        if family not in ("grants", "requests", "engagements", "risk_approvals", "case_overview"):
            continue
        source = indexed[family].get(id) if type(id) is str else None
        eid = id if family in ("engagements","case_overview") else (
            source.get("engagement_id") if source is not None else None)
        row = item(family, id, eid)
        row["reason"].add("ORIGINAL_"+str(change.get("change", "SOURCE_DELTA")))
        if change.get("priority") == "URGENT_HUMAN_REVIEW":
            row["reason"].add("SOURCE_URGENT_HUMAN_REVIEW")

    for linked in native["unchanged_grant_request_dependencies"]:
        if type(linked) is not dict or linked.get("authority_claim") is not False:
            raise ReviewHold("original dependent unchanged grant claims authority")
        gid=linked.get("original_grant_id")
        grant=indexed["grants"].get(gid) if type(gid) is str else None
        if grant is None or grant.get("approved_request_id") != linked.get("recorded_request_id"):
            raise ReviewHold("native dependent grant differs from original current source")
        row=item("grants", gid, grant.get("engagement_id"))
        row["reason"].add("RECORDED_REQUEST_CHANGED_EVEN_THOUGH_GRANT_UNCHANGED")
        request=linked.get("recorded_request_id")
        if type(request) is str:
            row["reason"].add("RECHECK_ORIGINAL_REQUEST_"+request)

    if len(agenda["items"]) > 200:
        raise ReviewHold("original window agenda exceeds source bound")
    for window in agenda["items"]:
        if type(window) is not dict:
            raise ReviewHold("original window event malformed")
        gid=window.get("grant_id")
        grant=indexed["grants"].get(gid) if type(gid) is str else None
        if grant is None:
            raise ReviewHold("original window item has no current grant source")
        row=item("grants",gid,grant.get("engagement_id"))
        day=window.get("review_date_utc")
        if type(day) is not str or len(day)!=10:
            raise ReviewHold("original human review day unavailable")
        row["review_day"]=day
        if window.get("human_priority") == "HOLD":
            row["reason"].add("ORIGINAL_WINDOW_HUMAN_HOLD")
        elif window.get("human_priority") != "REVIEW_ONLY":
            raise ReviewHold("unknown source window human priority")
        row["source_attention"]=window.get("original_link_observation")

    for case in current["case_overview"]:
        eid=case["engagement_id"]
        if (case["grant_count"]==0 or
                case["attention"].startswith("HOLD_") or
                case["attention"]=="RISK_DECISION_PENDING_SOURCE_REVIEW"):
            row=item("engagements",eid,eid)
            if case["grant_count"]==0:
                row["reason"].add("NO_ORIGINAL_GRANT_RECORDED")
            if case["attention"].startswith("HOLD_"):
                row["reason"].add("ORIGINAL_CASE_ATTENTION_HOLD")
            if case["attention"]=="RISK_DECISION_PENDING_SOURCE_REVIEW":
                row["reason"].add("ORIGINAL_RISK_SOURCE_PENDING")
            row["source_attention"]=case["attention"]

    values=[]
    for row in tasks.values():
        priorities=("HOLD" in " ".join(row["reason"]) or
                    "URGENT" in " ".join(row["reason"]) or
                    "NO_ORIGINAL_GRANT" in row["reason"] or
                    "RECORDED_REQUEST_CHANGED_EVEN_THOUGH_GRANT_UNCHANGED" in row["reason"])
        row["human_priority"]="HOLD" if priorities else "REVIEW_ONLY"
        values.append(row)
    values.sort(key=lambda x:(x["human_priority"]!="HOLD",x["review_day"] or "9999-12-31",x["family"],x["id"]))
    metrics={
        "status": "HOLD_HUMAN_REVIEW",
        "original_source_issuer_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "execution_allowed": False,
        "release_approved": False,
        "queued_original_items": len(values),
        "human_hold": sum(x["human_priority"]=="HOLD" for x in values),
        "recorded_request_linked_unchanged_grants": len(native["unchanged_grant_request_dependencies"]),
        "original_no_grant_engagements": sum(x["grant_count"]==0 for x in current["case_overview"]),
    }
    stats="".join(
        '<div class="stat"><strong>'+_label(value)+'</strong>'+_label(label)+'</div>'
        for label,value in (
            ("Original source items",metrics["queued_original_items"]),
            ("Human source HOLD",metrics["human_hold"]),
            ("Unchanged grant / changed request",metrics["recorded_request_linked_unchanged_grants"]),
            ("Original engagements without grant",metrics["original_no_grant_engagements"]),
        )
    )
    cards=[]
    for row in values:
        fields=[
            ("Recorded engagement",row["engagement"] or "none in recorded source"),
            ("Human review date (UTC)",row["review_day"] or "no recorded window date"),
            ("Original source observation",row["source_attention"] or "not recorded"),
        ]
        pairs="".join("<dt>"+_label(key)+"</dt><dd>"+_label(val)+"</dd>" for key,val in fields)
        reasons="".join("<li>"+_label(reason)+"</li>" for reason in sorted(row["reason"]))
        cards.append(
            '<article class="entry '+("hold" if row["human_priority"]=="HOLD" else "review")+'">'
            '<div class="tag">'+_label(row["human_priority"])+" · HUMAN ONLY</div>"
            '<h2>'+_label(row["family"])+" / "+_label(row["id"])+'</h2>'
            "<dl>"+pairs+"</dl><ul>"+reasons+"</ul></article>"
        )
    style_hash=base64.b64encode(sha256(STYLE.encode()).digest()).decode()
    script_hash=base64.b64encode(sha256(SCRIPT.encode()).digest()).decode()
    csp=("default-src 'none'; style-src 'sha256-"+style_hash+
         "'; script-src 'sha256-"+script_hash+
         "'; connect-src 'none'; img-src 'none'; font-src 'none'; object-src 'none';"
         " form-action 'none'; base-uri 'none'")
    html=(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="'+_label(csp)+'">'
        '<title>LightUp · Original Source Human Priority Queue</title><style>'+STYLE+'</style></head>'
        '<body><p class="eyebrow">LIGHTUP / PRIVATE / SOURCE-BOUND / OFFLINE</p>'
        '<h1>Original scope · human priorities</h1>'
        '<p>Original Casebook changes, unchanged grants linked to changed requests, '
        'and original Window Review/engagement human attention in one private list. '
        'Read-only historical source, never a verified grant, STOP clearance, consent '
        'or permission to touch a target.</p>'
        '<div class="cards">'+stats+'</div>'
        '<label for="q">Search private source IDs and recorded attention</label>'
        '<input id="q" type="search" placeholder="Search only this local private page">'
        '<p class="counts"><span id="visible">'+str(len(values))+'</span> visible source items</p>'
        '<main>'+"".join(cards)+'</main>'
        '<footer><strong>HUMAN HOLD, NOT AUTHORIZATION.</strong> Local-only source '
        'correlation of unsigned historical records. Explicit original current source '
        're-authentication, independent client/operator consent, action-time STOP/revocation, '
        'owner/security/privacy review, exact-head CI and HUMAN GO remain required.</footer>'
        '<script>'+SCRIPT+'</script></body></html>\n'
    )
    if len(html.encode("utf-8"))>2*1024*1024:
        raise ReviewHold("human source priority page exceeds private bound")
    return html.encode("utf-8"),metrics
