"""Source-minimal, static private human operations dashboard for LightUp.

Standalone HTML has NO JavaScript or remote resource. It is built only from the
already-authenticated five-column source and never reveals finding identities.
"""
from __future__ import annotations

import base64
import hashlib
from html import escape

MAX_BYTES = 24 * 1024
SEVERITIES = ("critical", "high", "medium", "low", "info")
MAX_ROWS = 350
CSS = """
:root{color-scheme:dark;font-family:Inter,ui-sans-serif,system-ui,-apple-system,Arial,sans-serif}
*{box-sizing:border-box}
body{margin:0;background:#08121c;color:#eef4f7;line-height:1.55}
main{max-width:1150px;margin:auto;padding:3rem 1.4rem 5rem}
header{border-bottom:1px solid #233645;background:#0b1b29}
nav{max-width:1150px;margin:auto;padding:1.1rem 1.4rem;display:flex;justify-content:space-between;align-items:center;gap:1rem;flex-wrap:wrap}
.logo{font-weight:850;letter-spacing:.065em;font-size:1.1rem;color:#e6fbfa}
.phase{border:1px solid #52697b;border-radius:999px;padding:.3rem .7rem;font-size:.78rem;letter-spacing:.06em;color:#b9d8e3}
.kicker{color:#7bd9d0;font-weight:740;font-size:.78rem;letter-spacing:.16em;text-transform:uppercase}
h1{font-size:clamp(2rem,5vw,3.6rem);line-height:1.1;letter-spacing:-.045em;margin:.75rem 0 1rem;max-width:800px}
h2{font-size:1.15rem;letter-spacing:-.02em}
.lead{color:#c2d1da;max-width:760px;font-size:1.06rem}
.rail{margin:2rem 0;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:1rem}
.metric{background:#122634;border:1px solid #314858;border-radius:18px;padding:1.25rem}
.metric strong{display:block;font-size:2.35rem;line-height:1;font-variant-numeric:tabular-nums;margin-bottom:.6rem;color:#f5fbfa}
.metric span{color:#a6c0cd;font-size:.87rem}
.warning{border-left:3px solid #dab874;padding:.9rem 1rem;background:#1f2630;color:#f0dcb7;border-radius:0 10px 10px 0;margin:2rem 0}
.warning strong{color:#ffecb8}
.cards{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:1rem;margin-top:1.3rem}
.card{border:1px solid #2b4757;border-radius:17px;background:#102332;display:flex;flex-direction:column;min-height:188px;padding:1.4rem;text-decoration:none;color:inherit;transition:border-color .15s,transform .15s}
.card:hover,.card:focus-visible{border-color:#66d4cb;transform:translateY(-2px);outline:none}
.card .number{color:#7bd9d0;font-size:.78rem;font-weight:800;letter-spacing:.1em}
.card h3{font-size:1.2rem;margin:.6rem 0 .4rem}
.card p{margin:.1rem 0 1rem;color:#a9bdc9}
.card .action{margin-top:auto;color:#94efe2;font-weight:700;font-size:.91rem}
.card.wide{grid-column:1/-1}
.foot{border-top:1px solid #284150;margin-top:2.5rem;padding-top:1.4rem;color:#a7bdca;font-size:.9rem}
.foot ul{padding-left:1.15rem;max-width:900px}
.foot li{margin:.45rem 0}
@media(max-width:700px){main{padding:2rem 1rem 4rem}.rail{grid-template-columns:1fr;gap:.6rem}.metric strong{font-size:1.8rem}.cards{grid-template-columns:1fr}.card.wide{grid-column:auto}}
@media(prefers-reduced-motion:reduce){.card{transition:none}.card:hover{transform:none}}
"""

def _safe_source(rows: list[dict[str, str]]) -> dict[str, int]:
    if type(rows) is not list or not 1 <= len(rows) <= MAX_ROWS:
        raise ValueError("Original source membership not admitted.")
    seen = set()
    counts = dict.fromkeys(SEVERITIES, 0)
    keys = {"finding_id","title","severity","retest_status","remediation"}
    for row in rows:
        if type(row) is not dict or set(row) != keys or any(type(v) is not str for v in row.values()):
            raise ValueError("Original five-column source contract changed.")
        fid = row["finding_id"]
        if not fid or fid in seen or row["severity"] not in counts:
            raise ValueError("Original source membership or source-labelled severity ambiguous.")
        seen.add(fid)
        counts[row["severity"]] += 1
    return counts

def build_portal(rows: list[dict[str,str]], history_count: int, human_present: bool, previous_source: list[dict[str,str]] | None = None) -> bytes:
    """Render only source-labelled aggregates and local literal navigation targets."""
    counts = _safe_source(rows)
    if type(history_count) is not int or not 0 <= history_count <= 12 or type(human_present) is not bool:
        raise ValueError("Historical/HUMAN workbench provenance malformed.")
    high = counts["critical"] + counts["high"]
    drift = None
    if previous_source is not None:
        _safe_source(previous_source)
        old={row["finding_id"]:row for row in previous_source}
        now={row["finding_id"]:row for row in rows}
        drift={
            "changed":sum(now[k]!=old[k] for k in now.keys() & old.keys()),
            "added":len(now.keys()-old.keys()),
            "absent":len(old.keys()-now.keys())
        }
    cards = [
        ("01","Original finding review","01-review.html",
         "Read source claims, priorities and original remediation suggestions. Historical labels are not verified fixes."),
        ("02","HUMAN Ticket Desk","02-ticketdesk.html",
         "Draft owners, proposed engineering tickets and follow-up plans without sending or authorizing work."),
        ("03","Original Casework","03-casework.html",
         "Private owner/date/blocker planning; a HUMAN completed label does not prove a retest."),
    ]
    if history_count:
        cards.append(("04","Original source history","04-history.html",
           "Compare exactly "+str(history_count)+" older PRIVATE snapshots with today's authenticated source, without inferring closure."))
    cards.append(("05","Evidence Artifact Ledger","05-evidence-ledger.html",
       "Local source-bound evidence fingerprints, reviewer notes, human requests"+
       (" and separately previewable encrypted HUMAN collaboration." if human_present else ". No HUMAN notes were supplied.")))
    cards.append(("06","Unified HUMAN action board","06-human-actions.html",
       "Prioritised original finding labels, owner workload, LOCAL evidence gaps and HUMAN requests"+
       (" from the separately opened private workroom." if human_present else ". Add encrypted HUMAN notes to see owners and requests.")))
    def card(row: tuple[str,str,str,str]) -> str:
        n,title,href,detail=row
        return ('<a class="card'+(' wide' if n == "05" else '')+'" href="'+escape(href,quote=True)+'">'
                '<span class="number">WORKSPACE '+escape(n)+'</span><h3>'+escape(title)+'</h3>'
                '<p>'+escape(detail)+'</p><span class="action">Open private offline screen →</span></a>')
    csp_hash=base64.b64encode(hashlib.sha256(CSS.encode("utf-8")).digest()).decode("ascii")
    csp=("default-src 'none'; connect-src 'none'; script-src 'none'; "
         "style-src 'sha256-"+csp_hash+"'; img-src 'none'; font-src 'none'; "
         "form-action 'none'; object-src 'none'; base-uri 'none'; frame-src 'none'")
    drift_html = ""
    if drift is not None:
        drift_html=(
            '<section aria-label="Private historical original source changes">'
            '<h2>Source changes since latest PRIVATE previous snapshot · HUMAN re-review</h2>'
            '<div class="rail">'
            '<div class="metric"><strong>'+str(drift["changed"])+
            '</strong><span>Changed original source records · not verified</span></div>'
            '<div class="metric"><strong>'+str(drift["added"])+
            '</strong><span>Added original source records · HUMAN follow-up</span></div>'
            '<div class="metric"><strong>'+str(drift["absent"])+
            '</strong><span>Absent from current source · NOT resolved</span></div>'
            '</div><p class="lead">Previous snapshots are PRIVATE historical claims, '
            'not authenticated current findings or remediation evidence. '
            '<a href="06-human-actions.html">Review source-bound HUMAN attention →</a></p>'
            '</section>'
        )
    html=('<!doctype html><html lang="en"><head><meta charset="utf-8">'
          '<meta name="viewport" content="width=device-width,initial-scale=1">'
          '<meta http-equiv="Content-Security-Policy" content="'+escape(csp,quote=True)+'">'
          '<title>LightUp · PRIVATE human operations</title><style>'+CSS+'</style></head><body>'
          '<header><nav aria-label="Workroom status"><div class="logo">LIGHTUP / HUMAN OPERATIONS</div>'
          '<span class="phase">INCUBATE · M3/M7 · DRAFT/HOLD</span></nav></header>'
          '<main><p class="kicker">Authenticated source read · private device · offline only</p>'
          '<h1>One private workroom. Original tools and HUMAN action board.</h1>'
          '<p class="lead">Review evidence references and coordinate human remediation across unchanged '
          'original LightUp applications. The source was read under original account and client permissions '
          'before this local folder was created. Nothing here grants assessment authority.</p>'
          '<section class="rail" aria-label="Original source-only counts">'
          '<div class="metric"><strong>'+str(len(rows))+'</strong><span>original source findings (unverified labels)</span></div>'
          '<div class="metric"><strong>'+str(high)+'</strong><span>source-labelled critical/high (NOT verified exposure)</span></div>'
          '<div class="metric"><strong>'+str(history_count)+'</strong><span>older PRIVATE source revisions (not true retests)</span></div>'
          '</section>'+drift_html+
          '<aside class="warning" role="note"><strong>HUMAN HOLD:</strong> '
          'A locally encrypted note or SHA-256 match is not proof of remediation, authenticity, '
          'client consent, current operator permission or a verified retest. '
          'Only separately authorized work may ever contact a target.</aside>'
          '<section aria-labelledby="tools-title"><h2 id="tools-title">Original private workspaces</h2>'
          '<div class="cards">'+''.join(card(row) for row in cards)+'</div></section>'
          '<section class="foot"><h2>Privacy and source boundaries</h2><ul>'
          '<li>All links open local 0600 HTML files inside this single owner-only 0700 folder. '
          'Never upload, share publicly or serve this folder.</li>'
          '<li>Source-reported missing, fixed, severity and regression fields remain unverified; '
          'a missing row never means remediated.</li>'
          '<li>Human evidence drafts, requests, owners and notes never issue grants, consent, '
          'a retest, an execution permit or a release decision.</li>'
          '<li>Re-authenticate and obtain independent client/operator consent at action time, '
          'including revocation checks, before any separately authorized future work.</li>'
          '</ul><p>No JavaScript, remote images, fonts, network, persistent browser storage or hidden '
          'services are used by this navigation page.</p></section></main></body></html>')
    data=html.encode("utf-8","strict")
    if len(data)>MAX_BYTES or "</script" in html.lower() or "<link " in html.lower():
        raise ValueError("Standalone private workroom dashboard exceeded offline boundary.")
    return data
