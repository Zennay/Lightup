"""Scriptless PRIVATE original-source lineage explorer; never an authorization or verdict."""
from __future__ import annotations

import base64
import hashlib
from html import escape

from desk import CSS

MAX_HTML = 4*1024*1024
SEVERITY = ("critical","high","medium","low","info")


def _html(value):
    if type(value) is not str:
        raise ValueError("Noncanonical original source string")
    return escape(value, quote=True)


def _details(title, body, opened=False):
    return ("<details" + (" open" if opened else "") + "><summary>" +
            _html(title)+"</summary><div class=\"lineage-body\">"+body+"</div></details>")


def _plain_ids(ids, message):
    if not ids:
        return '<p class="muted">None in this source transition.</p>'
    return ('<p class="muted">'+_html(message)+'</p><ul>'+
            "".join("<li>"+_html(ident)+"</li>" for ident in ids)+"</ul>")


def _changed_rows(changed, prior, current):
    if not changed:
        return '<p class="muted">No textually changed original records.</p>'
    cards=[]
    for ident,fields in sorted(changed.items()):
        rows=["<article><h3>"+_html(ident)+"</h3><dl>"]
        for field in fields:
            rows.append("<dt>Earlier "+_html(field)+"</dt><dd>"+_html(prior[ident][field])+"</dd>")
            rows.append("<dt>Later "+_html(field)+"</dt><dd>"+_html(current[ident][field])+"</dd>")
        rows.append("</dl><p>Original source text drift only. HUMAN review required.</p></article>")
        cards.append("".join(rows))
    return '<div class="cards">'+"".join(cards)+"</div>"


EXTRA = """
meter{width:100%;height:1rem}
.stage{border-radius:14px;background:#fff;border:1px solid var(--line);padding:1rem;margin-bottom:1rem}
.stage h3{margin-bottom:.5rem}
.stage-head{display:flex;gap:.8rem;justify-content:space-between;align-items:baseline;flex-wrap:wrap}
.change-count{display:flex;flex-wrap:wrap;gap:.5rem}
.change-count span{padding:.2rem .6rem;background:#e5eff7;border-radius:8px;font-size:.88rem}
details{margin-top:.7rem;border:1px solid #b6cadb;border-radius:11px;background:#f8fbff}
summary{cursor:pointer;font-weight:700;padding:.65rem}
summary:focus-visible{outline:3px solid #6088b4;outline-offset:2px}
.lineage-body{padding:.6rem 1rem 1rem;overflow-wrap:anywhere}
li{margin:.22rem 0;overflow-wrap:anywhere}
.bar-shell{background:#e6eef5;height:11px;width:100%;border-radius:12px;overflow:hidden}
.bar-fill{background:#285b8b;height:100%}
.horizontal{display:grid;grid-template-columns:140px 1fr 60px;gap:.65rem;align-items:center;margin:.45rem 0}
@media(max-width:560px){.horizontal{grid-template-columns:100px 1fr 42px}}
@media print{details:not([open])>.lineage-body{display:block}}
"""


def build_history_desk(info):
    """Generate an offline browsable confidential HUMAN longitudinal report."""
    snapshots=info["snapshots"]
    if not 2<=len(snapshots)<=13 or len(info["transitions"])!=len(snapshots)-1:
        raise ValueError("Invalid bounded original lineage")
    content=[]
    for index,source in enumerate(snapshots,1):
        counts={s:sum(1 for item in source.values() if item["severity"]==s) for s in SEVERITY}
        scale=max(1,len(source))
        bars="".join(
            '<div class="horizontal"><span>'+_html(name.title())+'</span>'
            '<meter min="0" max="'+str(scale)+'" value="'+str(counts[name])+'">'+str(counts[name])+'</meter>'
            '<strong>'+str(counts[name])+'</strong></div>'
            for name in SEVERITY
        )
        label=("Current newly authenticated original source" if index==len(snapshots)
               else "Historical PRIVATE local source "+str(index))
        content.append(
            '<section class="stage"><div class="stage-head"><h3>Original snapshot '+
            str(index)+"</h3><span>"+_html(label)+"</span></div>"+
            '<p class="muted">'+str(len(source))+' original source IDs (not verified vulnerabilities)</p>'+
            bars+"</section>"
        )
    transitions=[]
    for t in info["transitions"]:
        old=snapshots[t["index"]-1]
        new=snapshots[t["index"]]
        summary=(
            "Added: "+str(len(t["added"]))+" · Absent: "+str(len(t["absent"]))+
            " · Changed: "+str(len(t["changed"]))+
            " · Original fixed-label changes (UNVERIFIED): "+str(len(t["unverified_fixed"]))
        )
        sections=[
            '<div class="change-count"><span>New original IDs '+str(len(t["added"]))+
            '</span><span>Absent HUMAN HOLD '+str(len(t["absent"]))+
            '</span><span>Changed source rows '+str(len(t["changed"]))+
            '</span><span>Textually unchanged '+str(t["unchanged"])+'</span></div>',
            _details("Newly present original IDs",_plain_ids(t["added"],"Requires separate HUMAN review.")),
            _details("Absent original IDs — never automatically resolved",
                     _plain_ids(t["absent"],"No longer present means UNKNOWN, not fixed.")),
            _details("Changed original fields",_changed_rows(t["changed"],old,new)),
            _details("Original retest label changed to fixed (UNVERIFIED)",
                     _plain_ids(t["unverified_fixed"],"A source label cannot verify remediation or retest.")),
        ]
        transitions.append(
            '<section class="stage"><h3>Original transition '+str(t["index"])+" → "+
            str(t["index"]+1)+"</h3><p>"+_html(summary)+"</p>"+
            "".join(sections)+"</section>"
        )
    tail=[
        _details("Reappeared original IDs after disappearance",
                 _plain_ids(info["reappeared"],"Possible original source churn. Not an independently verified regression."),
                 bool(info["reappeared"])),
        _details("Historically seen original IDs absent in current source",
                 _plain_ids(info["currently_absent"],"Still requires HUMAN confirmation; do not mark fixed."),
                 bool(info["currently_absent"])),
    ]
    css=CSS+EXTRA
    digest=base64.b64encode(hashlib.sha256(css.encode("utf-8")).digest()).decode("ascii")
    csp=("default-src 'none'; connect-src 'none'; img-src 'none'; object-src 'none'; "
         "form-action 'none'; base-uri 'none'; frame-src 'none'; "
         "style-src 'sha256-"+digest+"'; script-src 'none'")
    html=(
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="'+_html(csp)+'">'
        '<title>LightUp | PRIVATE original source history</title>'
        '<style>'+css+'</style></head><body><header>'
        '<small>LIGHTUP · HUMAN SOURCE HISTORY · OFFLINE</small>'
        '<h1>Private Original Source Continuity</h1>'
        '<p>Operator-ordered historical encrypted snapshots and a newly authenticated current source.</p>'
        '<div class="notice"><strong>DRAFT/HOLD · HUMAN REVIEW ONLY</strong><p>'
        'The order is operator supplied; no trusted timestamps inferred. '
        'All original finding and retest labels are unverified. A fixed or absent original '
        'finding is NOT repaired or retested. No consent, grant, target contact, '
        'remediation, verification or release is authorized by this local report.'
        '</p></div></header><main>'
        '<section><h2>Original severity distribution per local snapshot</h2>'
        '<p class="muted">Counts track original source labels, not actual security risk.</p>'+
        "".join(content)+"</section>"+
        '<section><h2>Original finding transitions</h2>'+
        "".join(transitions)+"</section>"+
        '<section><h2>HUMAN source ambiguity and follow-up</h2>'+
        "".join(tail)+"</section>"+
        '<footer>PRIVATE confidential source data may be shown. '
        'Local-only HTML, fixed hash-pinned CSS, no JavaScript, browser storage or network. '
        'Securely destroy this copy after authorized local human review.</footer>'
        '</main></body></html>'
    )
    raw=html.encode("utf-8","strict")
    if not 1<=len(raw)<=MAX_HTML:
        raise ValueError("PRIVATE original-source history HTML exceeds bound")
    return raw
