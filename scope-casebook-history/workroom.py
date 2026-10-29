"""Private local-only HTML human caseboard builder for original Casebook data.

Static original-source reviewer input is already admitted by history.admit().
Only HUMAN workflow fields can change client-side; no backend/API/storage.
"""
from __future__ import annotations

import base64
import hashlib
from html import escape
from pathlib import Path

CSS = """
* {box-sizing:border-box}
:root{color-scheme:dark;font-family:system-ui,-apple-system,sans-serif}
body{margin:0;min-height:100vh;background:#101828;color:#e6effb;line-height:1.55}
.wrap{max-width:1480px;margin:0 auto;padding:28px clamp(16px,3vw,44px)}
header{display:flex;flex-wrap:wrap;justify-content:space-between;gap:12px;align-items:center}
h1{font-size:clamp(1.5rem,3vw,2.35rem);margin:0}
h2{font-size:1.2rem}
p{max-width:1100px;color:#cbd6e8}
a{color:#9eeddc}
small,.muted{color:#c3d0e3}
.hold{border:2px solid #b88857;border-radius:12px;padding:16px;background:#402d26;margin-top:22px}
.hold strong{color:#ffddb1}
.metrics{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin:20px 0}
.metric{background:#1b293e;padding:14px;border:1px solid #3c506e;border-radius:10px}
.metric span{display:block;font-size:.78rem;color:#cddcf0}
.metric strong{display:block;font-size:1.7rem;color:#a0ebd4}
.tools{display:flex;gap:12px;flex-wrap:wrap;align-items:end;margin:20px 0}
label{display:flex;flex-direction:column;gap:6px;font-weight:600;font-size:.8rem}
input,select,button{font:inherit;padding:10px;border:1px solid #617b96;border-radius:8px;color:#eef6ff;background:#182940;max-width:100%}
select{min-width:145px}
button{cursor:pointer;background:#234c58;border-color:#80cbb6;font-weight:700}
button:hover,button:focus-visible{background:#356674}
#search{min-width:min(400px,85vw)}
.data{overflow:auto;border:1px solid #3b516e;border-radius:12px}
.detail{border-top:1px solid #3b516e;padding-top:8px;font-size:.82rem}
details{max-width:320px}summary{cursor:pointer;color:#9eeddc}
details p{margin:7px 0;font-size:.83rem}
table{width:100%;border-collapse:collapse;min-width:1000px;font-size:.88rem}
th,td{padding:10px;border-bottom:1px solid #374d68;text-align:left;vertical-align:top;word-break:break-word}
th{background:#233851;position:sticky;top:0}
tr[hidden]{display:none}
td strong{display:block}
.warn{color:#ffd4aa}
#status{padding:10px 14px;border-radius:10px;background:#233951;min-height:45px}
#status[data-invalid="true"]{background:#5a3534;color:#fff}
footer{margin-top:30px;border-top:1px solid #445b76;padding-top:20px;color:#c1cee1}
.controls{display:flex;align-items:end;flex-wrap:wrap;gap:10px}
@media (max-width:640px){.wrap{padding:15px}.tools{display:block}.tools label{margin:8px 0}}
"""


def _hash(text: str) -> str:
    return base64.b64encode(hashlib.sha256(text.encode("utf-8")).digest()).decode("ascii")


def _select(name: str, options: tuple[str, ...], initial: str) -> str:
    assert initial in options
    rows = []
    for option in options:
        selected = " selected" if option == initial else ""
        rows.append(f'<option value="{escape(option, quote=True)}"{selected}>'
                    f'{escape(option)}</option>')
    return f'<select class="{escape(name)}" aria-label="{escape(name)} HUMAN selection">' + "".join(rows) + "</select>"


def render(*, source_queue: list[dict], source_details: list[list[object]],
           human_stages: tuple[str, ...], human_routes: tuple[str, ...],
           human_blockers: tuple[str, ...]) -> bytes:
    """Portable, locally editable PRIVATE app, never an original grant handler."""
    if len(source_queue) > 200 or len(source_details) > 600:
        raise ValueError("original current Casebook source records exceed private workroom bound")
    original_ids = {str(row["local_original_engagement_id"]) for row in source_queue}
    if any(len(detail) != 6 or str(detail[0]) not in original_ids for detail in source_details):
        raise ValueError("original source-detail lineage does not match source workroom")
    detail_map: dict[str, list[list[object]]] = {}
    for detail in source_details:
        detail_map.setdefault(str(detail[0]), []).append(detail)

    file = Path(__file__).with_name("workroom.js")
    javascript = file.read_text(encoding="utf-8")
    # This is a repository-owned static file, not source-derived JS or input.
    if "</script" in javascript.lower():
        raise ValueError("invalid original workroom script fragment")
    css_payload = "\n" + CSS + "\n"
    js_payload = "\n" + javascript + "\n"
    sheet = []
    for record in source_queue:
        ident = str(record["local_original_engagement_id"])
        action = str(record["source_next_human_action"])
        attention = str(record["source_attention"])
        status = str(record["source_status"])
        source_context = detail_map.get(ident, [])
        case_details = [
            '<details><summary>Original recorded grants / risks</summary>'
            '<p>Recorded source only; NEVER a verified grant or current consent.</p>'
        ]
        for item in source_context:
            case_details.append(
                '<p class="detail"><strong>' + escape(str(item[1])) + '</strong><br>'
                + 'Record: ' + escape(str(item[2]))
                + '<br>Recorded source state: ' + escape(str(item[3]))
                + '<br>Original HUMAN action: ' + escape(str(item[4]))
                + ('<br>Original request: ' + escape(str(item[5])) if item[5] else '')
                + '</p>'
            )
        case_details.append('</details>')
        cells = [
            f'<td><strong>{escape(ident)}</strong><small>Source only, never a target</small></td>',
            f'<td>{escape(status)}</td>',
            f'<td>{escape(attention)}</td>',
            f'<td>{escape(action)}</td>',
            f'<td>{_select("stage", human_stages, "unreviewed")}</td>',
            f'<td>{_select("route", human_routes, "unassigned")}</td>',
            f'<td>{_select("blocker", human_blockers, "none")}</td>',
            '<td>' + "".join(case_details) + '</td>',
        ]
        sheet.append(
            f'<tr data-case="{escape(ident, quote=True)}"'
            f' data-action="{escape(action, quote=True)}"'
            f' data-attention="{escape(attention, quote=True)}">'
            + "".join(cells) + "</tr>"
        )
    policy = (
        "default-src 'none'; "
        f"style-src 'sha256-{_hash(css_payload)}'; "
        f"script-src 'sha256-{_hash(js_payload)}'; "
        "connect-src 'none'; img-src 'none'; object-src 'none'; "
        "frame-src 'none'; form-action 'none'; base-uri 'none'"
    )
    html_text = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width, initial-scale=1">'
        '<meta name="referrer" content="no-referrer">'
        f'<meta http-equiv="Content-Security-Policy" content="{escape(policy, quote=True)}">'
        '<title>LightUp | PRIVATE HUMAN Casebook Workroom</title>'
        f'<style>{css_payload}</style></head><body><main class="wrap">'
        '<header><h1>LightUp | PRIVATE HUMAN Casebook Workroom</h1>'
        '<nav aria-label="Private original source">'
        '<a href="index.html">Original source history</a> · '
        '<a href="workroom-current-template.csv">Source-bound CSV template</a>'
        '</nav></header>'
        '<div class="hold"><strong>DRAFT / HOLD — NEVER AN AUTHORIZATION</strong>'
        '<p>Only the LAST original Casebook packet is shown here. Source rows are unverified declarations, '
        'not live grants, current client/operator consent, remediation, risk decisions, or revocation evidence. '
        'Editable fields track local HUMAN follow-up ONLY. No target activity, scanner, account, network or backend.</p>'
        '</div>'
        '<h2>Local HUMAN progress</h2><section id="totals" class="metrics" aria-live="polite"></section>'
        '<div class="tools"><label>Filter source cases<input id="search" type="search" '
        'placeholder="Source engagement or action" autocomplete="off"></label>'
        '<label>HUMAN stage<select id="stage-filter"><option value="">All stages</option>'
        + "".join(f'<option value="{escape(v)}">{escape(v)}</option>' for v in human_stages) +
        '</select></label><label>Original source category<select id="source-filter">'
        '<option value="">All original categories</option><option value="hold">HOLD source only</option>'
        '<option value="not-hold">Other source labels</option></select></label></div>'
        '<div class="data"><table><thead><tr><th scope="col">Original engagement ID</th>'
        '<th scope="col">Original status</th><th scope="col">Original attention</th>'
        '<th scope="col">Original next HUMAN action</th><th scope="col">Local HUMAN stage</th>'
        '<th scope="col">Local follow-up route</th><th scope="col">Local blocker</th>'
        '<th scope="col">PRIVATE original dossier</th>'
        '</tr></thead><tbody id="cases">' + "".join(sheet) + '</tbody></table></div>'
        '<h2>Keep your private HUMAN selections</h2>'
        '<p>This browser tab does not save anything automatically. '
        'Export a PRIVATE CSV, or restore a CSV from this EXACT original source report. '
        'The separate ID-free HUMAN workload export contains stage/route/blocker counts only, '
        'but small-group counts may still be sensitive. '
        'Import refuses changed original engagement IDs/actions, extra/missing rows, '
        'unknown human labels, and malformed CSV. Never share raw case IDs publicly.</p>'
        '<div class="controls"><button type="button" id="export">Export PRIVATE HUMAN CSV</button>'
        '<button type="button" id="export-summary">Export ID-free HUMAN workload counts</button>'
        '<label>Select prior PRIVATE CSV<input type="file" id="import-file" accept=".csv,text/csv"></label>'
        '<button type="button" id="import">Restore PRIVATE HUMAN CSV</button>'
        '<button type="button" id="reset">Clear local HUMAN stages</button></div>'
        '<p role="status" aria-live="polite" id="status"></p>'
        '<footer>Offline in one file. Source labels and human choices are UNSIGNED, not verified consent, '
        'not a PASS or release. Return to the real current authenticated LightUp source for actual review. '
        'Original owners and mandatory release gates unchanged.</footer>'
        f'</main><script>{js_payload}</script></body></html>'
    )
    return html_text.encode("utf-8")
