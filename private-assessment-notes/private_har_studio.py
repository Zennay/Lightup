"""Source-free, CSP-pinned standalone PRIVATE HAR HUMAN status studio."""
from __future__ import annotations

import base64
from hashlib import sha256
from html import escape
from pathlib import Path

from private_har_worklist import entries

STATES = (
    ("PENDING_HUMAN", "Pending HUMAN review"),
    ("IN_PROGRESS", "In progress (unverified)"),
    ("SOURCE_OWNER_NEEDED", "Original source owner needed"),
    ("WITHHOLD", "Withhold / escalate privately"),
    ("HUMAN_REVIEWED", "Human-marked reviewed (not clearance)"),
)


def render(rows: list[dict]) -> bytes:
    tasks = entries(rows)
    if not 1 <= len(rows) <= 12 or not 1 <= len(tasks) <= 96:
        raise ValueError("PRIVATE HAR studio source bounds exceeded")
    source = Path(__file__).with_suffix(".js").read_bytes()
    integrity = base64.b64encode(sha256(source).digest()).decode("ascii")
    cards = []
    for record in tasks:
        ordinal = record["original_ordinal"]
        area = record["review_area"]
        count = record["literal_cue_count"]
        instruction = record["next_human_action"]
        if (type(ordinal) is not int or not 1 <= ordinal <= 12
                or type(count) is not int or not 0 <= count <= 65536
                or any(type(value) is not str or len(value) > 256
                       for value in (area, instruction))):
            raise ValueError("invalid source-free task identity")
        attributes = (
            ' data-action="1" data-ordinal="' + str(ordinal) +
            '" data-area="' + escape(area, quote=True) +
            '" data-count="' + str(count) +
            '" data-task="' + escape(instruction, quote=True) + '"'
        )
        select = "".join(
            '<option value="' + escape(status, quote=True) + '">' +
            escape(label) + '</option>' for status, label in STATES
        )
        cards.append(
            '<tr' + attributes + '><th scope="row">Original #' + str(ordinal) +
            '</th><td>' + escape(area.replace("_", " ")) +
            '</td><td>' + str(count) + ' literal markers</td><td>' +
            escape(instruction) + '</td><td><label class="sr" for="s-' +
            str(len(cards)) + '">Manual HUMAN status</label><select id="s-' +
            str(len(cards)) + '" data-status>' + select + '</select></td></tr>'
        )
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';script-src 'sha256-""" + integrity + """';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none';img-src 'none'">
<title>LightUp PRIVATE HAR HUMAN Status Studio</title>
<style>
:root{font:16px/1.5 system-ui;color:#142d40;background:#eff3f7}
*{box-sizing:border-box}body{max-width:1220px;margin:0 auto;padding:1.3rem}
header,section,footer{background:white;border:1px solid #d1d9e1;border-radius:12px;
padding:1.15rem;margin:1rem 0}
h1{margin:.25rem 0;font-size:clamp(1.55rem,3vw,2.4rem)}
h2{font-size:1.25rem}
aside{border-left:5px solid #b05d38;background:#fff0e7;padding:1rem}
.controls{display:flex;align-items:end;flex-wrap:wrap;gap:1rem}
label{display:block;font-weight:600}
input,select,button{font:inherit;border:1px solid #647d90;border-radius:7px;
padding:.65rem;min-height:44px}
button{background:#174e71;color:white;font-weight:700;cursor:pointer}
button:focus-visible,input:focus-visible,select:focus-visible{outline:3px solid #bc6b23}
button:disabled{opacity:.5;cursor:not-allowed}
#notice{min-height:2em;font-weight:bold}
#counter{font-weight:bold}
table{border-collapse:collapse;width:100%}
td,th{text-align:left;vertical-align:top;border-bottom:1px solid #cbd5df;padding:.65rem}
thead{background:#edf3f7}
table select{max-width:250px}
.table-scroller{overflow-x:auto}
tr[hidden]{display:none}
.sr{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0,0,0,0)}
@media(max-width:720px){table{font-size:13px}td,th{padding:.4rem}}
@media print{body{background:white}button,.controls{display:none}
tr{break-inside:avoid}}
</style>
<header><h1>PRIVATE HAR HUMAN Status Studio</h1>
<aside><b>INCUBATE · PLAN/LAB ONLY · REVIEW_ONLY/HOLD.</b>
This is an offline, human-edited work plan — not a credential/PII classifier,
privacy review, source-authentication certificate, consent, grant, security
finding, assessment runtime, or authority to send/share/scan/deploy.
Nothing is uploaded or saved in browser storage. Literal masking markers can
occur in raw source text and absence proves nothing.</aside>
<p>Only original positions, generic task text and literal placeholder counts
are embedded. No original source content, identity, filename, URL, hash,
secret or HUMAN notes are included.</p></header>
<section><h2>Filter and change HUMAN task proposals</h2>
<p>All original rows are retained in export even when filtered. Only a human
can individually select HUMAN_REVIEWED; bulk actions cannot mark work reviewed.
A status is self-reported and never independently verified.</p>
<div class="controls">
<label>Search original/task<input id="search" type="search" autocomplete="off"
placeholder="Original # or review area"></label>
<label>Status filter<select id="filter"><option value="ALL">All statuses</option>""" + "".join(
        '<option value="' + escape(key) + '">' + escape(label) + '</option>'
        for key, label in STATES
    ) + """</select></label>
<label>Bulk action<select id="bulk">
<option value="PENDING_HUMAN">Pending HUMAN</option>
<option value="IN_PROGRESS">In progress</option>
<option value="SOURCE_OWNER_NEEDED">Source owner needed</option>
<option value="WITHHOLD">Withhold</option></select></label>
<button id="apply" type="button">Apply to visible tasks</button>
<button id="undo" type="button" disabled>Undo bulk</button>
</div><p id="counter" role="status"></p>
<p>Review all changed task statuses against the privately held original
materials. Filtering and local status selection have no security effects.</p></section>
<section><h2>Continue a PRIVATE HUMAN status draft</h2>
<label>Reopen locally exported original action CSV
<input id="resume" type="file" accept=".csv,text/csv"></label>
<p>Strict local import reads no more than 64 KiB. Every original ordinal,
task identity, count, instruction and row order must match before any statuses
change. It never uploads a file. Any mismatch refuses the entire draft.</p>
<button id="save" type="button">Save complete PRIVATE action CSV</button>
<p id="notice" role="status"></p>
<p><b>Privacy step:</b> browser downloads may be saved with permissive
filesystem modes. Move them into a trusted 0700 directory and chmod 0600
before running <code>notes.py har-action-progress</code>. Never modify the
original source-bound cue receipt files. This editor is not a finalizer.</p>
</section><section class="table-scroller"><h2>All original HUMAN tasks</h2>
<table><thead><tr><th>Source</th><th>Area</th><th>Source-minimal cue count</th>
<th>Human question</th><th>Manual unverified status</th></tr></thead><tbody>""" + "".join(cards) + """</tbody></table></section>
<footer>No network, target interaction, execution, grant, model, clipboard,
telemetry, persistent storage or authority transition. All output stays
PRIVATE/HOLD pending independent source-owner review and explicit HUMAN GO.
</footer><script>""" + source.decode("utf-8") + """</script></html>"""
    return document.encode("utf-8")
