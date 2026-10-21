"""Source-minimal, static original-ordinal HAR HOLD attention board.

Only an advisory private HUMAN worklist. Marker appearance is not proof
of an actual credential, correct masking, provenance or grant.
"""
from __future__ import annotations

from private_har_gate import HOLD_MARKER


def render(rows: list[dict]) -> bytes:
    held = sum(row["redacted_text"] == HOLD_MARKER for row in rows)
    lines = []
    for row in rows:
        slot = int(row["ordinal"])
        withheld = row["redacted_text"] == HOLD_MARKER
        # Numbers only: no source text, hash, filenames, URL, client or notes.
        lines.append(
            "<tr><th scope='row'>Original #" + str(slot) + "</th>"
            "<td>" + ("WHOLE DERIVED COPY WITHHELD" if withheld
                       else "Inspect original source separately") +
            "</td><td>" + ("Original source required" if withheld
                           else "HUMAN verification required") + "</td></tr>"
        )
    document = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy"
content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE original HAR HUMAN HOLD desk</title>
<style>body{font:16px/1.6 system-ui;max-width:920px;margin:2rem auto;padding:1rem;color:#223040}
aside{border-left:5px solid #ae5b31;background:#fff0e8;padding:1rem}
table{border-collapse:collapse;width:100%;margin:1.5rem 0}
th,td{border:1px solid #aab8c9;padding:10px;text-align:left}
thead{background:#edf3f7}
@media print{body{margin:0;max-width:none}}</style>
<h1>PRIVATE original HAR HUMAN HOLD attention</h1>
<aside><strong>REVIEW_ONLY / HOLD / NO DISCLOSURE.</strong>
This local worklist contains only original ordinals and literal local
whole-copy-withheld status, NOT verified findings or a clearance verdict.
A source may contain a pre-existing marker. Zero withheld copies does
not establish that credentials, personal data or unrecognized HAR fields
were safely removed. No client/operator consent is inferred.</aside>
<p>Original sources: """ + str(len(rows)) + """. Whole derived note
copies visibly marked withheld: """ + str(held) + """.
Every original requires independent private HUMAN review.</p>
<table><thead><tr><th scope="col">Original position</th>
<th scope="col">Local derived note indicator</th>
<th scope="col">Human next step</th></tr></thead><tbody>""" + "".join(lines) + """</tbody></table>
<p>Open the original owner-private review workroom, locate the ordinal,
and inspect the original privately held source separately. Do not
share these derived notes or use this HTML as privacy verification,
authorization, a scan/grant request, a security verdict, or a release.
No network, scripts or automatic actions.</p></html>"""
    return document.encode("utf-8")
