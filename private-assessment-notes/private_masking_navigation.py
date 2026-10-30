"""PRIVATE source-minimal HUMAN masking-cue navigator (no authorization).

Only original ordinals and literal marker counts. No scripts, raw source,
identifying names, source hashes, notes, credentials or outcome claims.
"""
from __future__ import annotations

import html


COLUMNS = (
    ("HTTP / shell", "literal_http_or_shell_markers"),
    ("URL / session", "literal_url_or_session_markers"),
    ("Structured config", "literal_config_markers"),
    ("Tokens / keys", "literal_token_or_key_markers"),
)


def render(rows: list[dict]) -> bytes:
    sections = []
    for title, field in COLUMNS:
        relevant = sorted(
            (row for row in rows if row[field]),
            key=lambda row: (-row[field], row["original_ordinal"]),
        )
        anchors = "".join(
            "<li><a href='#source-" + str(row["original_ordinal"]) + "'>Original #" +
            str(row["original_ordinal"]) + "</a>: " + str(row[field]) +
            " literal marker occurrences</li>" for row in relevant
        )
        sections.append(
            "<details><summary>" + html.escape(title) + " — " +
            str(len(relevant)) + " originals / " +
            str(sum(row[field] for row in rows)) +
            " literal marker occurrences</summary><ol>" +
            (anchors or "<li>No literal markers (NOT clearance)</li>") +
            "</ol></details>"
        )
    complete = []
    for row in rows:
        ordinal = str(row["original_ordinal"])
        cells = "".join("<td>" + str(row[field]) + "</td>" for _, field in COLUMNS)
        complete.append(
            "<tr id='source-" + ordinal + "'><th scope='row'>Original #" +
            ordinal + "</th>" + cells + "<td>" +
            str(row["literal_total_markers"]) + "</td></tr>"
        )
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN original masking-cue navigation</title>
<style>body{max-width:1050px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui;color:#1c2f42}
aside{border-left:5px solid #a65d2b;background:#fff2e8;padding:1rem}
details{border:1px solid #ccd6de;border-radius:8px;margin:.8rem 0;padding:1rem}
summary{cursor:pointer;font-weight:700}details ol{columns:2}
a{color:#145881}a:focus-visible{outline:3px solid #aa6620}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{padding:.6rem;border:1px solid #c6d2dd;text-align:left}
thead{background:#eef3f7}tr:target{outline:3px solid #a65d2b}
@media(max-width:650px){body{margin:0;padding:.6rem}table{font-size:12px}th,td{padding:4px}details ol{columns:1}}
@media print{body{max-width:none;margin:0}}</style>
<h1>PRIVATE original-source masking-cue navigator</h1>
<aside><strong>INCUBATE / PLAN-LAB ONLY / REVIEW_ONLY / HOLD.</strong>
Counts are only literal appearances of existing placeholder strings; they are NOT
proof that any credential was successfully masked, NOT a secret-detection score,
NOT evidence of anonymization, safety, authentication, consent or permission to
share. Unknown personal and client information may remain. No external action.</aside>
<p>Original source positions: """ + str(len(rows)) + """.
Only original ordinal positions and placeholder counts appear here; no source
names, content, SHA values, HUMAN notes or identifying metadata.</p>
<h2>Find original source positions for manual HUMAN inspection</h2>
<p>Open a category below to jump to original position rows; within each category
positions are sorted by literal count only, NEVER security severity. All original
positions still appear in the complete roster below, including zero counts.</p>
""" + "".join(sections) + """
<h2>Complete original position roster</h2><table><thead><tr>
<th scope="col">Original</th><th scope="col">HTTP / shell</th>
<th scope="col">URL / session</th><th scope="col">Structured config</th>
<th scope="col">Tokens / keys</th><th scope="col">Literal total</th>
</tr></thead><tbody>""" + "".join(complete) + """</tbody></table>
<p>Return to the original owner-private masked-note workroom and independently
review every selected source, including sources with zero markers. Neither the
original receipt nor this navigator clears disclosure, dispatch, assessment or
release. Separate HUMAN/privacy/security/consent checks remain mandatory.</p></html>"""
    return page.encode("utf-8")
