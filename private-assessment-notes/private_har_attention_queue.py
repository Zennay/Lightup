"""Source-minimal scriptless HUMAN HAR review queue; no release authority."""
from __future__ import annotations

from html import escape
from private_har_hold_board import HAR_CATEGORIES, inventory


def render(rows: list[dict]) -> bytes:
    records = inventory(rows)
    groups = []
    for label, _markers in HAR_CATEGORIES:
        field = label + "_literal_markers"
        found = [r for r in records if r[field]]
        links = "".join(
            '<li><a href="#original-' + str(r["original_ordinal"]) +
            '">Original #' + str(r["original_ordinal"]) + '</a>: ' +
            str(r[field]) + ' literal markers</li>'
            for r in found
        )
        groups.append('<details><summary>' + escape(label.replace("_", " ").title()) +
                      ' — ' + str(len(found)) +
                      ' source positions</summary><ol>' +
                      (links or '<li>Zero markers is NOT clearance.</li>') +
                      '</ol></details>')
    held = [r for r in records if r["whole_derived_copy_withheld"]]
    held_links = "".join('<li><a href="#original-' + str(r["original_ordinal"]) +
                         '">Original #' + str(r["original_ordinal"]) + '</a></li>'
                         for r in held)
    roster = "".join(
        '<li id="original-' + str(r["original_ordinal"]) +
        '">Original #' + str(r["original_ordinal"]) +
        ' — Private original HUMAN review required.</li>' for r in records
    )
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HAR human queue</title>
<style>body{font:16px/1.6 system-ui;max-width:930px;margin:2rem auto;padding:1rem}
aside{border-left:5px solid #98582d;background:#fff0e2;padding:1rem}
details{border:1px solid #ccd2da;padding:.7rem;margin:.8rem 0}
summary{cursor:pointer;font-weight:bold}a:focus-visible{outline:3px solid #905620}
@media print{body{margin:0;max-width:none}}</style>
<h1>PRIVATE source-ordinal HAR HUMAN attention queue</h1>
<aside><b>REVIEW ONLY / HOLD / NO DISCLOSURE.</b>
Literal marker counts are not detected secrets, privacy clearance, source
authenticity, a safe-sharing verdict or customer/operator consent. Zero
markers never means clean. Only source positions appear; no source content,
hashes, names, URLs, identities, credentials or HUMAN notes.</aside>
<p>Original sources: """ + str(len(records)) + """.
Wholly withheld derived copies: """ + str(len(held)) + """.</p>
<h2>Whole-copy HOLD</h2><ol>""" +
            (held_links or "<li>None marked; still requires HUMAN review.</li>") +
            "</ol><h2>Category navigation</h2>" + "".join(groups) +
            "<h2>Complete original roster</h2><ol>" + roster +
            """</ol><p>Consult privately held original sources outside this
overview. No scan, network, automatic action, grant or release.</p></html>"""
            ).encode("utf-8")
