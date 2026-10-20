#!/usr/bin/env python3
"""PRIVATE original-byte membership change briefing, never status carry or authorization."""
from __future__ import annotations

import argparse
from html import escape

from history import Hold, STAGES, CLASSIFICATIONS, HOLD_FLAGS, HUMAN_FIELDS, publish_private, read_receipt


def _name(row):
    return "<strong>" + escape(row["alias"]) + "</strong>"


def _source(row):
    return "<code>" + escape(row["sha256"][:16]) + "…</code> · " + str(row["bytes"]) + " bytes"


def _human(row):
    stage = escape(STAGES[row["status"]])
    review = escape(row["review_date"]) or "geen menselijke datum"
    return (stage + " · review: " + review
            + "<br>HUMAN houder: " + escape(row["custodian"] or "NIET TOEGEWEZEN")
            + "<br>HUMAN gevoeligheid: " + escape(CLASSIFICATIONS[row["classification"]])
            + "<br>HUMAN bewaarbeperking: " + escape(HOLD_FLAGS[row["hold_flag"]]))


def build(old, new):
    """Display observations, never adopt a source identity or HUMAN decision."""
    for key in set(old) & set(new):
        if old[key]["bytes"] != new[key]["bytes"]:
            raise Hold("source SHA has conflicting byte lengths")
    before, after = set(old), set(new)
    added, absent, kept = sorted(after - before), sorted(before - after), sorted(before & after)
    changes = []
    for key in kept:
        fields = [field for field in HUMAN_FIELDS
                  if old[key][field] != new[key][field]]
        if fields:
            changes.append((key, fields))
    rows = []
    for key in added:
        row = new[key]
        rows.append("<tr><td class='add'>NIEUW in plan 2 (niet beoordeeld door deze vergelijking)</td><td>" +
                    _source(row) + "</td><td>—</td><td>" + _name(row) + "<br>" + _human(row) + "</td></tr>")
    for key in absent:
        row = old[key]
        rows.append("<tr><td class='absent'>NIET AANWEZIG in plan 2 — geen verwijderings-/herstelclaim</td><td>" +
                    _source(row) + "</td><td>" + _name(row) + "<br>" + _human(row) + "</td><td>—</td></tr>")
    for key, fields in changes:
        a, b = old[key], new[key]
        rows.append("<tr><td>Zelfde originele bytes, veranderde HUMAN-velden: " +
                    escape(", ".join(fields)) + "</td><td>" + _source(a) + "</td><td>" +
                    _name(a) + "<br>" + _human(a) + "</td><td>" + _name(b) +
                    "<br>" + _human(b) + "</td></tr>")
    if not rows:
        rows.append("<tr><td colspan='4'>Geen verschillen in bestandsaanwezigheid of HUMAN velden.</td></tr>")
    return """<!doctype html><html lang="nl"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN bronwijzigingen</title>
<style>body{font:16px/1.5 system-ui,sans-serif;max-width:1190px;margin:30px auto;padding:0 16px;color:#1a2532}
.banner{border:2px solid #a97131;background:#fff4df;padding:14px;border-radius:10px}table{border-collapse:collapse;width:100%}
th,td{border:1px solid #bec6ce;padding:10px;text-align:left;vertical-align:top}th{background:#eaf0f5}
.add{color:#175a3e;font-weight:700}.absent{color:#843c25;font-weight:700}
code{font-size:.82em;overflow-wrap:anywhere}
@media print{body{margin:0;font-size:11px}.banner{background:white}td,th{padding:4px}}</style></head><body>
<h1>PRIVATE · oorspronkelijke assessmentbron versus HUMAN planverschil</h1>
<p class="banner"><strong>INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.</strong>
Dit is een ongetekende vergelijking van twee door een mens aangeleverde PRIVATE plannen.
Bestandsgelijkheid berust uitsluitend op SHA-256 + bytes, niet op producent-, tenant-, client- of consent-authenticatie.
Een afwezige bron is <strong>NIET</strong> verwijderd, hersteld, ingetrokken of veilig bevonden.
HUMAN-labels en statussen zijn onbevestigde voorstellen; geen toestemming voor scan of wissen.
De planvolgorde is door de operator gekozen en bewijst geen chronologie.</p>
<p><strong>Nieuw in aangeleverd plan 2:</strong> """ + str(len(added)) + """ ·
<strong>Afwezig in plan 2:</strong> """ + str(len(absent)) + """ ·
<strong>Exact dezelfde bronbytes:</strong> """ + str(len(kept)) + """ ·
<strong>HUMAN wijzigingen op dezelfde bron:</strong> """ + str(len(changes)) + """</p>
<h2>Observaties — geen automatische HUMAN-statusoverdracht</h2>
<table><thead><tr><th>Bronobservatie</th><th>SHA-prefix en grootte</th><th>HUMAN plan 1</th><th>HUMAN plan 2</th></tr></thead>
<tbody>""" + "".join(rows) + """</tbody></table>
<p>Alle oorspronkelijke source-content blijft buiten dit rapport. Bronidentiteit en HUMAN-besluiten blijven PRIVATE.
De operator moet wijzigingen afzonderlijk beoordelen; er is geen apply-, grant-, scan-, delete- of deploypad.</p>
</body></html>"""


def main():
    parser = argparse.ArgumentParser(description="Offline PRIVATE HUMAN source-drift briefing (read-only).")
    parser.add_argument("--output", required=True, help="New 0600 HTML output within an existing private 0700 directory")
    parser.add_argument("old", help="Original PRIVATE plan JSON (operator-declared earlier)")
    parser.add_argument("new", help="Original PRIVATE plan JSON (operator-declared later)")
    args = parser.parse_args()
    try:
        old = read_receipt(args.old)
        new = read_receipt(args.new)
        report = build(old, new)
        publish_private(args.output, report)
    except Hold as exc:
        parser.exit(2, "HOLD: " + str(exc) + "\n")
    print("PRIVATE non-authorizing HUMAN source-drift briefing created.")


if __name__ == "__main__":
    main()
