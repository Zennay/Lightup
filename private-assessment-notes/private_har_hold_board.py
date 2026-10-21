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

# Source-free literal marker counts, not verified redaction or detection.
HAR_CATEGORIES = (
    ("url_or_redirect", ("[REDACTED_HAR_REQUEST_URL]",
                         "[REDACTED_HAR_REDIRECT_URL]")),
    ("http_header", ("[REDACTED_HAR_ANY_HEADER_VALUE]",
                     "[REDACTED_HAR_HEADER_VALUE]")),
    ("cookie_query_form", ("[REDACTED_HAR_COOKIE_VALUE]",
                           "[REDACTED_HAR_QUERY_VALUE]",
                           "[REDACTED_HAR_FORM_PARAM_VALUE]")),
    ("body_or_frame", ("[REDACTED_HAR_REQUEST_BODY]",
                       "[REDACTED_HAR_RESPONSE_BODY]",
                       "[REDACTED_HAR_WEBSOCKET_FRAME]",
                       "[REDACTED_HAR_FORM_TEXT]",
                       "[REDACTED_HAR_MULTIPART_TEXT]",
                       "[REDACTED_HAR_EMBEDDED_JSON]")),
    ("file_reference", ("[REDACTED_HAR_FILE_REFERENCE]",)),
)
HAR_FIELDS = ("original_ordinal", "whole_derived_copy_withheld",
              *(label + "_literal_markers" for label, _ in HAR_CATEGORIES))


def inventory(rows: list[dict]) -> list[dict]:
    """No raw source, hashes, filenames, freeform notes or private text."""
    records = []
    for row in rows:
        message = row["redacted_text"]
        record = {
            "original_ordinal": int(row["ordinal"]),
            "whole_derived_copy_withheld": int(message == HOLD_MARKER),
        }
        for label, names in HAR_CATEGORIES:
            record[label + "_literal_markers"] = sum(
                message.count(name) for name in names
            )
        records.append(record)
    return records


def inventory_csv(rows: list[dict]) -> bytes:
    import csv
    import io
    output = io.StringIO(newline="")
    writer = csv.DictWriter(output, fieldnames=HAR_FIELDS,
                            lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(inventory(rows))
    return output.getvalue().encode("utf-8")


def render_inventory(rows: list[dict]) -> bytes:
    listing = inventory(rows)
    total_held = sum(r["whole_derived_copy_withheld"] for r in listing)
    labels = ("Original source", "Whole derived copy withheld",
              "URL / redirect", "HTTP headers", "Cookies / query / form",
              "Body / frame", "File references")
    head = "".join("<th scope='col'>" + label + "</th>" for label in labels)
    body = ""
    for record in listing:
        entries = [record[field] for field in HAR_FIELDS]
        body += ("<tr><th scope='row'>Original #" +
                 str(entries[0]) + "</th>" +
                 "".join("<td>" + str(value) + "</td>"
                         for value in entries[1:]) + "</tr>")
    sums = "".join("<li>" + label.replace("_", " ") + ": " +
                   str(sum(r[label + "_literal_markers"] for r in listing)) +
                   " literal occurrences</li>" for label, _ in HAR_CATEGORIES)
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HAR original-ordinal attention</title>
<style>body{font:16px/1.5 system-ui;max-width:1100px;margin:2rem auto;padding:1rem;color:#253445}
aside{border-left:5px solid #ac5a31;background:#fff1e6;padding:1rem}
table{border-collapse:collapse;width:100%;margin:1.5rem 0}
td,th{border:1px solid #b6c1cf;padding:.55rem;text-align:left}
thead{background:#eef2f5}
@media(max-width:650px){table{font-size:11px}td,th{padding:3px}}
@media print{body{margin:0;max-width:none}}</style>
<h1>PRIVATE original HAR source-attention inventory</h1>
<aside><b>HUMAN REVIEW / HOLD / NO DISCLOSURE.</b>
Every number is a literal string-marker count in an owner-private
derived note, not evidence of a verified mask or complete sanitisation.
Markers may occur as original text. Zero counts NEVER mean safe, fixed,
consented, authorised or cleared. Original identities, source content,
paths, hashes, credentials, URLs and HUMAN notes are not included.</aside>
<p>Original positions: """ + str(len(listing)) + """.
Derived copies with whole-source withheld marker: """ + str(total_held) + """.
Every original requires separate PRIVATE source-owner HUMAN inspection.</p>
<ul>""" + sums + """</ul>
<table><thead><tr>""" + head + """</tr></thead>
<tbody>""" + body + """</tbody></table>
<p>Use original ordinals in the PRIVATE owner workroom. For a whole
derived copy withheld, consult the unchanged original offline source.
This is not approval, assessment execution, external sharing or security
verification. No scripts, network, recipients, grants or automation.</p>
</html>"""
    return page.encode("utf-8")
