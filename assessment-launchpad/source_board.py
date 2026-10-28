"""Scriptless private source-ordinal summary for offline lab manifest composition."""
from __future__ import annotations

import base64
from hashlib import sha256

STYLE = ("body{font:16px/1.5 system-ui,sans-serif;color:#17212f;"
         "max-width:900px;margin:2rem auto;padding:1rem}"
         ".hold{padding:1rem;background:#fff3dd;border-left:5px solid #965e11}"
         "table{width:100%;border-collapse:collapse}th,td{padding:.7rem;"
         "border:1px solid #cbd5e1;text-align:left}th{background:#eaf1f9}"
         "small{color:#536174}a{color:#18467b;font-weight:750}")


def render_board(receipt):
    """Use only fixed-schema ordinal counts; never URLs, paths, source hashes or notes."""
    rows = receipt["sources"]
    position = 1
    table_rows = []
    for row in rows:
        ordinal = row["ordinal"]
        count = row["endpoints"]
        included = (ordinal not in receipt.get("omitted_source_ordinals", [])
                    and (receipt["mode"] == "append" or ordinal > 1))
        slots = (str(position) if count == 1 else
                 str(position) + "–" + str(position + count - 1)) if included else "—"
        if included:
            position += count
        table_rows.append("<tr><td>" + str(ordinal) + "</td><td>" +
                          str(count) + "</td><td>" +
                          ("RETAINED" if included else "DISCARDED") +
                          "</td><td>" + slots + "</td></tr>")
    hash_value = base64.b64encode(sha256(STYLE.encode("utf-8")).digest()).decode("ascii")
    html = ("<!doctype html><html lang='en'><head><meta charset='utf-8'>"
            "<meta name='viewport' content='width=device-width,initial-scale=1'>"
            "<meta name='referrer' content='no-referrer'>"
            "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; "
            "script-src 'none'; style-src 'sha256-" + hash_value +
            "'; connect-src 'none'; img-src 'none'; object-src 'none';"
            " form-action 'none'; base-uri 'none'\">"
            "<title>LightUp PRIVATE source board</title><style>" + STYLE +
            "</style></head><body><h1>Offline PRIVATE source composition</h1>"
            "<p class='hold'>INCUBATE M3/M7 · PLAN/LAB ONLY · REVIEW_ONLY ·"
            " NOT AUTHORIZED</p>"
            "<p>Order and counts are operator-declared, not authenticated"
            " provenance, lab authority or proof of assessed endpoints.</p>"
            "<table><caption>Original source-file ordinals and result slots</caption>"
            "<thead><tr><th>Source ordinal</th><th>Declared endpoints</th>"
            "<th>Mode</th><th>Result slots</th></tr></thead><tbody>" +
            "".join(table_rows) + "</tbody></table><p>Total planned slots: " +
            str(receipt["counts"]["result_endpoints"]) + "</p>"
            "<p><a href='lightup-manifest-source-slots-private.csv'>"
            "Open PRIVATE source-local slot CSV</a></p>"
            "<p><small>PRIVATE, unsigned and local. Endpoint values, original file"
            " paths, names and hashes are absent. Small-group counts can still"
            " be sensitive. No source identity, consent, review approval, scan,"
            " grant, dispatch, model, target interaction or HUMAN GO is asserted."
            "</small></p></body></html>")
    return html.encode("utf-8")


def slot_map_csv(receipt):
    """Fixed-vocabulary source-local -> resulting ordinal mapping, no private URL data."""
    omitted = set(receipt.get("omitted_source_ordinals", ()))
    output = ["source_ordinal,source_slot,result_slot,selection,review_state"]
    position = 1
    for row in receipt["sources"]:
        ordinal = row["ordinal"]
        included = ordinal not in omitted and (receipt["mode"] == "append" or ordinal > 1)
        for source_slot in range(1, row["endpoints"] + 1):
            result_slot = str(position) if included else ""
            output.append(",".join((str(ordinal), str(source_slot), result_slot,
                                    "RETAINED" if included else "DISCARDED", "REVIEW_ONLY")))
            if included:
                position += 1
    if position - 1 != receipt["counts"]["result_endpoints"]:
        raise ValueError("declared result count and slot map differ")
    return ("\n".join(output) + "\n").encode("ascii")
