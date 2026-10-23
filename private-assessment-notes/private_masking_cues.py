#!/usr/bin/env python3
"""Original-source PRIVATE HUMAN masking cue navigation; never clearance.

Reopens immutable owner-private masked note packets and provides a
source-minimal, human-only overview of literal known placeholder appearances.
Marker counts are not proven masks and never a security/privacy verdict.
"""
from __future__ import annotations

import csv
from hashlib import sha256
import html
import io
import json
import os
from pathlib import Path
import shutil
import tempfile

from notes import FALSE_FLAGS, Hold, file_new, load_workroom, private_directory, private_input, save_json

LEGACY_SCHEMA = "lightup.private_assessment_masking_cues.v1"
V2_SCHEMA = "lightup.private_assessment_masking_cues.v2"
V3_SCHEMA = "lightup.private_assessment_masking_cues.v3"
V4_SCHEMA = "lightup.private_assessment_masking_cues.v4"
V5_SCHEMA = "lightup.private_assessment_masking_cues.v5"
V6_SCHEMA = "lightup.private_assessment_masking_cues.v6"
V7_SCHEMA = "lightup.private_assessment_masking_cues.v7"
V8_SCHEMA = "lightup.private_assessment_masking_cues.v8"
V9_SCHEMA = "lightup.private_assessment_masking_cues.v9"
V10_SCHEMA = "lightup.private_assessment_masking_cues.v10"
V11_SCHEMA = "lightup.private_assessment_masking_cues.v11"
V12_SCHEMA = "lightup.private_assessment_masking_cues.v12"
V13_SCHEMA = "lightup.private_assessment_masking_cues.v13"
V14_SCHEMA = "lightup.private_assessment_masking_cues.v14"
V15_SCHEMA = "lightup.private_assessment_masking_cues.v15"
V16_SCHEMA = "lightup.private_assessment_masking_cues.v16"
V17_SCHEMA = "lightup.private_assessment_masking_cues.v17"
V18_SCHEMA = "lightup.private_assessment_masking_cues.v18"
SCHEMA = "lightup.private_assessment_masking_cues.v19"
GROUPS = (
    ("HTTP_OR_SHELL", ("[REDACTED_HEADER_VALUE]", "[REDACTED_HTTP_VALUE]",
                       "[REDACTED_COMMAND_CREDENTIAL]")),
    ("URL_OR_SESSION", ("[REDACTED_USERINFO]", "[REDACTED_URL_VALUE]",
                        "[REDACTED_SESSION_VALUE]")),
    ("STRUCTURED_CONFIG", ("[REDACTED_JSON_VALUE]", "[REDACTED_ENV_VALUE]",
                           "[REDACTED_CONFIG_VALUE]")),
    ("TOKEN_OR_PRIVATE_KEY", ("[REDACTED_PRIVATE_KEY_BLOCK]",
                              "[REDACTED_JWT_SHAPE]", "[REDACTED_PROVIDER_TOKEN_SHAPE]",
                              "[REDACTED_AWS_ACCESS_KEY]", "[REDACTED]")),
)
LEGACY_GROUPS = GROUPS
# V2 receives a newly recognized HAR exported HTTP credential placeholder.
# Original V1 cue room source bytes remain stable and read-only reopenable.
V2_GROUPS = (("HTTP_OR_SHELL", LEGACY_GROUPS[0][1] +
              ("[REDACTED_HAR_HEADER_VALUE]",)), *LEGACY_GROUPS[1:])
# V3 adds known credential-like HAR cookie, query and form name/value fields,
# counted as literal structured markers, never as detected verified secrets.
V3_GROUPS = (*V2_GROUPS[:2],
             ("STRUCTURED_CONFIG", V2_GROUPS[2][1] +
              ("[REDACTED_HAR_PARAM_VALUE]",)),
             V2_GROUPS[3])
# V4 adds quoted cURL form-value cues under the existing HTTP/shell count.
# Never reinterpret a previously written V3 unsigned source-bound packet.
V4_GROUPS = (("HTTP_OR_SHELL", V3_GROUPS[0][1] +
              ("[REDACTED_FORM_VALUE]",)), *V3_GROUPS[1:])
# V5 adds conservative XML element and attribute cues. Prior receipts retain
# the exact original historical count algorithm and can reopen unchanged.
GROUPS = (*V4_GROUPS[:2],
          ("STRUCTURED_CONFIG", V4_GROUPS[2][1] + ("[REDACTED_XML_VALUE]",)),
          V4_GROUPS[3])
V6_GROUPS = GROUPS
# V7 only extends the structured-count family; preserved originals v1-v6
# always render and reopen with their historically fixed marker sets.
GROUPS = (*V6_GROUPS[:2],
          ("STRUCTURED_CONFIG", V6_GROUPS[2][1] +
           ("[REDACTED_HAR_FORM_TEXT]",
            "[REDACTED_HAR_EMBEDDED_JSON]")),
          V6_GROUPS[3])
V7_GROUPS = GROUPS
# V8 admits the new named multipart HAR form-data body marker only. Earlier
# original reviewer receipts rederive their own exact historical cue set.
GROUPS = (*V7_GROUPS[:2],
          ("STRUCTURED_CONFIG", V7_GROUPS[2][1] +
           ("[REDACTED_HAR_MULTIPART_TEXT]",)),
          V7_GROUPS[3])
V8_GROUPS = GROUPS
# V9 adds privacy-minimal opaque HAR request/response body withholding cues.
# Historical V1-V8 receipts keep their original marker families unchanged.
GROUPS = (*V8_GROUPS[:2],
          ("STRUCTURED_CONFIG", V8_GROUPS[2][1] +
           ("[REDACTED_HAR_REQUEST_BODY]",
            "[REDACTED_HAR_RESPONSE_BODY]",
            "[REDACTED_HAR_WEBSOCKET_FRAME]")),
          V8_GROUPS[3])
V9_GROUPS = GROUPS
# V10 separately adds all bounded structural HAR cookie value cues.
# Do not change historical V9 counts/receipts from the earlier source build.
GROUPS = (*V9_GROUPS[:2],
          ("STRUCTURED_CONFIG", V9_GROUPS[2][1] +
           ("[REDACTED_HAR_COOKIE_VALUE]",)),
          V9_GROUPS[3])
V10_GROUPS = GROUPS
# V11 further minimises all original HAR query/form parameter values;
# preserve V10 exact ordinal marker counts on historical receipt reopening.
GROUPS = (*V10_GROUPS[:2],
          ("STRUCTURED_CONFIG", V10_GROUPS[2][1] +
           ("[REDACTED_HAR_QUERY_VALUE]",
            "[REDACTED_HAR_FORM_PARAM_VALUE]")),
          V10_GROUPS[3])
V11_GROUPS = GROUPS
# V12 withholds arbitrary-name request/response header values and
# URLs/file names inside original bounded HAR entries. Historical
# receipt counts remain exact to their original source algorithm.
GROUPS = ((V11_GROUPS[0][0],
           V11_GROUPS[0][1] + ("[REDACTED_HAR_ANY_HEADER_VALUE]",)),
          (V11_GROUPS[1][0],
           V11_GROUPS[1][1] + ("[REDACTED_HAR_REQUEST_URL]",
                                "[REDACTED_HAR_REDIRECT_URL]")),
          (V11_GROUPS[2][0],
           V11_GROUPS[2][1] + ("[REDACTED_HAR_FILE_REFERENCE]",)),
          V11_GROUPS[3])
V12_GROUPS = GROUPS
# V13 flags wholly withheld ambiguous HAR source copies, without leaking
# original text, absolute paths, metadata, or source identity.
GROUPS = (*V12_GROUPS[:2],
          (V12_GROUPS[2][0],
           V12_GROUPS[2][1] + ("[WITHHELD_PRIVATE_HAR_UNREVIEWED]",)),
          V12_GROUPS[3])
V13_GROUPS = GROUPS
# V14 keeps the historical V13 marker algorithm while adding a distinct
# source-free HUMAN attention HTML file to the private cue packet.
GROUPS = V13_GROUPS
V14_GROUPS = GROUPS
# V15 adds source-free HAR category inventory while preserving V14 receipts.
GROUPS = V14_GROUPS
V15_GROUPS = GROUPS
# V16 additionally binds original-ordinal-only HTML attention navigation.
GROUPS = V15_GROUPS
V16_GROUPS = GROUPS
# V17 only adds source-minimal printable private HUMAN questions.
GROUPS = V16_GROUPS
V17_GROUPS = GROUPS
# V18 adds original task worksheets, V19 adds the offline HUMAN status studio.
# No legacy masking/count algorithm or original v18 artifact changes.
GROUPS = V17_GROUPS
V18_GROUPS = GROUPS
GROUPS = V18_GROUPS
CSV_FIELDS = ("original_ordinal", "literal_http_or_shell_markers",
              "literal_url_or_session_markers", "literal_config_markers",
              "literal_token_or_key_markers", "literal_total_markers")


def cues(sources: list[dict], groups=GROUPS) -> list[dict]:
    output = []
    for record in sources:
        # IMPORTANT: these are plain STRING OCCURRENCES. The source may
        # already contain the marker in plaintext, and unknown secrets can
        # survive all patterns. Never use as proof or risk classification.
        message = record["redacted_text"]
        by_type = [sum(message.count(marker) for marker in markers)
                   for _, markers in groups]
        output.append({
            "original_ordinal": record["ordinal"],
            "literal_http_or_shell_markers": by_type[0],
            "literal_url_or_session_markers": by_type[1],
            "literal_config_markers": by_type[2],
            "literal_token_or_key_markers": by_type[3],
            "literal_total_markers": sum(by_type),
        })
    return output


def cue_csv(rows: list[dict]) -> bytes:
    handle = io.StringIO(newline="")
    writer = csv.DictWriter(handle, fieldnames=CSV_FIELDS, lineterminator="\r\n")
    writer.writeheader()
    for entry in rows:
        writer.writerow({field: entry[field] for field in CSV_FIELDS})
    return handle.getvalue().encode("utf-8")


def cue_page_v5(rows: list[dict]) -> bytes:
    listing = []
    for record in rows:
        values = [record[name] for name in CSV_FIELDS]
        cells = "".join("<td>" + html.escape(str(value)) + "</td>" for value in values[1:])
        listing.append("<tr><th scope='row'>Original #" +
                       str(record["original_ordinal"]) + "</th>" + cells + "</tr>")
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none'">
<title>LightUp PRIVATE HUMAN masking-cue navigation</title>
<style>body{max-width:1050px;margin:2rem auto;padding:1rem;font:16px/1.6 system-ui}
aside{background:#fff1e7;border-left:5px solid #b24822;padding:1rem}
table{border-collapse:collapse;width:100%;margin:1rem 0}
th,td{border:1px solid #cad4dd;padding:10px;text-align:left}
thead{background:#f0f4f8}caption{margin:10px;font-weight:700}
@media print{body{margin:0;max-width:none}}</style>
<h1>PRIVATE original source · literal masking-cue desk</h1>
<aside><b>INCUBATE / REVIEW_ONLY / HOLD · NOT A MASKING SAFETY SCORE.</b>
The counts below are literal appearances of known REDACTED marker strings
inside the original owner-private masked note outputs. Some source text
may already contain those strings; unknown secrets and personal data may
remain. Zero counts means nothing about source safety or approval.
No reviewer identity, permission, client consent or right to disclose
is inferred. Keep this entire output confidential.</aside>
<p>Original PRIVATE sources: """ + str(len(rows)) + """.
The original source hashes, masked notes, free HUMAN comments,
source filenames and any raw customer or target details are deliberately
withheld from this overview.</p>
<table><caption>Human review navigation by ORIGINAL source ordinal</caption>
<thead><tr><th scope="col">Original source</th>
<th scope="col">HTTP / shell</th><th scope="col">URL / session</th>
<th scope="col">Structured config</th><th scope="col">Tokens / keys</th>
<th scope="col">Literal marker total</th></tr></thead>
<tbody>""" + "".join(listing) + """</tbody></table>
<p>Return to the original PRIVATE HUMAN source review and independently
inspect all remaining context and credentials. A marker is not a credential
proof, private data anonymisation, severity rating, authorization, or release.
The original HUMAN review and all real security/consent/CI approvals remain
separate and mandatory. No active tool, network, model or dispatch.</p>
</html>""").encode("utf-8")


def cue_page(rows: list[dict]) -> bytes:
    from private_masking_navigation import render
    return render(rows)


def cue_receipt(manifest_raw: bytes, sources: list[dict],
                schema: str = SCHEMA) -> dict:
    return {
        "schema": schema, "claimed_status": "HOLD",
        "source_count": len(sources),
        "original_manifest_sha256_unsigned": sha256(manifest_raw).hexdigest(),
        "original_masked_sha256_unsigned": [
            source["output_sha256_unsigned"] for source in sources],
        "counts_are_literal_marker_occurrences_not_verified_masks": True,
        "not_authorized_or_safe_to_share": True,
        **{flag: False for flag in FALSE_FLAGS},
    }


def create(original: str, private_parent: str,
           created_room: list[Path] | None = None) -> int:
    kit = private_directory(original)
    # Original notes.py admission checks complete canonical source-bound
    # original slot identities and the actual masked content bytes.
    _manifest, sources, rows = load_workroom(kit)
    marker_rows = cues(rows)
    manifest_raw = private_input(str(kit / "PRIVATE-source-bindings.json"), 128 * 1024)
    output_parent = private_directory(private_parent)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-masking-cues-", dir=output_parent))
    os.chmod(output, 0o700)
    ready = False
    try:
        save_json(output / "PRIVATE-masking-cues-receipt.json",
                  cue_receipt(manifest_raw, sources))
        file_new(output / "PRIVATE-masking-cues.csv", cue_csv(marker_rows))
        file_new(output / "PRIVATE-masking-cues.html", cue_page(marker_rows))
        from private_har_hold_board import (
            render as render_har_hold, render_inventory, inventory_csv,
        )
        file_new(output / "PRIVATE-HAR-HOLD.html", render_har_hold(rows))
        file_new(output / "PRIVATE-HAR-INVENTORY.html", render_inventory(rows))
        file_new(output / "PRIVATE-HAR-INVENTORY.csv", inventory_csv(rows))
        from private_har_attention_queue import render as render_har_queue
        file_new(output / "PRIVATE-HAR-QUEUE.html", render_har_queue(rows))
        from private_har_questions import render as render_questions
        file_new(output / "PRIVATE-HAR-QUESTIONS.html", render_questions(rows))
        from private_har_worklist import worksheet_html, worksheet_csv
        file_new(output / "PRIVATE-HAR-ACTIONS.html", worksheet_html(rows))
        file_new(output / "PRIVATE-HAR-ACTIONS.csv", worksheet_csv(rows))
        from private_har_studio import render as render_har_studio
        file_new(output / "PRIVATE-HAR-STUDIO.html", render_har_studio(rows))
        ready = True
        if created_room is not None:
            created_room.append(output)
        print("REVIEW_ONLY: PRIVATE original masking-cue navigation created; NOT privacy proof")
        print("OPEN LOCALLY: " + str(output / "PRIVATE-masking-cues.html"))
        return 2
    finally:
        if not ready:
            shutil.rmtree(output)



def reopen(original: str, cue_room: str) -> int:
    """Read-only original private masked-source and cue receipt re-admission."""
    kit = private_directory(original)
    _binding, sources, rows = load_workroom(kit)
    manifest_raw = private_input(str(kit / "PRIVATE-source-bindings.json"), 128 * 1024)
    folder = private_directory(cue_room)
    stored_receipt = private_input(
        str(folder / "PRIVATE-masking-cues-receipt.json"), 65536)
    def serialized_receipt(schema):
        return (json.dumps(cue_receipt(manifest_raw, sources, schema=schema),
                           indent=2, sort_keys=True,
                           ensure_ascii=False) + "\n").encode("utf-8")
    is_v19 = stored_receipt == serialized_receipt(SCHEMA)
    is_v18 = stored_receipt == serialized_receipt(V18_SCHEMA)
    is_v17 = stored_receipt == serialized_receipt(V17_SCHEMA)
    is_v16 = stored_receipt == serialized_receipt(V16_SCHEMA)
    is_v15 = stored_receipt == serialized_receipt(V15_SCHEMA)
    is_v14 = stored_receipt == serialized_receipt(V14_SCHEMA)
    if is_v19 or is_v18 or is_v17:
        derived = cues(rows)
        render_page = cue_page
    elif is_v16:
        derived = cues(rows, groups=V16_GROUPS)
        render_page = cue_page
    elif is_v15:
        derived = cues(rows, groups=V15_GROUPS)
        render_page = cue_page
    elif is_v14:
        derived = cues(rows, groups=V14_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V13_SCHEMA):
        derived = cues(rows, groups=V13_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V12_SCHEMA):
        derived = cues(rows, groups=V12_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V11_SCHEMA):
        derived = cues(rows, groups=V11_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V10_SCHEMA):
        derived = cues(rows, groups=V10_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V9_SCHEMA):
        derived = cues(rows, groups=V9_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V8_SCHEMA):
        derived = cues(rows, groups=V8_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V7_SCHEMA):
        derived = cues(rows, groups=V7_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V6_SCHEMA):
        derived = cues(rows, groups=V6_GROUPS)
        render_page = cue_page
    elif stored_receipt == serialized_receipt(V5_SCHEMA):
        derived = cues(rows, groups=V6_GROUPS)
        render_page = cue_page_v5
    elif stored_receipt == serialized_receipt(V4_SCHEMA):
        render_page = cue_page_v5
        derived = cues(rows, groups=V4_GROUPS)
    elif stored_receipt == serialized_receipt(V3_SCHEMA):
        render_page = cue_page_v5
        derived = cues(rows, groups=V3_GROUPS)
    elif stored_receipt == serialized_receipt(V2_SCHEMA):
        render_page = cue_page_v5
        # Preserve exact historical V2 marker counts and source bytes.
        derived = cues(rows, groups=V2_GROUPS)
    elif stored_receipt == serialized_receipt(LEGACY_SCHEMA):
        render_page = cue_page_v5
        # Pre-HAR cue workrooms are not silently upgraded or overwritten.
        derived = cues(rows, groups=LEGACY_GROUPS)
    else:
        raise Hold("HOLD: original-bound PRIVATE masking-cue receipt changed")
    expected_receipt = stored_receipt
    expected_files = (
        ("PRIVATE-masking-cues-receipt.json", expected_receipt),
        ("PRIVATE-masking-cues.csv", cue_csv(derived)),
        ("PRIVATE-masking-cues.html", render_page(derived)),
    )
    if is_v19 or is_v18 or is_v17 or is_v16 or is_v15 or is_v14:
        from private_har_hold_board import render as render_har_hold
        expected_files += (("PRIVATE-HAR-HOLD.html",
                            render_har_hold(rows)),)
    if is_v19 or is_v18 or is_v17 or is_v16 or is_v15:
        from private_har_hold_board import render_inventory, inventory_csv
        expected_files += (
            ("PRIVATE-HAR-INVENTORY.html", render_inventory(rows)),
            ("PRIVATE-HAR-INVENTORY.csv", inventory_csv(rows)),
        )
    if is_v19 or is_v18 or is_v17 or is_v16:
        from private_har_attention_queue import render as render_har_queue
        expected_files += (("PRIVATE-HAR-QUEUE.html", render_har_queue(rows)),)
    if is_v19 or is_v18 or is_v17:
        from private_har_questions import render as render_questions
        expected_files += (("PRIVATE-HAR-QUESTIONS.html", render_questions(rows)),)
    if is_v19 or is_v18:
        from private_har_worklist import worksheet_html, worksheet_csv
        expected_files += (
            ("PRIVATE-HAR-ACTIONS.html", worksheet_html(rows)),
            ("PRIVATE-HAR-ACTIONS.csv", worksheet_csv(rows)),
        )
    if is_v19:
        from private_har_studio import render as render_har_studio
        expected_files += (("PRIVATE-HAR-STUDIO.html", render_har_studio(rows)),)
    for name, original_bytes in expected_files:
        if private_input(str(folder / name), 65536) != original_bytes:
            raise Hold("HOLD: original-bound PRIVATE HUMAN masking-cue packet changed")
    print("HOLD: original PRIVATE masking-cue packet reopened read-only; no safety claim")
    print("OPEN LOCALLY: " + str(folder / "PRIVATE-masking-cues.html"))
    return 3
