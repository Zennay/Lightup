#!/usr/bin/env python3
"""Original-bound second PRIVATE HUMAN masking pass on *already masked* notes.

Explicit owner-only literal rules, no automatic claims of safe disclosure.
Never writes raw literals or unselected originals to its output packet.
"""
from __future__ import annotations

import argparse
from hashlib import sha256
import html
import os
from pathlib import Path
import shutil
import sys
import tempfile

from notes import FALSE_FLAGS, Hold, file_new, private_directory, read_json, save_json
from revision_changes import admit_completed
from manual_mask_board import render as render_mask_board

SCHEMA = "lightup.private_human_extra_mask_rules.v1"
OUT_SCHEMA = "lightup.private_human_extra_masked_selection.v1"
LIMIT = 24
REPLACEMENT = "[MANUALLY_REDACTED]"
STYLE = """body{max-width:900px;margin:2rem auto;padding:20px;
font:16px/1.65 system-ui;color:#203247}
article{border:1px solid #afc2d0;padding:16px;margin:14px 0;border-radius:9px}
.warn{border-left:5px solid #ae4e29;background:#fff0e8;padding:12px}
pre{white-space:pre-wrap;overflow-wrap:anywhere;padding:15px;
background:#17263a;color:#eaf0f8;border-radius:8px}
a{color:#15577c}a:focus-visible{outline:3px solid #bf7c22}
@media print{pre{color:black;background:white;border:1px solid #999}}"""


def template(completed_packet: str, parent: str) -> int:
    """Create an original-bound, owner-only editable masking request shell."""
    target = private_directory(parent)
    _, manifest, decisions_csv, sources, source_rows, _ = admit_completed(completed_packet)
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-mask-plan-", dir=target))
    os.chmod(output, 0o700)
    complete = False
    try:
        rules = {
            "schema": SCHEMA, "claimed_status": "HOLD",
            "completed_manifest_sha256_unsigned": sha256(manifest).hexdigest(),
            "completed_human_csv_sha256_unsigned": sha256(decisions_csv).hexdigest(),
            "rules": [
                {
                    "original_source_ordinal": item["ordinal"],
                    "original_source_sha256_unsigned": item["source_sha256_unsigned"],
                    "literal_to_mask": "",
                } for item in sources
            ],
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(output / "PRIVATE-manual-mask-rules.json", rules)
        file_new(output / "PRIVATE-manual-mask-editor.html",
                 render_mask_board(source_rows, sha256(manifest).hexdigest(),
                                   sha256(decisions_csv).hexdigest()))
        notice = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE original HUMAN manual masking</title><style>""" + STYLE +
        """</style><header><p class="warn"><b>PRIVATE HUMAN MASKING REQUEST · HOLD</b>
<br>Contains original source SHA identities but no original text or requested
secret literal yet. This local file is not permission to disclose.</p>
<h1>Manually redact remaining PRIVATE content</h1>
<p><a href="PRIVATE-manual-mask-editor.html">Open offline PRIVATE HUMAN
manual masking editor</a> to inspect the pattern-masked original and enter
exact remaining phrases. The downloaded JSON contains the sensitive literal;
protect it immediately with mode 0600. The HTML itself also contains already
masked PRIVATE source content and must remain owner-private.</p>
<p>Alternatively, edit the <code>PRIVATE-manual-mask-rules.json</code> file within this
owner-private directory. Replace each chosen <code>literal_to_mask</code> blank
with its exact secret phrase, and REMOVE all unneeded rule entries.
You may duplicate a source entry for multiple distinct secret phrases.
The edited file itself is HIGHLY SENSITIVE: it contains secret literal text.
Keep it mode 0600, local and never post/send/upload it.</p>
<p>At least one valid HUMAN literal is required; each is 3–256 Unicode
characters with no control characters, duplicates or overlapping matches.
The original completed HUMAN source and complete HUMAN CSV SHA bindings must
remain unchanged. An unmatched phrase or unsafe value rejects the complete
operation without creating a derived packet.</p><p>Then invoke native
<code>notes.py mask-copy --completed-packet ... --rules-json ... --private-parent ...</code>.
The result contains only selected extra-masked originals (never raw rule
literals), remains owner-private/HOLD and is NOT cleared for sharing.
No network, external action, source edit or authorization occurs.</p>
</header></html>""")
        file_new(output / "OPEN-PRIVATE.html", notice.encode("utf-8"))
        complete = True
        print("REVIEW_ONLY: original-bound editable PRIVATE manual masking template prepared.")
        print("OPEN LOCALLY: " + str(output / "OPEN-PRIVATE.html"))
        return 2
    finally:
        if not complete:
            shutil.rmtree(output)


def prepare(completed_packet: str, rules_file: str, parent: str) -> int:
    target = private_directory(parent)
    _, original_manifest, original_csv, sources, rows, decisions = admit_completed(
        completed_packet)
    # Contains raw original secrets selected by an actual HUMAN: never log it
    # or store it in the derived result. This input MUST be owner-only 0600.
    from notes import private_input
    raw = private_input(rules_file, 64 * 1024)
    import json
    try:
        def reject_duplicates(pairs):
            result = {}
            for key, value in pairs:
                if key in result:
                    raise ValueError("duplicate key")
                result[key] = value
            return result
        request = json.loads(raw.decode("utf-8"), object_pairs_hook=reject_duplicates,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError()))
    except (UnicodeError, TypeError, ValueError):
        raise Hold("HOLD: original PRIVATE manual masking rules are invalid") from None
    if (type(request) is not dict or set(request) != {
            "schema", "claimed_status", "completed_manifest_sha256_unsigned",
            "completed_human_csv_sha256_unsigned", "rules", *FALSE_FLAGS}
            or request["schema"] != SCHEMA or request["claimed_status"] != "HOLD"
            or request["completed_manifest_sha256_unsigned"] != sha256(original_manifest).hexdigest()
            or request["completed_human_csv_sha256_unsigned"] != sha256(original_csv).hexdigest()
            or any(request[flag] is not False for flag in FALSE_FLAGS)
            or type(request["rules"]) is not list
            or not 1 <= len(request["rules"]) <= LIMIT):
        raise Hold("HOLD: manual mask rules do not match the original completed PRIVATE source")

    selected = {}
    for entry in request["rules"]:
        if (type(entry) is not dict or set(entry) != {
                "original_source_ordinal", "original_source_sha256_unsigned",
                "literal_to_mask"}
                or type(entry["original_source_ordinal"]) is not int
                or not 1 <= entry["original_source_ordinal"] <= len(rows)
                or entry["original_source_sha256_unsigned"] !=
                   sources[entry["original_source_ordinal"] - 1]["source_sha256_unsigned"]
                or type(entry["literal_to_mask"]) is not str):
            raise Hold("HOLD: a manual mask rule is not original-source-bound")
        text = entry["literal_to_mask"]
        if (not 3 <= len(text) <= 256 or text != text.strip()
                or any(ord(c) < 32 or ord(c) == 127 for c in text)
                or "[REDACTED" in text or "[MANUALLY_REDACTED]" in text):
            raise Hold("HOLD: manual mask literal must be an exact bounded PRIVATE phrase")
        slot = entry["original_source_ordinal"]
        selected.setdefault(slot, [])
        if text in selected[slot]:
            raise Hold("HOLD: repeated original HUMAN literal rule")
        selected[slot].append(text)

    masked = []
    for slot, literals in sorted(selected.items()):
        row = rows[slot - 1]
        # Compute actual original occurrence spans before replacing anything.
        # Partially intersecting different phrases must not silently lose an
        # operator-requested mask even when neither phrase contains the other.
        before = row["redacted_text"]
        spans = []
        for value in literals:
            offset = 0
            found = 0
            while True:
                index = before.find(value, offset)
                if index < 0:
                    break
                spans.append((index, index + len(value)))
                found += 1
                # Also find self-overlapping occurrences (e.g. "aba" in
                # "ababa"): silently leaving a portion behind is not safe.
                # All intersecting ranges then fail closed below.
                offset = index + 1
            if found == 0:
                raise Hold("HOLD: literal missing from original completed PRIVATE masked note")
        spans.sort()
        if any(left < prev_end
               for (_, prev_end), (left, _) in zip(spans, spans[1:])):
            raise Hold("HOLD: original HUMAN masking phrases have overlapping occurrences")
        replacement_count = len(spans)
        parts = []
        start = 0
        for left, right in spans:
            parts.extend((before[start:left], REPLACEMENT))
            start = right
        parts.append(before[start:])
        after = "".join(parts)
        output_bytes = after.encode("utf-8")
        masked.append({
            "original_ordinal": slot,
            "original_source_sha256_unsigned": row["source_sha256_unsigned"],
            "original_masked_sha256_unsigned": row["output_sha256_unsigned"],
            "new_masked_sha256_unsigned": sha256(output_bytes).hexdigest(),
            "new_masked_bytes": len(output_bytes),
            "manual_literals_applied_count": len(literals),
            "manual_occurrences_masked_count": replacement_count,
            "human_stage": decisions[slot - 1]["human_stage"],
            "redacted_text": after,
        })
    output = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-human-more-masked-", dir=target))
    os.chmod(output, 0o700)
    completed = False
    try:
        output_notes = output / "notes"
        output_notes.mkdir(mode=0o700)
        provenance = []
        panes = []
        for item in masked:
            slot = item["original_ordinal"]
            raw_output = item.pop("redacted_text")
            file_new(output_notes / f"PRIVATE-manually-masked-{slot:03d}.txt",
                     raw_output.encode("utf-8"))
            provenance.append(item)
            panes.append(
                "<article><h2>Selected ORIGINAL note #" + str(slot) + "</h2>" +
                "<p>Prior HUMAN stage: " + html.escape(item["human_stage"]) +
                "; additional local HUMAN literals applied: " +
                str(item["manual_literals_applied_count"]) + "</p>" +
                "<p class='warn'>Pattern and literal masking remain incomplete. "+
                "This source stays PRIVATE / HOLD, including any remaining personal data.</p>" +
                "<pre>" + html.escape(raw_output) + "</pre></article>")
        manifest = {
            "schema": OUT_SCHEMA,
            "claimed_status": "HOLD",
            "source_authenticated": False,
            "recipient_authenticated": False,
            "pattern_and_literal_masking_not_anonymization": True,
            "original_completed_manifest_sha256_unsigned": sha256(original_manifest).hexdigest(),
            "original_completed_human_csv_sha256_unsigned": sha256(original_csv).hexdigest(),
            "original_secret_rule_bytes_withheld": True,
            "selected_original_count": len(masked),
            "sources": provenance,
            **{flag: False for flag in FALSE_FLAGS},
        }
        save_json(output / "PRIVATE-extra-mask-bindings.json", manifest)
        html_bytes = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE HUMAN extra masking</title><style>""" + STYLE +
        """</style><header><p class="warn"><b>HOLD · PRIVATE HUMAN secondary masking</b><br>
No verified anonymity, absence of secrets, independent source identity,
client consent, recipient authorization, security PASS or permission to send.</p>
<h1>Selected original PRIVATE HUMAN extra-masked notes</h1><p>Only """ +
        str(len(masked)) + """ manually selected original source positions are
shown. Original rule literals, complete source files, and original HUMAN
free-text notes are intentionally withheld. NOTHING WAS SENT.</p></header>""" +
        "".join(panes) + """<footer><p><a href="PRIVATE-extra-mask-bindings.json">
Read PRIVATE original source SHA receipt</a></p><p>Incubate M3/M7 PLAN/LAB
ONLY · DRAFT/HOLD. Independent source-owner/privacy/security review,
client/operator consent with action-time revocation and explicit HUMAN GO
remain externally necessary. No target execution or release.</p></footer></html>""")
        file_new(output / "OPEN-PRIVATE.html", html_bytes.encode("utf-8"))
        completed = True
        print("HOLD: extra-masked selected PRIVATE HUMAN copy created. NOT cleared for sharing.")
        print("OPEN LOCALLY: " + str(output / "OPEN-PRIVATE.html"))
        return 3
    finally:
        if not completed:
            shutil.rmtree(output)


def main() -> int:
    cli = argparse.ArgumentParser(
        description="Extra manual PRIVATE masking of source-bound completed HUMAN notes; no release")
    cli.add_argument("--completed-packet", required=True)
    cli.add_argument("--rules-json", required=True, help="0600 human-only literal rule JSON (sensitive)")
    cli.add_argument("--private-parent", required=True)
    args = cli.parse_args()
    try:
        return prepare(args.completed_packet, args.rules_json, args.private_parent)
    except (Hold, OSError, ValueError, KeyError, TypeError) as exc:
        print(str(exc) if isinstance(exc, Hold) else
              "HOLD: PRIVATE HUMAN manual masking refused", file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.modules.setdefault("notes", __import__("notes"))
    raise SystemExit(main())
