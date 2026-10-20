#!/usr/bin/env python3
"""PRIVATE original-source-bound HUMAN review return; never issue a permission.

Requires the same two original byte-identical SOURCE-MANIFEST inputs used to
produce change_brief.py's editable human-review-template.csv. Offline only.
"""
from __future__ import annotations

import csv
import html
import io
import json
import os
from pathlib import Path
import sys

from change_brief import AUTHORITY, source, require_fresh_private_directory, write_private
from privacy_counts import suppressed_counts

MAX_CSV = 400_000
FIELDS = ("previous_manifest_sha256", "current_manifest_sha256",
          "source_file_path", "change_status", "previous_sha256",
          "current_sha256", "human_stage", "human_team", "human_notes")
STAGES = {"unreviewed", "investigating", "escalated", "documented"}
STATUSES = {"unchanged", "changed", "added", "absent"}


def human_text(s: str, limit: int) -> str:
    if type(s) is not str or len(s) > limit:
        raise ValueError("Overlong/invalid HUMAN freeform entry")
    if any(ord(c) < 32 or ord(c) == 127 or 0x202A <= ord(c) <= 0x202E
           or 0x2066 <= ord(c) <= 0x2069 for c in s):
        raise ValueError("Control or bidi formatting in HUMAN entry")
    if s.lstrip().startswith(("=", "+", "-", "@")):
        raise ValueError("HUMAN freeform spreadsheet formula prefix rejected")
    return s


def worksheet_bytes(data: bytes):
    """Read a single already-captured exact PRIVATE worksheet byte snapshot.

    Importers that also bind worksheet SHA-256 must pass those SAME bytes to
    avoid a second filesystem read observing a different revision.
    """
    if type(data) is not bytes or not 0 < len(data) <= MAX_CSV:
        raise ValueError("HUMAN worksheet outside bounded byte budget")
    text = data.decode("utf-8", "strict")
    if "\r" in text.replace("\r\n", ""):
        raise ValueError("Unexpected carriage return in HUMAN worksheet")
    reader = csv.reader(io.StringIO(text, newline=""), strict=True)
    header = next(reader, None)
    if tuple(header or ()) != FIELDS:
        raise ValueError("HUMAN worksheet must have original exact columns")
    rows = list(reader)
    if not 1 <= len(rows) <= 256:
        raise ValueError("HUMAN worksheet row count out of bounds")
    if any(len(row) != len(FIELDS) for row in rows):
        raise ValueError("Ambiguous HUMAN worksheet column count")
    return rows


def worksheet(path: Path):
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= MAX_CSV:
        raise ValueError("Missing, linked or oversized private HUMAN worksheet")
    descriptor = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(descriptor, "rb") as fp:
        data = fp.read(MAX_CSV + 1)
    return worksheet_bytes(data)


def expected_files(previous, current):
    values = []
    for filename in sorted(previous.keys() | current.keys()):
        before, after = previous.get(filename), current.get(filename)
        category = "absent" if after is None else "added" if before is None else "unchanged" if before == after else "changed"
        values.append((filename, category, before[1] if before else "", after[1] if after else ""))
    return values


def render(all_rows, changed_heads, first_hash, second_hash):
    body = []
    for path, status, old, new, stage, team, note in all_rows:
        body.append("<tr><td>" + html.escape(path) + "</td><td>" + status.upper() +
                    "</td><td>" + html.escape(stage) + "</td><td>" + html.escape(team) +
                    "</td><td>" + html.escape(note) + "</td></tr>")
    return ("""<!doctype html><html lang="nl"><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'"><title>LightUp PRIVATE HUMAN bronreview — HOLD</title><style>body{font:16px system-ui;margin:2rem auto;padding:0 1rem;max-width:1100px;background:#101927;color:#eef5ff}h1{font-size:1.7rem}p{line-height:1.6}.hold{color:#ffe4a3;font-weight:bold}th,td{border-bottom:1px solid #46526d;padding:.7rem;text-align:left;overflow-wrap:anywhere}table{width:100%;border-collapse:collapse}tr:nth-child(2n){background:#1c2940}small{color:#bad0ed}</style><main><h1>PRIVATE bronversie-HUMAN opvolging</h1><p class="hold">REVIEW ONLY · INCUBATE M3/M7 · DRAFT/HOLD · géén toestemming, scan, grant, remediatiebewijs of productie-release.</p><p>Alle statusvelden en teams zijn uitsluitend onverifieerde menselijke verklaringen op exact hergeselecteerde broninventarisbytes. Afwezige bestanden zijn niet gerepareerd of ingetrokken. De originele eigenaar en onafhankelijke security/privacy-authorisatie blijven verplicht.</p><p>Oorspronkelijke bron-HEADs gewijzigd: """ + ("JA — onafhankelijke bronreview nodig" if changed_heads else "NEE (geen bronauthenticiteit)") +
            "</p><small>Vorig origineel manifest SHA-256: " + first_hash + "<br>Huidig origineel manifest SHA-256: " + second_hash +
            "</small><table><thead><tr><th>Origineel bronpad (PRIVATE)</th><th>Wijziging</th><th>HUMAN fase</th><th>HUMAN team</th><th>PRIVATE notitie</th></tr></thead><tbody>" + "".join(body) + "</tbody></table><p class='hold'>Geen enkele HUMAN status activeert LightUp tools of wijzigt originele grants.</p></main></html>").encode("utf-8")


def main(argv):
    if len(argv) != 5:
        raise ValueError("usage: python3 human_followup.py PREVIOUS-SOURCE-MANIFEST.json CURRENT-SOURCE-MANIFEST.json FILLED-HUMAN-WORKSHEET.csv NEW-PRIVATE-DIR")
    old, old_heads, old_digest = source(Path(argv[1]))
    new, new_heads, new_digest = source(Path(argv[2]))
    rows = worksheet(Path(argv[3]))
    expected = expected_files(old, new)
    if len(rows) != len(expected):
        raise ValueError("HUMAN worksheet incomplete or extra original rows")
    enriched = []
    for item, original in zip(rows, expected):
        prev, cur, name, kind, old_sha, new_sha, stage, team, notes = item
        if (prev, cur) != (old_digest, new_digest) or (name, kind, old_sha, new_sha) != original:
            raise ValueError("Wrong original source bytes, ordering or labels: HUMAN import rejected atomically")
        if stage not in STAGES:
            raise ValueError("Unknown HUMAN stage")
        enriched.append((*original, stage, human_text(team, 80), human_text(notes, 500)))
    output = Path(argv[4])
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("Private output must have an ordinary existing parent")
    page = render(enriched, old_heads != new_heads, old_digest, new_digest)
    counts = {"posture": "INCUBATE_M3_M7_DRAFT_HOLD",
              "authority": {key: False for key in sorted(AUTHORITY)},
              "heads_changed": old_heads != new_heads,
              "human_stage_counts": suppressed_counts(
                  {stage: sum(1 for row in enriched if row[4] == stage)
                   for stage in sorted(STAGES)}, len(enriched)),
              "source_change_counts": suppressed_counts(
                  {kind: sum(1 for row in enriched if row[1] == kind)
                   for kind in sorted(STATUSES)}, len(enriched))}
    require_fresh_private_directory(output)
    write_private(output / "human-review.html", page)
    write_private(output / "source-minimized-counts.json", (json.dumps(counts, sort_keys=True, indent=2) + "\n").encode("utf-8"))
    print("Private HUMAN read-only review:", output / "human-review.html")


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError, csv.Error) as exc:
        print("HOLD:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(3)
