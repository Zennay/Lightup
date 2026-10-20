#!/usr/bin/env python3
"""PRIVATE source-minimized multi-team HUMAN review exchange.

This is a local non-authorizing human coordination companion. Neither a
source manifest, receipt, recipient CSV nor a reviewer response proves a
client identity, authenticated sender, consent, revocation or grant.
No scanner/network/process execution, credential input or source mutation.
"""
from __future__ import annotations

import csv
import hashlib
import html
import io
import json
import os
from pathlib import Path
import re
import secrets
import sys

from change_brief import AUTHORITY, no_duplicates, require_fresh_private_directory, source, write_private
from human_followup import FIELDS, STAGES, human_text, worksheet
from review_history import admit_human
from recipient_browser import render_recipient
from owner_decision import original_owner_desk

FORMAT = "lightup.source_minimized_human_exchange.v1"
RECEIPT_LIMIT = 256_000
REPLY_LIMIT = 300_000
MAX_TEAMS = 16
HEX = re.compile(r"[0-9a-f]{32}\Z")
GROUP = re.compile(r"[a-z][a-z0-9_-]{0,39}\Z")
ASSIGN_FIELDS = (
    "exchange_token", "team_slot", "review_row", "private_row_token",
    "declared_source_change", "original_human_stage", "proposed_human_stage",
    "human_reply"
)
REPLY_STAGES = set(STAGES)


def bytes_regular(path: Path, limit: int) -> bytes:
    if path.is_symlink() or not path.is_file() or not 0 < path.stat().st_size <= limit:
        raise ValueError("Missing, symlink or oversized PRIVATE input")
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as handle:
        blob = handle.read(limit + 1)
    if not 0 < len(blob) <= limit:
        raise ValueError("Source limit exceeded")
    return blob


def checksum(blob: bytes) -> str:
    return hashlib.sha256(blob).hexdigest()


def encoded_csv(rows: list[tuple[str, ...]]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, quoting=csv.QUOTE_ALL, lineterminator="\n")
    writer.writerows(rows)
    result = stream.getvalue().encode("utf-8")
    if len(result) > REPLY_LIMIT:
        raise ValueError("HUMAN CSV too large")
    return result


def read_csv(path: Path) -> list[list[str]]:
    raw = bytes_regular(path, REPLY_LIMIT)
    text = raw.decode("utf-8", "strict")
    if "\r" in text.replace("\r\n", ""):
        raise ValueError("Unexpected carriage returns in HUMAN return")
    parser = csv.reader(io.StringIO(text, newline=""), strict=True)
    rows = list(parser)
    if not 1 < len(rows) <= 257 or tuple(rows[0]) != ASSIGN_FIELDS:
        raise ValueError("Unexpected or excessive HUMAN return records")
    if any(len(row) != len(ASSIGN_FIELDS) for row in rows):
        raise ValueError("Malformed HUMAN return columns")
    return rows


def read_originals(argv: list[str]):
    old, old_heads, old_hash = source(Path(argv[0]))
    new, new_heads, new_hash = source(Path(argv[1]))
    original_path = Path(argv[2])
    original_bytes = bytes_regular(original_path, 400_000)
    original_rows = admit_human(old, new, old_hash, new_hash, worksheet(original_path))
    return old_hash, new_hash, checksum(original_bytes), original_rows


def make_exchange(argv: list[str]):
    if len(argv) != 4:
        raise ValueError(
            "prepare PREVIOUS-MANIFEST CURRENT-MANIFEST ORIGINAL-HUMAN.csv NEW-PRIVATE-FOLDER"
        )
    previous_hash, current_hash, human_hash, originals = read_originals(argv)
    output = Path(argv[3])
    if not output.parent.is_dir() or output.parent.is_symlink():
        raise ValueError("Destination requires an existing ordinary parent")
    assignments: dict[str, list[dict]] = {}
    for index, row in enumerate(originals, 1):
        _source, changed, _old, _new, stage, team, _notes = row
        if not team:
            continue
        if not GROUP.fullmatch(team):
            raise ValueError("Assigned HUMAN team must use a-z, 0-9, underscore or dash")
        entries = assignments.setdefault(team, [])
        entries.append({
            "ordinal": index,
            "row_token": secrets.token_hex(16),
            "change": changed,
            "stage": stage,
        })
    if not assignments:
        raise ValueError("No assigned HUMAN reviewers: fill the original review CSV first")
    if len(assignments) > MAX_TEAMS:
        raise ValueError("Too many HUMAN recipient teams")
    session = secrets.token_hex(16)
    receipt = {
        "format": FORMAT, "posture": "INCUBATE_M3_M7_DRAFT_HOLD",
        "authority": {k: False for k in sorted(AUTHORITY)},
        "exchange_token": session,
        "previous_source_manifest_sha256": previous_hash,
        "current_source_manifest_sha256": current_hash,
        "original_human_worksheet_sha256": human_hash,
        "original_row_count": len(originals),
        "groups": [
            {"team": team, "team_slot": str(slot), "rows": assigned}
            for slot, (team, assigned) in enumerate(sorted(assignments.items()), 1)
        ],
        "note": "Private unsigned self-reported review routing, not identity, client/operator permission, or authorization."
    }
    receipt_blob = (json.dumps(receipt, indent=2, sort_keys=True) + "\n").encode("utf-8")
    groups = []
    for group in receipt["groups"]:
        result = [ASSIGN_FIELDS]
        for item in group["rows"]:
            result.append((
                session, group["team_slot"], str(item["ordinal"]), item["row_token"],
                item["change"], item["stage"], item["stage"], ""
            ))
        groups.append((f"recipient-{int(group['team_slot']):02d}.csv", encoded_csv(result)))
        groups.append((f"recipient-{int(group['team_slot']):02d}.html",
                       render_recipient(group["team"], group["team_slot"], session, group["rows"])))
    # All content is computed before any private output is created.
    require_fresh_private_directory(output)
    write_private(output / "PRIVATE-owner-receipt.json", receipt_blob)
    for name, content in groups:
        write_private(output / name, content)
    print("Created PRIVATE non-authorizing team reply templates:", output)
    print("Share only the intended team's own source-minimized recipient-XX.csv.")
    print("Keep PRIVATE-owner-receipt.json secret in the source owner's custody.")


def admit_receipt(path: Path, original_hashes, original_rows):
    document = json.loads(bytes_regular(path, RECEIPT_LIMIT).decode("utf-8", "strict"), object_pairs_hook=no_duplicates)
    if type(document) is not dict or set(document) != {
        "format", "posture", "authority", "exchange_token",
        "previous_source_manifest_sha256", "current_source_manifest_sha256",
        "original_human_worksheet_sha256", "original_row_count", "groups", "note"
    } or document["format"] != FORMAT or document["posture"] != "INCUBATE_M3_M7_DRAFT_HOLD":
        raise ValueError("Unexpected HUMAN exchange receipt format")
    authority = document["authority"]
    if type(authority) is not dict or set(authority) != AUTHORITY or any(v is not False for v in authority.values()):
        raise ValueError("HUMAN receipt asserts forbidden authority")
    session = document["exchange_token"]
    if type(session) is not str or not HEX.fullmatch(session):
        raise ValueError("Unsafe exchange token")
    expected_prev, expected_cur, expected_human = original_hashes
    if (document["previous_source_manifest_sha256"], document["current_source_manifest_sha256"],
        document["original_human_worksheet_sha256"]) != (expected_prev, expected_cur, expected_human):
        raise ValueError("PRIVATE owner receipt does not match exact original bytes")
    if type(document["original_row_count"]) is not int or document["original_row_count"] != len(original_rows):
        raise ValueError("Original HUMAN source count changed")
    groups = document["groups"]
    if type(groups) is not list or not 1 <= len(groups) <= MAX_TEAMS:
        raise ValueError("Invalid HUMAN recipient group count")
    seen_teams, seen_ordinals, groups_by_slot = set(), set(), {}
    for expected_slot, group in enumerate(groups, 1):
        if type(group) is not dict or set(group) != {"team", "team_slot", "rows"}:
            raise ValueError("Malformed recipient group")
        team, slot = group["team"], group["team_slot"]
        if type(team) is not str or not GROUP.fullmatch(team) or team in seen_teams or slot != str(expected_slot):
            raise ValueError("Ambiguous HUMAN recipient identity/slot")
        seen_teams.add(team)
        if type(group["rows"]) is not list or not group["rows"]:
            raise ValueError("HUMAN group must have rows")
        ordinals = set()
        for entry in group["rows"]:
            if type(entry) is not dict or set(entry) != {"ordinal", "row_token", "change", "stage"}:
                raise ValueError("Malformed source-minimized row identity")
            ordinal = entry["ordinal"]
            if type(ordinal) is not int or not 1 <= ordinal <= len(original_rows) or ordinal in ordinals or ordinal in seen_ordinals:
                raise ValueError("Duplicate/invalid source ordinal")
            ordinals.add(ordinal); seen_ordinals.add(ordinal)
            if (original_rows[ordinal-1][1], original_rows[ordinal-1][4],
                original_rows[ordinal-1][5]) != (entry["change"], entry["stage"], team):
                raise ValueError("Source-side HUMAN assignment changed since receipt")
            if type(entry["row_token"]) is not str or not HEX.fullmatch(entry["row_token"]):
                raise ValueError("Malformed row receipt token")
        groups_by_slot[slot] = group
    expected_assignments = {index for index, row in enumerate(original_rows, 1) if row[5]}
    if seen_ordinals != expected_assignments:
        raise ValueError("Receipt omitted or invented assigned HUMAN source rows")
    return document, groups_by_slot


def reconcile(argv: list[str]):
    if len(argv) < 6 or len(argv) > 21:
        raise ValueError(
            "reconcile PREVIOUS-MANIFEST CURRENT-MANIFEST ORIGINAL-HUMAN.csv PRIVATE-owner-receipt.json "
            "NEW-PRIVATE-OUTPUT-DIR RESPONSE-1.csv [... RESPONSE-16.csv]"
        )
    previous_hash, current_hash, human_hash, original_rows = read_originals(argv)
    receipt, groups_by_slot = admit_receipt(
        Path(argv[3]), (previous_hash, current_hash, human_hash), original_rows
    )
    responses = {}
    used_slots = set()
    for filename in argv[5:]:
        entries = read_csv(Path(filename))
        first = entries[1]
        session, slot = first[:2]
        if session != receipt["exchange_token"] or slot not in groups_by_slot or slot in used_slots:
            raise ValueError("Foreign/repeated/stale HUMAN reviewer response")
        expected = groups_by_slot[slot]["rows"]
        if len(expected) != len(entries) - 1:
            raise ValueError("Partial or expanded HUMAN recipient response")
        pending = []
        for item, raw in zip(expected, entries[1:]):
            if (raw[:6] != [
                receipt["exchange_token"], slot, str(item["ordinal"]), item["row_token"],
                item["change"], item["stage"]
            ]):
                raise ValueError("Invalid recipient row binding, order or original stage")
            stage, notes = raw[6], human_text(raw[7], 400)
            if stage not in REPLY_STAGES:
                raise ValueError("Invalid recipient-proposed HUMAN stage")
            pending.append((item["ordinal"], stage, notes))
        used_slots.add(slot)
        responses[slot] = pending
    pending_source_rows = []
    report = []
    for slot, group in groups_by_slot.items():
        if slot not in responses:
            continue
        for ordinal, stage, note in responses[slot]:
            src = original_rows[ordinal - 1]
            # Recipient responses never rewrite the original assignment.
            # A source-owner must independently accept/reject HUMAN proposals.
            pending_source_rows.append((
                str(ordinal), src[0], src[1], src[4], stage,
                group["team"], note
            ))
            report.append(
                "<tr><td>" + html.escape(src[0]) + "</td><td>" + html.escape(src[1]) +
                "</td><td>" + html.escape(group["team"]) + "</td><td>" + html.escape(src[4]) +
                "</td><td>" + html.escape(stage) + "</td><td>" + html.escape(note) + "</td></tr>"
            )
    style = "body{font:15px/1.6 system-ui;max-width:1100px;margin:auto;padding:20px;background:#111a2a;color:#f3f7ff}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #435a76;text-align:left;overflow-wrap:anywhere}h1{font-size:1.8rem}strong{color:#ffd795}"
    html_page = ("<!doctype html><html lang='en'><meta charset='utf-8'><meta name='viewport' content='width=device-width, initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; form-action 'none'; base-uri 'none'\">"
        "<title>PRIVATE HUMAN return triage — HOLD</title><style>" + style + "</style><main>"
        "<h1>LightUp PRIVATE source-owner recipient return triage</h1>"
        "<p><strong>HUMAN proposals only · DRAFT/HOLD · no real consent, verification, fix or authorization.</strong></p>"
        "<p>Original names and comments in this report may identify confidential systems. "
        "Review independently; no source, grant, accepted HUMAN stage or real permission changed.</p>"
        "<p>Received HUMAN team replies: " + str(len(used_slots)) +
        ". Still awaiting: " + str(len(groups_by_slot) - len(used_slots)) +
        ". Self-reported sender identity is NOT authenticated by a CSV row token.</p>"
        "<table><thead><tr><th>Original PRIVATE file</th><th>Source class</th><th>Assigned HUMAN team</th>"
        "<th>Existing HUMAN stage</th><th>Proposed HUMAN stage</th><th>PRIVATE reply</th>"
        "</tr></thead><tbody>" + "".join(report) + "</tbody></table>"
        "<p>No private source data, grant or consent is changed by this offline artifact.</p></main></html>"
    ).encode("utf-8")
    stream = [
        ("source_ordinal","original_PRIVATE_file","source_change",
         "current_human_stage","recipient_proposed_stage","self_declared_human_team","PRIVATE_reply"),
        *pending_source_rows
    ]
    proposal_csv = encoded_csv(stream)
    # Original-owner local-only explicit HUMAN accept/retain workroom.
    owner_html = original_owner_desk(
        original_rows, (previous_hash, current_hash), pending_source_rows
    )
    counts = {
        "format": "lightup.human_recipient_return_counts.v1",
        "posture": "INCUBATE_M3_M7_DRAFT_HOLD",
        "authority": {k: False for k in sorted(AUTHORITY)},
        "receipts_imported": len(responses),
        "teams_awaiting": len(groups_by_slot) - len(responses),
        "rows_proposed": len(pending_source_rows),
        "note": "Source-minimized counts, small cohorts may identify teams; not approval/consent."
    }
    out = Path(argv[4])
    if not out.parent.is_dir() or out.parent.is_symlink():
        raise ValueError("New output needs an ordinary existing parent directory")
    require_fresh_private_directory(out)
    write_private(out / "PRIVATE-HUMAN-proposals.html", html_page)
    write_private(out / "PRIVATE-HUMAN-owner-decisions.html", owner_html)
    write_private(out / "PRIVATE-HUMAN-proposals.csv", proposal_csv)
    write_private(out / "source-minimized-counts.json", (json.dumps(counts, indent=2, sort_keys=True) + "\n").encode("utf-8"))
    print("PRIVATE source-owner HUMAN proposal triage:", out)
    print("No recipient proposal has been promoted to an authorized status.")


def main(argv: list[str]):
    if len(argv) < 2 or argv[1] not in ("prepare", "reconcile"):
        raise ValueError("usage: recipient_exchange.py {prepare|reconcile} ...; read README")
    if argv[1] == "prepare":
        make_exchange(argv[2:])
    else:
        reconcile(argv[2:])


if __name__ == "__main__":
    try:
        main(sys.argv)
    except (OSError, ValueError, UnicodeError, csv.Error, json.JSONDecodeError) as exc:
        print("HOLD:", type(exc).__name__, str(exc), file=sys.stderr)
        sys.exit(3)
