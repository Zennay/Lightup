#!/usr/bin/env python3
"""Offline, source-free, HUMAN-only LightUp assessment work queue.

All inputs and generated outputs stay in owner-controlled 0700/0600 local
storage. A queue status NEVER asserts authorization or source correctness.
"""
from __future__ import annotations
import csv
from datetime import date
import hashlib
import html
import io
import json
import os
from pathlib import Path
import shutil
import stat

import private_session as privacy
import route_board
import queue_browser

SCHEMA = "lightup.private.assessment-human-queue.v1"
COLUMNS = ("snapshot_sha256", "workflow_key", "human_stage", "review_team",
           "followup_date", "human_question")
STAGES = ("UNASSESSED", "HOLD", "NEEDS_INPUT", "HUMAN_REVIEW", "HUMAN_FOLLOWUP")
TEAMS = ("", "Security", "Privacy", "Client operations", "Platform")
MAX_CSV = 65536
MAX_QUESTION = 240


def rows_for(session) -> tuple[list[dict], str]:
    # SHA binds to locally referenced *paths* and workflow schema, not
    # evidence bytes or identity. Never export those paths in CSV/JSON.
    paths = privacy.clean_paths(session)
    stable = json.dumps({"schema": SCHEMA, "paths": paths},
                        sort_keys=True, ensure_ascii=True,
                        separators=(",", ":")).encode("ascii")
    digest = hashlib.sha256(stable).hexdigest()
    groups, _, _ = route_board.snapshot(session)
    rows = []
    for group in groups:
        for item in group["cards"]:
            rows.append({
                "snapshot_sha256": digest,
                "workflow_key": item["key"],
                "human_stage": "UNASSESSED",
                "review_team": "",
                "followup_date": "",
                "human_question": "",
                "local_state": item["state"],
                "human_next": item["human_next"],
                "title": item["title"],
                "group": group["heading"],
                "local_href": item["local_href"],
            })
    return rows, digest


def csv_bytes(rows: list[dict]) -> bytes:
    stream = io.StringIO(newline="")
    writer = csv.writer(stream, lineterminator="\r\n", quoting=csv.QUOTE_MINIMAL)
    writer.writerow(COLUMNS)
    for item in rows:
        writer.writerow([item[field] for field in COLUMNS])
    return stream.getvalue().encode("utf-8")


def read_owner_csv(name: str) -> bytes:
    path = Path(name)
    if not path.is_absolute() or not privacy.private(path.parent, True):
        raise privacy.Hold("original HUMAN CSV parent must be owner-only")
    # Refuse symbolic links, hardlinks and oversized files before decode.
    before = path.lstat()
    if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.geteuid()
            or stat.S_IMODE(before.st_mode) & 0o077
            or before.st_nlink != 1 or not 0 < before.st_size <= MAX_CSV):
        raise privacy.Hold("original HUMAN CSV must be an owner-only 0600 regular file")
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        a = os.fstat(fd)
        # The original lstat and the opened descriptor must identify the
        # SAME original 0600 one-link regular file; mode/owner cannot change
        # to a public or swapped file in the admission gap.
        if (not stat.S_ISREG(a.st_mode) or a.st_uid != os.geteuid()
                or stat.S_IMODE(a.st_mode) & 0o077 or a.st_nlink != 1
                or not 0 < a.st_size <= MAX_CSV
                or (before.st_dev, before.st_ino) != (a.st_dev, a.st_ino)):
            raise privacy.Hold("opened HUMAN CSV is not the original owner-private file")
        raw = os.read(fd, MAX_CSV + 1)
        b = os.fstat(fd)
        if ((a.st_dev, a.st_ino, a.st_size, a.st_mtime_ns, a.st_mode, a.st_uid,
             a.st_nlink) !=
            (b.st_dev, b.st_ino, b.st_size, b.st_mtime_ns, b.st_mode, b.st_uid,
             b.st_nlink) or len(raw) != a.st_size):
            raise privacy.Hold("HUMAN CSV changed during PRIVATE read")
    finally:
        os.close(fd)
    return raw


def admit_human_edits(base: list[dict], csv_source: str) -> list[dict]:
    # Parse precisely the owner-private descriptor snapshot admitted by the
    # original native reader; callers that retain the bytes can share it.
    return admit_human_edits_bytes(base, read_owner_csv(csv_source))


def admit_human_edits_bytes(base: list[dict], raw: bytes) -> list[dict]:
    """Validate exactly one immutable original CSV byte snapshot."""
    try:
        if type(raw) is not bytes or not 0 < len(raw) <= MAX_CSV:
            raise privacy.Hold("HOLD: bounded original HUMAN CSV bytes required")
        decoded = raw.decode("utf-8", "strict")
        reader = csv.reader(io.StringIO(decoded, newline=""), strict=True)
        header = next(reader)
        if tuple(header) != COLUMNS:
            raise privacy.Hold("HUMAN CSV must keep exact column order")
        changes = list(reader)
        if len(changes) != len(base):
            raise privacy.Hold("HUMAN CSV must preserve all original workflow rows")
        updated = []
        for old, fields in zip(base, changes):
            if len(fields) != len(COLUMNS):
                raise privacy.Hold("HUMAN CSV has malformed fields")
            item = dict(zip(COLUMNS, fields))
            if (item["snapshot_sha256"] != old["snapshot_sha256"]
                    or item["workflow_key"] != old["workflow_key"]):
                raise privacy.Hold("HUMAN CSV source/session binding or key order changed")
            if item["human_stage"] not in STAGES or item["review_team"] not in TEAMS:
                raise privacy.Hold("HUMAN stage or team unsupported")
            due = item["followup_date"]
            if due:
                if (len(due) != 10 or due[4] != "-" or due[7] != "-"):
                    raise privacy.Hold("HUMAN follow-up date must be YYYY-MM-DD")
                try:
                    if date.fromisoformat(due).isoformat() != due:
                        raise ValueError()
                except ValueError:
                    raise privacy.Hold("HUMAN follow-up date not valid") from None
            question = item["human_question"]
            if (len(question) > MAX_QUESTION or any(ord(ch) < 32 or ord(ch) == 127
                                                     for ch in question)):
                raise privacy.Hold("HUMAN question is too long or contains control characters")
            # A HUMAN CSV opened by spreadsheet software must not contain
            # executable CSV formula payloads. Preserve original text only.
            if question.lstrip().startswith(("=", "+", "-", "@")):
                raise privacy.Hold("HUMAN questions cannot begin with spreadsheet formulas")
            if item["human_stage"] == "UNASSESSED" and (item["review_team"] or due or question):
                raise privacy.Hold("unassessed workflow cannot claim an assigned HUMAN follow-up")
            updated.append({**old, **item})
        return updated
    except (OSError, UnicodeError, csv.Error, StopIteration) as exc:
        raise privacy.Hold("HOLD: unreadable or malformed original HUMAN CSV") from None


def render_html(rows: list[dict]) -> bytes:
    counts = {state: sum(item["human_stage"] == state for item in rows)
              for state in STAGES}
    counts_text = " · ".join(f"{counts[k]} {k.replace('_', ' ').lower()}" for k in STAGES)
    parts = []
    for group, items in route_board.GROUPS:
        matching = [row for row in rows if row["group"] == group]
        cards = []
        for item in matching:
            stage = html.escape(item["human_stage"].replace("_", " "))
            local = html.escape(item["local_state"].replace("_", " "))
            link = ""
            if item["local_href"]:
                link = '<a rel="noopener noreferrer" href="' + html.escape(
                    item["local_href"], quote=True) + '">Open original PRIVATE local workroom</a>'
            due = item["followup_date"] or "—"
            team = item["review_team"] or "Not assigned"
            question = item["human_question"] or "No local HUMAN question recorded."
            cards.append("<li><h3>" + html.escape(item["title"]) + "</h3>"
                         "<p><strong>HUMAN: " + stage + "</strong> · " + local + "</p>"
                         "<p>Team: " + html.escape(team) + " · Follow-up: " +
                         html.escape(due) + "</p><p>HUMAN question: " +
                         html.escape(question) + "</p><p>Suggested manual next step: " +
                         html.escape(item["human_next"]) + "</p>" + link + "</li>")
        parts.append("<section><h2>" + html.escape(group) + "</h2><ul>" +
                     "".join(cards) + "</ul></section>")
    page = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; base-uri 'none'; form-action 'none'">
<title>LightUp PRIVATE HUMAN Assessment Work Queue</title>
<style>
:root{color-scheme:dark;font:16px/1.55 system-ui,sans-serif;background:#0d1727;color:#e7f3fa}
*{box-sizing:border-box}body{max-width:1240px;margin:auto;padding:24px}
header{background:#20354e;padding:27px;border:1px solid #526c85;border-radius:18px}
h1{font-size:clamp(1.7rem,4vw,2.8rem);line-height:1.18;margin:.4rem 0}
.warn{color:#ffdda5;font-weight:700}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,470px),1fr));gap:16px;margin:22px 0}
section{background:#192c42;border:1px solid #405e7c;border-radius:14px;padding:20px}
h2{color:#b3eedc;font-size:1.14rem}ul{margin:0;padding:0;list-style:none}
li{padding:15px 0;border-top:1px solid #44617b}h3{margin:0;font-size:1rem}
p{color:#d3e5f0;margin:8px 0}strong{color:#ffdda5}
a{color:#9adeff;font-weight:bold}a:focus-visible{outline:3px solid #ffe3a4;outline-offset:3px}
footer{background:#263950;border-left:5px solid #f0d5a1;padding:17px}
</style><header><p class="warn">LIGHTUP · PRIVATE / HUMAN ONLY / INCUBATE M3-M7</p>
<h1>Local Assessment Work Queue</h1>
<p>A manual coordination snapshot from saved path references. This cannot
confirm original file contents, customer identity, actual reviewer, authority
to assess, validated findings, completed fixes or any release.</p>
<p class="warn">""" + html.escape(counts_text) + """</p></header><main>""" + "".join(parts) + """</main>
<footer>Local PRIVATE file: links can reveal confidential machine paths. Never
publish this page or CSV. Every original remains subject to its own native
byte admission and current authenticated client/operator consent with
revocation at action time, independent review and explicit HUMAN GO.
No scanning, model, network, dispatch, schedule, grant, retest, delete or
automatic promotion. HUMAN status is a proposal, never PASS/APPROVED.
PLAN/LAB ONLY · DRAFT/HOLD · REVIEW_ONLY.</footer></html>"""
    return page.encode("utf-8")


def build(session, parent_name: str, name: str,
          imported_csv: str = "") -> Path:
    if not privacy.NAME.fullmatch(name):
        raise privacy.Hold("invalid new PRIVATE work queue folder name")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == privacy.ROOT or privacy.ROOT in parent.parents
            or not privacy.private(parent, True)):
        raise privacy.Hold("existing owner-only 0700 parent outside checkout required")
    destination = parent / name
    if os.path.lexists(destination):
        raise privacy.Hold("existing PRIVATE work queue must never be overwritten")
    rows, digest = rows_for(session)
    if imported_csv:
        rows = admit_human_edits(rows, imported_csv)
    html_bytes = queue_browser.render(rows)
    readonly_bytes = render_html(rows)
    csv_document = csv_bytes(rows)
    summary = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": privacy.AUTHORITY,
        "snapshot_sha256_unsigned": digest, "original_source_bytes_included": False,
        "owner_paths_included": False, "human_verified": False,
        "workflows": [{"key": row["workflow_key"], "availability": row["local_state"],
                       "human_stage": row["human_stage"], "team": row["review_team"],
                       "followup_date": row["followup_date"]}
                      for row in rows],
    }
    json_bytes = (json.dumps(summary, sort_keys=True, ensure_ascii=True,
                             separators=(",", ":")) + "\n").encode("ascii")
    destination.mkdir(mode=0o700)
    try:
        if not privacy.private(destination, True):
            raise privacy.Hold("new work queue not owner-private")
        privacy.private_write(destination, "OPEN-PRIVATE.html", html_bytes)
        privacy.private_write(destination, "PRIVATE-READONLY.html", readonly_bytes)
        privacy.private_write(destination, "PRIVATE-HUMAN-QUEUE.csv", csv_document)
        privacy.private_write(destination, "PRIVATE-HUMAN-QUEUE.json", json_bytes)
        fd = os.open(destination, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(destination)
        raise privacy.Hold("HOLD: PRIVATE HUMAN work queue publication refused") from None
    return destination / "OPEN-PRIVATE.html"
