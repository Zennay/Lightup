#!/usr/bin/env python3
"""Integrated source-PATH-bound, HUMAN-only assessment daily workspace.

Compose the existing original PRIVATE queue, priorities and one-team desks
in one NEW owner-only folder. This never executes or authorizes an assessment.
Every original input is re-admitted by the existing native owner-only readers.
"""
from __future__ import annotations

from datetime import date
import hashlib
import html
import json
import os
from pathlib import Path
import shutil

import human_priorities
import private_session as privacy
import route_queue
import route_team

LEGACY_SCHEMA = "lightup.private.assessment-human-workpack.v1"
SCHEMA = "lightup.private.assessment-human-workpack.v2"
TEAM_FOLDERS = {
    "Security": "team-security",
    "Privacy": "team-privacy",
    "Client operations": "team-client-operations",
    "Platform": "team-platform",
}


def _index(teams: list[tuple[str, int]], rows: list[dict],
           review_date: str) -> bytes:
    open_workflows = len(rows)
    assigned = sum(item["human_stage"] != "UNASSESSED" for item in rows)
    attention = sum(item["human_stage"] in ("HOLD", "NEEDS_INPUT") for item in rows)
    links = [
        ("queue/OPEN-PRIVATE.html", "HUMAN assessment queue",
         "Edit all source-PATH-bound manual tasks, then explicitly export a local PRIVATE CSV."),
        ("queue/PRIVATE-READONLY.html", "Scriptless review",
         "Read the original full HUMAN queue without any JavaScript."),
        ("priorities/OPEN-PRIVATE.html", "HUMAN follow-up priorities",
         "See manual HOLDs, declared dates and workload. Not a calendar or vulnerability ranking."),
    ]
    for team, count in teams:
        links.append((TEAM_FOLDERS[team] + "/OPEN-PRIVATE.html",
                      team + " HUMAN worklist",
                      str(count) + " manually assigned tasks; excludes other teams' questions."))
    cards = "".join(
        '<li><a rel="noopener noreferrer" href="' + html.escape(link, quote=True) +
        '">' + html.escape(title) + '</a><p>' + html.escape(detail) + "</p></li>"
        for link, title, detail in links
    )
    doc = ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp PRIVATE HUMAN Assessment Workpack</title>
<style>:root{color-scheme:dark;font:16px/1.6 system-ui,sans-serif;background:#101d31;color:#edf7fe}
*{box-sizing:border-box}body{max-width:980px;margin:0 auto;padding:24px}
header,main,footer{border:1px solid #4a6984;border-radius:18px;background:#1a3148;padding:26px;margin:15px 0}
h1{font-size:clamp(2rem,4vw,3rem);line-height:1.14;margin:.4rem 0}
.warn{color:#ffe0a7;font-weight:700}.summary{color:#b3efd8;font-weight:bold}
ul{list-style:none;padding:0}li{padding:18px 0;border-top:1px solid #47627e}
a{font-weight:700;color:#9ddeff}a:focus-visible{outline:3px solid #ffe0a7;outline-offset:4px}
p{margin:.4rem 0;color:#d3e3ee}footer{border-left:5px solid #ffe0a7}</style>
<header><p class="warn">LIGHTUP / OWNER-PRIVATE / HUMAN-ONLY / PLAN-LAB</p>
<h1>Assessment HUMAN Workpack</h1>
<p>Manually prepared offline coordination; every original workflow remains
REVIEW_ONLY. Local workpack navigation is not an authentic client engagement
or release approval.</p>
<p class="summary">""" + str(open_workflows) + " original workrooms · " + str(assigned) +
        " manually staged · " + str(attention) + " HUMAN HOLD / NEEDS INPUT" +
        "</p><p>Operator-declared review date: <strong>" + html.escape(review_date) +
        """</strong>. No appointment, reminder or deadline is actually scheduled.</p>
</header><main><h2>Open original PRIVATE local HUMAN views</h2><ul>""" +
        cards + """</ul></main><footer><p class="warn">DRAFT/HOLD · NO PERMISSION
GRANTED · NOT A VERIFIED SECURITY ASSESSMENT</p><p>All pages stay inside this
owner-only offline workpack. The editable queue and one-team human task
decks may contain sensitive PRIVATE notes and original file: bookmarks.
Do not publish, share, serve over HTTP, or upload the folder. Browser
CSV downloads must be manually admitted under 0700/0600 custody before
native re-import. No automation, scanning, model, recipient contact,
grant, scheduling, retest, deletion, disclosure or target execution.
Separate current authenticated client/operator consent and revocation at
action time, source-owner and independent review, all original CI gates
and explicit HUMAN GO remain mandatory. Incubate M3/M7.</p></footer></html>""")
    return doc.encode("utf-8")


def build(session, source_csv: str, parent_name: str, name: str,
          review_date: str, *, original_snapshot: bytes | None = None) -> Path:
    human_priorities.as_of(review_date)
    if not privacy.NAME.fullmatch(name):
        raise privacy.Hold("HOLD: unique PRIVATE HUMAN workpack folder name required")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == privacy.ROOT or privacy.ROOT in parent.parents
            or not privacy.private(parent, True)):
        raise privacy.Hold("HOLD: existing owner-only 0700 parent outside checkout required")
    root = parent / name
    if os.path.lexists(root):
        raise privacy.Hold("HOLD: existing PRIVATE workpack must not be overwritten")

    # The original source-PATH fingerprint and every HUMAN CSV field are
    # re-admitted BEFORE the new directory is created. No path or client
    # source bytes are disclosed in the source-free summary.
    base, _ = route_queue.rows_for(session)
    # Two fully explicit HUMAN-only modes: read an original admitted
    # queue, or seed a first all-UNASSESSED queue from native session paths.
    # Never invent HUMAN decisions or reuse an unrelated original CSV.
    if original_snapshot is not None and source_csv:
        raise privacy.Hold("HOLD: provide only one original HUMAN snapshot source")
    seeded_from_session = not bool(source_csv) and original_snapshot is None
    if seeded_from_session:
        rows = base
        source_bytes = route_queue.csv_bytes(base)
    else:
        # Direct re-admission of a pinned original descriptor snapshot permits
        # continuation without reopening an old mutable source path.
        source_bytes = (original_snapshot if original_snapshot is not None else
                        route_queue.read_owner_csv(source_csv))
        rows = route_queue.admit_human_edits_bytes(base, source_bytes)
    teams = [(team, sum(row["review_team"] == team and
                        row["human_stage"] != "UNASSESSED" for row in rows))
             for team in TEAM_FOLDERS]
    teams = [(team, count) for team, count in teams if count]
    index = _index(teams, rows, review_date)
    receipt = {
        "schema": SCHEMA,
        "status": "REVIEW_ONLY",
        "authority": privacy.AUTHORITY,
        "declared_review_date": review_date,
        "original_client_source_included": False,
        "pinned_private_human_csv_included": True,
        "pinned_private_human_csv_sha256_unsigned": hashlib.sha256(source_bytes).hexdigest(),
        "pinned_private_human_csv_bytes": len(source_bytes),
        "created_from_unassessed_session": seeded_from_session,
        "original_session_paths_included": False,
        "external_recipient_authenticated": False,
        "review_verified": False,
        "automated_actions": False,
        "workflows": len(rows),
        "human_staged": sum(row["human_stage"] != "UNASSESSED" for row in rows),
        "team_decks": [{"team": team, "human_workflows": count}
                       for team, count in teams],
        "generated_views": ["queue", "priorities"] +
                           [TEAM_FOLDERS[team] for team, _ in teams],
    }
    receipt_bytes = (json.dumps(receipt, sort_keys=True, ensure_ascii=True,
                                separators=(",", ":")) + "\n").encode("ascii")
    root.mkdir(mode=0o700)
    try:
        if not privacy.private(root, True):
            raise privacy.Hold("PRIVATE HUMAN workpack not owner-controlled")
        # Freeze an owner-private HUMAN draft for EVERY child view.
        # The original input remains untouched, even if it changes later.
        pinned = root / "PINNED-HUMAN-QUEUE.csv"
        privacy.private_write(root, pinned.name, source_bytes)
        pinned_rows = route_queue.admit_human_edits(base, str(pinned))
        if route_queue.csv_bytes(pinned_rows) != route_queue.csv_bytes(rows):
            raise privacy.Hold("HOLD: original HUMAN CSV changed during workpack intake")
        # Original suite producers own all inner HTML, JSON, CSV bytes,
        # ownership and mode admission. No custom bypass of those gates.
        route_queue.build(session, str(root), "queue", imported_csv=str(pinned))
        human_priorities.build(session, str(pinned), str(root),
                               "priorities", review_date)
        for team, _ in teams:
            route_team.build(session, str(pinned), team, str(root),
                             TEAM_FOLDERS[team])
        privacy.private_write(root, "OPEN-PRIVATE.html", index)
        privacy.private_write(root, "PRIVATE-WORKPACK-RECEIPT.json", receipt_bytes)
        fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        # Never delete an old workspace: root was confirmed unused.
        # Cleanup affects ONLY the new incomplete PRIVATE workpack.
        shutil.rmtree(root)
        raise privacy.Hold("HOLD: integrated owner-private workpack not published") from None
    return root / "OPEN-PRIVATE.html"
