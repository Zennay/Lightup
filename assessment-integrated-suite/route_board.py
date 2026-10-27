#!/usr/bin/env python3
"""PRIVATE source-free assessment route board; purely local HUMAN navigation.

Builds a new owner-private, scriptless snapshot of existing original offline
workrooms. This never examines source artifacts or infers review/authority.
"""
from __future__ import annotations

import html
import json
import os
from pathlib import Path
import shutil

import private_session as custody

SCHEMA = "lightup.private.assessment-route-board.v1"
ADDITIONAL_PAGES = {"archive_kit": ("OPEN-PRIVATE.html",),
                    "drift_kit": ("OPEN-PRIVATE.html",),
                    "session_history": ("OPEN-PRIVATE.html",)}
GROUPS = (
    ("01 · Lab intake and provenance", (
        ("initial_kit", "Original private lab briefing", "Read the original producer declaration. Check source ownership independently."),
        ("drift_kit", "Original two-source change board", "Review only original declared changes; never call them verified fixes."),
        ("ledger_kit", "Original source-byte ledger", "Ask a HUMAN to compare the exact original snapshot; a hash is not authenticity."),
        ("archive_kit", "Original private archive", "Retain original source references under approved owner-only custody."),
        ("notes_kit", "Credential-masked PRIVATE notes", "Review any credentials or personal data manually before a later disclosure."),
    )),
    ("02 · Benchmarks and human interpretation", (
        ("benchmark_kit", "Original lab benchmark", "Interpret only finished isolated lab reports, including adverse HOLD."),
        ("trajectory_kit", "Original multi-cohort trajectory", "Review declared chronological order and unknown-versus-zero semantics."),
        ("reviewer_kit", "Multi-HUMAN review", "Reconcile independent HUMAN opinions; never infer real identities or consent."),
        ("portfolio_kit", "PRIVATE HUMAN follow-up portfolio", "Confirm HUMAN owner, date and next discussion outside this tool."),
    )),
    ("03 · Select-only evidence and reply", (
        ("curation_kit", "Original source-bound selection", "Select source-matched findings manually in the original HUMAN editor."),
        ("selected_kit", "Original selected PRIVATE dossier", "Inspect selected original findings; never call them verified."),
        ("evidence_preparation", "Original evidence HUMAN selection", "Edit original source-bound HUMAN selection before any publication."),
        ("evidence_dossier", "Selected-only evidence dossier", "Review original recipient questions without sending them."),
        ("recipient_preparation", "PRIVATE recipient studio", "Obtain independent current recipient identity and consent outside the app."),
        ("sender_preparation", "PRIVATE sender triage", "Reconcile HUMAN return and original receipt; no automatic dispatch."),
    )),
    ("04 · Remediation and scoped HUMAN handoff", (
        ("remediation_kit", "Original HUMAN casebook", "Review original casebook; no fixes, retest or approval are implied."),
        ("team_kit", "Original PRIVATE HUMAN team coordination", "Review per-team minimum necessary materials and recipient channel."),
    )),
    ("05 · Disclosure and retention", (
        ("disclosure_workroom", "Original source-free disclosure decisions", "Human review, redact and HOLD until separate authorized release."),
        ("disclosure_review", "Original PRIVATE disclosure review", "A human-only receipt is not authorization to distribute."),
        ("retention_workroom", "Original HUMAN retention history", "Review drift and proposals; NEVER auto-delete data."),
        ("session_history", "Original PRIVATE session continuity", "Source paths may have changed; re-admit original files before HUMAN use."),
    )),
)

# All known existing local product pages must be admitted by the original
# owner/private file mode boundary. No extra path fields or arbitrary hrefs.
def snapshot(session) -> tuple[list[dict], int, int]:
    values = custody.clean_paths(session)
    groups = []
    available = missing = 0
    for heading, entries in GROUPS:
        cards = []
        for key, title, next_step in entries:
            folder = values.get(key, "")
            original = custody.PAGES.get(key)
            filenames = original[1] if original else ADDITIONAL_PAGES.get(key, ())
            page = custody.original_page(folder, filenames) if filenames else None
            if page is not None:
                href = page.as_uri()
                if not href.startswith("file:///"):
                    page = None
            if page is not None:
                available += 1
                state = "LOCAL_PAGE_PRESENT_REVIEW_ONLY"
            elif folder:
                missing += 1
                state = "HOLD_PAGE_UNAVAILABLE"
            else:
                missing += 1
                state = "NOT_PREPARED"
            cards.append({"key": key, "title": title, "state": state,
                          "human_next": next_step,
                          "local_href": page.as_uri() if page is not None else ""})
        groups.append({"heading": heading, "cards": cards})
    return groups, available, missing


def markup(groups: list[dict], available: int, missing: int) -> bytes:
    sections = []
    for group in groups:
        cards = []
        for item in group["cards"]:
            title = html.escape(item["title"])
            instruction = html.escape(item["human_next"])
            if item["state"] == "LOCAL_PAGE_PRESENT_REVIEW_ONLY":
                state = "LOCAL PAGE PRESENT · REVIEW ONLY"
                link = ('<a rel="noopener noreferrer" href="' +
                        html.escape(item["local_href"], quote=True) +
                        '">Open original PRIVATE page locally</a>')
            elif item["state"] == "HOLD_PAGE_UNAVAILABLE":
                state = "HOLD · PREVIOUS PATH UNAVAILABLE"
                link = "<p>Re-check original owner-only folder and source workflow manually.</p>"
            else:
                state = "NOT PREPARED"
                link = "<p>Run the original native PRIVATE workflow only when manually chosen.</p>"
            cards.append('<li><h3>' + title + '</h3><strong>' +
                         html.escape(state) + '</strong><p>' + instruction +
                         '</p>' + link + '</li>')
        sections.append('<section><h2>' + html.escape(group["heading"]) +
                        '</h2><ul>' + "".join(cards) + '</ul></section>')
    body = """<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'; connect-src 'none'; form-action 'none'; base-uri 'none'">
<title>LightUp · PRIVATE Assessment Route Board</title>
<style>
:root{color-scheme:dark;font:16px/1.55 system-ui,sans-serif;background:#0d1625;color:#ecf3f9}
*{box-sizing:border-box}body{max-width:1260px;margin:0 auto;padding:24px}
header{background:#1a3048;border:1px solid #496781;border-radius:20px;padding:30px}
h1{font-size:clamp(1.7rem,4vw,2.7rem);line-height:1.17;margin:.3rem 0}
p{color:#d4e3ee}.warning{font-weight:700;color:#ffe2a0}
.summary{font-size:1.2rem;color:#a9eddc}
main{display:grid;grid-template-columns:repeat(auto-fit,minmax(min(100%,440px),1fr));gap:18px;margin-top:20px}
section{border:1px solid #46617a;border-radius:14px;background:#17283d;padding:22px}
h2{font-size:1.16rem;color:#a1e9dc;margin:0 0 12px}
ul{padding:0;list-style:none;margin:0}
li{border-top:1px solid #46617a;padding:15px 0}h3{font-size:1rem;margin:0 0 5px}
strong{font-size:.85rem;color:#f0d79d}li p{margin:7px 0;font-size:.9rem}
a{color:#96ddff;font-weight:680}a:focus-visible{outline:3px solid #fbd999;outline-offset:4px}
footer{margin:22px 0;border-left:4px solid #fbd999;padding:16px;background:#263349}
</style>
<header><p class="warning">LIGHTUP / OWNER-PRIVATE / PLAN-LAB ONLY / DRAFT-HOLD</p>
<h1>Private Assessment Route Board</h1>
<p>Local, scriptless HUMAN navigation across original offline products. This is
a one-time snapshot of local entry-page availability, NOT a stage completion or
source integrity check.</p>
<p class="summary">""" + str(available) + " locally openable originals · " + str(missing) + """ requiring separate HUMAN attention</p>
<p class="warning">NO permission, authentic source, validated finding, signed review,
client/operator consent, grant, execution, external transmission or release.</p>
</header><main>""" + "".join(sections) + """</main>
<footer><b>PRIVATE:</b> file:// bookmarks may disclose confidential local folder names.
Never post or email this HTML. All imported source artifacts stay outside this
board. Existing original workflows must independently re-admit exact bytes and
HUMAN decisions every time. No automatic execution, network, scanning, model,
assessment, retest, deletion, scheduling or distribution occurs. True authenticated
client + operator consent, at-use revocation and explicit HUMAN GO remain absent.
Incubate M3/M7 · REVIEW ONLY · DRAFT/HOLD.</footer></html>"""
    return body.encode("utf-8")


def build(session, parent_name: str, room_name: str) -> Path:
    if not custody.NAME.fullmatch(room_name):
        raise custody.Hold("HOLD: invalid unique private route-board folder")
    parent = Path(parent_name).resolve(strict=True)
    if (parent == custody.ROOT or custody.ROOT in parent.parents
            or not custody.private(parent, True)):
        raise custody.Hold("HOLD: existing owner-only 0700 parent outside repository required")
    room = parent / room_name
    if os.path.lexists(room):
        raise custody.Hold("HOLD: existing original owner-private folder cannot be overwritten")
    groups, available, missing = snapshot(session)
    html_bytes = markup(groups, available, missing)
    minimal = {
        "schema": SCHEMA, "status": "REVIEW_ONLY", "authority": custody.AUTHORITY,
        "source_bytes_included": False, "reviewed_or_verified": False,
        "local_pages_present": available, "manual_attention_required": missing,
        "groups": [{
            "heading": group["heading"],
            "workflows": [{"key": item["key"], "state": item["state"],
                           "human_next": item["human_next"]}
                          for item in group["cards"]]
        } for group in groups],
    }
    json_bytes = (json.dumps(minimal, ensure_ascii=True, sort_keys=True,
                             separators=(",", ":")) + "\n").encode("ascii")
    room.mkdir(mode=0o700)
    try:
        if not custody.private(room, True):
            raise custody.Hold("HOLD: owner-only mode for new room refused")
        custody.private_write(room, "OPEN-PRIVATE.html", html_bytes)
        custody.private_write(room, "PRIVATE-ROUTE-SUMMARY.json", json_bytes)
        fd = os.open(room, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except (OSError, ValueError):
        shutil.rmtree(room)
        raise custody.Hold("HOLD: failed to publish owner-private route board") from None
    return room / "OPEN-PRIVATE.html"
