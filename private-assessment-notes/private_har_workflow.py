"""One-command offline PRIVATE HAR review workflow, original receipts intact.

Creates fresh owner-only original and immutable independent cue packets with
a tiny source-free launcher. No scan, grant, sharing, consent or approval.
"""
from __future__ import annotations

from contextlib import redirect_stdout
from hashlib import sha256
from html import escape
import io
import json
import os
from pathlib import Path
import re
import shutil
import tempfile

from notes import (FALSE_FLAGS, Hold, file_new, load_workroom,
                   prepare as original_prepare, private_directory,
                   private_input, read_json, save_json)
from private_masking_cues import create as create_cues, reopen as reopen_cues

SCHEMA = "lightup.private_har_review_workflow.v1"
MANIFEST = "PRIVATE-HAR-WORKFLOW.json"
LANDING = "OPEN-PRIVATE-HAR-WORKFLOW.html"
NAMES = (
    ("original_kit", re.compile(r"PRIVATE-lightup-notes-[a-zA-Z0-9_-]{8,32}")),
    ("masking_cue_room", re.compile(r"PRIVATE-lightup-masking-cues-[a-zA-Z0-9_-]{8,32}")),
)


def _launcher(original_name: str, cue_name: str, count: int) -> bytes:
    """Source-free literal sibling paths, no original IDs/content or SHA."""
    for name, pattern in NAMES:
        value = original_name if name == "original_kit" else cue_name
        if not pattern.fullmatch(value):
            raise Hold("HOLD: invalid local PRIVATE source-room identity")
    if type(count) is not int or not 1 <= count <= 12:
        raise Hold("HOLD: invalid bounded PRIVATE original source count")
    original_href = "../" + escape(original_name, quote=True)
    cues_href = "../" + escape(cue_name, quote=True)
    return ("""<!doctype html><html lang="en"><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none';style-src 'unsafe-inline';connect-src 'none';form-action 'none';base-uri 'none';object-src 'none';img-src 'none'">
<title>LightUp PRIVATE HAR review workspace</title>
<style>body{font:16px/1.5 system-ui;background:#f2f5f8;color:#16334b;
max-width:960px;margin:2rem auto;padding:1rem}
header,section{background:white;padding:1.3rem;border:1px solid #c8d2dc;
border-radius:10px;margin:1rem 0}
aside{padding:1rem;background:#fff0e3;border-left:5px solid #aa5f36}
a{color:#155d91}a:focus-visible{outline:3px solid #a66b29}
li{margin:.65rem 0}
@media print{body{margin:0;background:white}}</style>
<header><h1>LightUp PRIVATE HAR HUMAN review</h1>
<aside><b>INCUBATE M3/M7 — PLAN/LAB ONLY — REVIEW_ONLY/HOLD.</b>
No real scan, model call, grant, assessment verdict, automated consent,
privacy clearance, target access, external sharing or deployment.
Original inputs remain owner-private. Masked text can still contain
sensitive information. This launcher contains only generic folder names
created locally and original source count — never source names, raw text,
credentials, URLs, hashes, identities or human notes.</aside>
<p>Selected original positions: """ + str(count) + """.
The two independent PRIVATE source-bound workrooms below were generated
together. Only original-source manual review is authoritative for a human
decision, and that decision never grants active execution.</p></header>
<section><h2>Open the offline source-owner workrooms</h2><ol>
<li><a href='""" + original_href + """/OPEN-PRIVATE.html'>Original PRIVATE HUMAN workroom</a>
— inspect and manually review masked notes with the separately retained
original private source. Source-masking remains heuristic.</li>
<li><a href='""" + cues_href + """/PRIVATE-HAR-STUDIO.html'>PRIVATE HAR
HUMAN task Status Studio</a> — filter, set manual task statuses,
resume/export the complete source-minimal PRIVATE CSV. Statuses are
unverified self-reports and never approval.</li>
<li><a href='""" + cues_href + """/PRIVATE-HAR-QUEUE.html'>HAR
category and whole-copy HOLD queue</a> — generic source-position cues.</li>
<li><a href='""" + cues_href + """/PRIVATE-HAR-QUESTIONS.html'>Print-only
original-position HUMAN source questions</a>.</li></ol>
<p>Original cue receipts/CSV/HTML must remain unchanged.
Save a <b>separate</b> edited status CSV in an owner-only 0700 directory
and chmod 0600 before the native import. Browser-created downloads
are not automatically private.</p></section>
<section><h2>Resume with native source-bound admission</h2>
<p>Run <code>notes.py har-review-reopen --workflow-room &lt;this-folder&gt;</code>
to re-admit every original source/cue/launcher byte. Then run
<code>notes.py har-review-progress --workflow-room &lt;this-folder&gt;
--edited-actions &lt;private-csv&gt; --private-parent
&lt;owner-private-folder&gt;</code> to create a NEW private HOLD status
report. After two separate status rounds, use the existing
<code>har-action-history</code> with the original and cue rooms.
This page does not invoke Python, inspect raw source, write state or
contact a recipient.</p>
<p>Source-owner and independent security/privacy/browser reviews,
authentic separate at-use client/operator consent, revocation, exact-head
CI and explicit HUMAN GO remain required for any main/live release.</p>
</section></html>""").encode("utf-8")


def _manifest(original: Path, cues: Path) -> dict:
    _original_binding, sources, _rows = load_workroom(original)
    return {
        "schema": SCHEMA, "claimed_status": "HOLD",
        "original_kit": original.name,
        "masking_cue_room": cues.name,
        "original_count": len(sources),
        "source_manifest_sha256_unsigned": sha256(private_input(
            str(original / "PRIVATE-source-bindings.json"), 128*1024
        )).hexdigest(),
        "masking_receipt_sha256_unsigned": sha256(private_input(
            str(cues / "PRIVATE-masking-cues-receipt.json"), 65536
        )).hexdigest(),
        "source_bound_but_not_authorized": True,
        **{flag: False for flag in FALSE_FLAGS},
    }


def prepare(sources: list[str], private_parent: str) -> int:
    parent = private_directory(private_parent)
    created: list[Path] = []
    complete = False
    try:
        original: list[Path] = []
        # Suppress incomplete component OPEN messages until all components
        # are published successfully. Use original native admission unchanged.
        with redirect_stdout(io.StringIO()):
            if original_prepare(sources, str(parent),
                                include_masking_cues=True,
                                created_room=original) != 2:
                raise Hold("HOLD: original PRIVATE notes preparation refused")
        created += original
        cue_rooms: list[Path] = []
        with redirect_stdout(io.StringIO()):
            if create_cues(str(original[0]), str(parent),
                           created_room=cue_rooms) != 2:
                raise Hold("HOLD: original PRIVATE cue preparation refused")
        created += cue_rooms
        workflow = Path(tempfile.mkdtemp(prefix="PRIVATE-lightup-har-workflow-",
                                         dir=parent))
        os.chmod(workflow, 0o700)
        created.append(workflow)
        manifest = _manifest(original[0], cue_rooms[0])
        file_new(workflow / LANDING, _launcher(
            original[0].name, cue_rooms[0].name, manifest["original_count"]))
        save_json(workflow / MANIFEST, manifest)
        # Native product admission before publishing any component path:
        # reconstruct the exact original source, v19 cues and launcher.
        # This is part of the create transaction, not a separate QA run.
        admit(str(workflow))
        complete = True
        print("REVIEW_ONLY/HOLD: linked offline PRIVATE original+HAR workrooms prepared")
        print("OPEN LOCALLY: " + str(workflow / LANDING))
        print("ORIGINAL KIT: " + str(original[0]))
        print("IMMUTABLE CUE ROOM: " + str(cue_rooms[0]))
        print("No source, privacy, consent, authorization, network or release claim.")
        return 2
    finally:
        if not complete:
            # Only fresh directories published by this invocation are rolled
            # back; never touch an earlier external source or other workroom.
            for folder in reversed(created):
                shutil.rmtree(folder)


def admit(workflow_room: str) -> tuple[Path, Path]:
    room = private_directory(workflow_room)
    stored = read_json(room / MANIFEST, 65536)
    if type(stored) is not dict or set(stored) != set(_manifest_fields()):
        raise Hold("HOLD: invalid PRIVATE HAR original-workflow receipt")
    for key, pattern in NAMES:
        value = stored.get(key)
        if type(value) is not str or not pattern.fullmatch(value):
            raise Hold("HOLD: invalid original PRIVATE workroom identity")
    parent = private_directory(str(room.parent))
    original = private_directory(str(parent / stored["original_kit"]))
    cues = private_directory(str(parent / stored["masking_cue_room"]))
    current = _manifest(original, cues)
    if current != stored:
        raise Hold("HOLD: source-bound PRIVATE HAR workroom receipt changed")
    # No new direct auth check, only immutable original native source/cue
    # packet read-only byte-reconstruction (including v19 studio HTML).
    with redirect_stdout(io.StringIO()):
        if reopen_cues(str(original), str(cues)) != 3:
            raise Hold("HOLD: source-bound original HAR cue re-admission refused")
    expected = _launcher(original.name, cues.name, current["original_count"])
    if private_input(str(room / LANDING), 65536) != expected:
        raise Hold("HOLD: original PRIVATE HAR workflow launch page changed")
    return original, cues


def _manifest_fields() -> tuple[str, ...]:
    return ("schema", "claimed_status", "original_kit", "masking_cue_room",
            "original_count", "source_manifest_sha256_unsigned",
            "masking_receipt_sha256_unsigned", "source_bound_but_not_authorized",
            *FALSE_FLAGS)


def reopen(workflow_room: str) -> int:
    original, cues = admit(workflow_room)
    print("HOLD: original and cue rooms reopened read-only, no authorization")
    print("OPEN LOCALLY: " + str(Path(workflow_room).absolute() / LANDING))
    print("ORIGINAL KIT: " + str(original))
    print("IMMUTABLE CUE ROOM: " + str(cues))
    return 3


def progress(workflow_room: str, edited_actions: str,
             private_parent: str,
             previous_rounds: list[str] | None = None) -> int:
    """Import a fresh manual round and hand back a usable linked PRIVATE desk.

    This mutates only new owner-private output directories; never the
    immutable original, cue receipt or earlier HUMAN status packets.
    """
    original, cues = admit(workflow_room)
    parent = private_directory(private_parent)
    workflow = private_directory(workflow_room)
    if parent != workflow.parent:
        raise Hold("HOLD: linked PRIVATE HAR round must use workflow parent")
    previous_rounds = previous_rounds or []
    if len(previous_rounds) > 7:
        raise Hold("HOLD: maximum seven previous HUMAN rounds plus current")
    from private_har_progress import import_progress
    from private_har_review_desk import create as create_desk
    new_status: list[Path] = []
    new_desk: list[Path] = []
    completed = False
    try:
        # The original native importer does ALL identity/status admission.
        # Keep its partial output hidden until both linked packets exist.
        with redirect_stdout(io.StringIO()):
            if import_progress(str(original), str(cues), edited_actions,
                               str(parent), created_room=new_status) != 3:
                raise Hold("HOLD: native PRIVATE HAR HUMAN status import refused")
        with redirect_stdout(io.StringIO()):
            if create_desk(str(workflow), previous_rounds +
                           [str(new_status[0])], str(parent),
                           created_room=new_desk) != 3:
                raise Hold("HOLD: original-bound PRIVATE HAR review desk refused")
        completed = True
        print("HOLD: original-bound PRIVATE HAR manual status + next-action desk")
        print("STATUS LOCALLY: " + str(
            new_status[0] / "PRIVATE-HAR-HUMAN-status.html"))
        print("OPEN LOCALLY: " + str(
            new_desk[0] / "OPEN-PRIVATE-HAR-DESK.html"))
        print("Human statuses are unverified; no consent, scan or release.")
        return 3
    finally:
        if not completed:
            for folder in reversed(new_desk + new_status):
                shutil.rmtree(folder)
