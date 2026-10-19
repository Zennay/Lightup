#!/usr/bin/env python3
"""Private encrypted HUMAN coordination plans for independently admitted inboxes.

This is local operator workload management, NOT modification of original
findings, client consent, evidence, security decisions or remediation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from datetime import date
import hashlib
import hmac
import html
import json
import os
from pathlib import Path
import re
import secrets
import stat
import sys

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

import attest
import inbox
import transport

review = attest.review
native = attest.read_cockpit
KIND = "lightup.private_human_slot_coordination_plan"
WARNING = ("LOCAL HUMAN coordination labels only: not authenticated ownership, "
           "client consent, source provenance, verified fixes, retests or authorization.")
MAGIC = b"LIGHTUP-PRIVATE-HUMAN-SLOT-PLAN-v1\x00"
DOMAIN = b"LightUp private HUMAN slot-only plan AES256GCM v1\x00"
MAX_RAW = 16384
MAX_FILE = len(MAGIC) + 12 + MAX_RAW + 16
STAGES = ("unassigned", "assigned", "waiting_human", "locally_answered")
PRIORITIES = ("normal", "attention", "urgent_review")
PLAN_FIELDS = frozenset({"kind", "schema_version", "disposition", "revision",
                         "prior_encrypted_plan_sha256", "inbox_manifest_sha256",
                         "slots", "warning", *review.FLAGS})
SLOT_FIELDS = frozenset({"slot", "original_cockpit_manifest_sha256", "assignee",
                         "stage", "priority", "due_date", "private_note"})
HEX = re.compile(r"^[0-9a-f]{64}$")
ASSIGNEE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9 _.@-]{0,47}$")
CSS = (
    "body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;"
    "padding:1rem;background:#f5f7fb;color:#14223a}h1{font-size:1.9rem}"
    "table{border-collapse:collapse;width:100%;background:white}"
    "th,td{border:1px solid #c9d3e4;padding:.8rem;text-align:left;vertical-align:top}"
    "th{background:#e8eef8}small{color:#43546c}a{color:#2453a0}"
    ".urgent_review{font-weight:700}.waiting_human{font-style:italic}"
    "p{line-height:1.5}article{padding:1rem;background:#fff;margin-bottom:1rem}"
)


def require(condition: bool) -> None:
    attest.require(condition)


def private_text(value: object, maximum: int, label: str) -> str:
    require(type(value) is str and len(value.encode("utf-8")) <= maximum)
    require(not any(ord(ch) < 32 or ord(ch) == 127 or
                    __import__("unicodedata").category(ch) in ("Cf", "Cs", "Co", "Cn", "Zl", "Zp")
                    for ch in value))
    return value


def due(value: object) -> str | None:
    if value is None:
        return None
    require(type(value) is str and re.fullmatch(r"\d{4}-\d{2}-\d{2}", value) is not None)
    require(date.fromisoformat(value).isoformat() == value)
    return value


def key_bytes(path: Path) -> bytes:
    return hmac.new(attest.key_bytes(path), DOMAIN, hashlib.sha256).digest()


def manifest_sha(inbox_dir: Path) -> str:
    return hashlib.sha256(review.private_read(inbox_dir / "manifest.json")).hexdigest()


def sealed_fields(document: object, original: dict, current_manifest: str) -> dict:
    require(type(document) is dict and set(document) == PLAN_FIELDS and
            document["kind"] == KIND and
            type(document["schema_version"]) is int and document["schema_version"] == 1 and
            document["disposition"] == "PRIVATE_LOCAL_HUMAN_COORDINATION_ONLY" and
            document["warning"] == WARNING and
            all(document.get(f) is False for f in review.FLAGS))
    revision = document["revision"]
    require(type(revision) is int and 1 <= revision <= 1000)
    parent = document["prior_encrypted_plan_sha256"]
    require((revision == 1 and parent is None) or
            (revision > 1 and type(parent) is str and HEX.fullmatch(parent) is not None))
    require(document["inbox_manifest_sha256"] == current_manifest and
            type(document["slots"]) is list and
            len(document["slots"]) == original["slot_count"])
    for index, row in enumerate(document["slots"], 1):
        require(type(row) is dict and set(row) == SLOT_FIELDS and
                type(row["slot"]) is int and row["slot"] == index and
                row["original_cockpit_manifest_sha256"] ==
                original["slots"][index - 1]["source_free_manifest_sha256"])
        require(row["stage"] in STAGES and type(row["stage"]) is str and
                row["priority"] in PRIORITIES and type(row["priority"]) is str)
        person = private_text(row["assignee"], 48, "assignee")
        require(person == "" or ASSIGNEE.fullmatch(person) is not None)
        private_text(row["private_note"], 400, "note")
        due(row["due_date"])
        require(row["stage"] != "unassigned" or person == "")
        require(row["stage"] == "unassigned" or person != "")
    return document


def canonical(document: dict) -> bytes:
    return transport.canonical(document)


def encrypt(document: dict, secret_file: Path, output: Path) -> None:
    attest.private_parent(output)
    require(output != secret_file and not output.exists() and not output.is_symlink())
    raw = canonical(document)
    require(len(raw) <= MAX_RAW)
    nonce = secrets.token_bytes(12)
    body = AESGCM(key_bytes(secret_file)).encrypt(nonce, raw, MAGIC)
    attest.exclusive_private_write(output, MAGIC + nonce + body)


def decrypt(source: Path, secret_file: Path, original: dict,
            digest: str) -> tuple[dict, bytes]:
    require(source != secret_file)
    raw = attest.private_file(source, MAX_FILE)
    require(raw.startswith(MAGIC) and len(raw) >= len(MAGIC) + 12 + 16)
    nonce = raw[len(MAGIC):len(MAGIC) + 12]
    payload = AESGCM(key_bytes(secret_file)).decrypt(nonce, raw[len(MAGIC)+12:], MAGIC)
    require(len(payload) <= MAX_RAW)
    document = json.loads(payload.decode("ascii"),
                          object_pairs_hook=transport.no_duplicate_pairs)
    require(canonical(document) == payload)
    return sealed_fields(document, original, digest), raw


def admitted_inbox(folder: Path, secret_file: Path) -> tuple[dict, str]:
    original = inbox.inspect(folder, secret_file)
    return original, manifest_sha(folder)


def start(folder: Path, secret_file: Path, output: Path) -> dict:
    original, digest = admitted_inbox(folder, secret_file)
    rows = [
        {"slot": idx, "original_cockpit_manifest_sha256": source["source_free_manifest_sha256"],
         "assignee": "", "stage": "unassigned", "priority": "normal",
         "due_date": None, "private_note": ""}
        for idx, source in enumerate(original["slots"], 1)
    ]
    plan = {"kind": KIND, "schema_version": 1,
            "disposition": "PRIVATE_LOCAL_HUMAN_COORDINATION_ONLY",
            "revision": 1, "prior_encrypted_plan_sha256": None,
            "inbox_manifest_sha256": digest, "slots": rows, "warning": WARNING,
            **{f: False for f in review.FLAGS}}
    sealed_fields(plan, original, digest)
    require(folder != output and folder not in output.parents and
            secret_file != output)
    encrypt(plan, secret_file, output)
    return plan


def revise(folder: Path, secret_file: Path, old_plan: Path, output: Path,
           slot: int, assignee: str | None, stage: str | None,
           priority: str | None, due_date: str | None,
           note: str | None, clear_due: bool, clear_note: bool) -> dict:
    original, digest = admitted_inbox(folder, secret_file)
    prior, previous_bytes = decrypt(old_plan, secret_file, original, digest)
    require(output != old_plan and output != folder and folder not in output.parents and
            type(slot) is int and 1 <= slot <= len(prior["slots"]) and
            prior["revision"] < 1000)
    require(not (clear_due and due_date is not None) and not (clear_note and note is not None))
    row = dict(prior["slots"][slot - 1])
    if assignee is not None:
        row["assignee"] = assignee
    if stage is not None:
        row["stage"] = stage
    if priority is not None:
        row["priority"] = priority
    if clear_due or due_date is not None:
        row["due_date"] = None if clear_due else due_date
    if clear_note or note is not None:
        row["private_note"] = "" if clear_note else note
    require(row != prior["slots"][slot - 1])
    next_document = dict(prior)
    next_document["slots"] = [dict(item) for item in prior["slots"]]
    next_document["slots"][slot - 1] = row
    next_document["revision"] = prior["revision"] + 1
    next_document["prior_encrypted_plan_sha256"] = hashlib.sha256(previous_bytes).hexdigest()
    sealed_fields(next_document, original, digest)
    # Already-admitted original and encrypted prior must remain unchanged
    # before writing a new independent immutable snapshot.
    require(inbox.inspect(folder, secret_file) == original and
            manifest_sha(folder) == digest and
            attest.private_file(old_plan, MAX_FILE) == previous_bytes)
    encrypt(next_document, secret_file, output)
    return next_document


def overview(document: dict) -> dict:
    counts = Counter(row["stage"] for row in document["slots"])
    return {
        "kind": "lightup.private_anonymous_human_slot_workload",
        "schema_version": 1,
        "disposition": "UNVERIFIED_HUMAN_PLANNING_COUNTS_ONLY",
        "slots_not_unique_cases": len(document["slots"]),
        "local_stage_totals": {name: counts[name] for name in STAGES},
        "pending_local_human_attention_slots":
            sum(r["stage"] != "locally_answered" for r in document["slots"]),
        "due_slots_with_local_dates": sum(r["due_date"] is not None for r in document["slots"]),
        "warning": WARNING,
        **{f: False for f in review.FLAGS}
    }


def render(document: dict) -> bytes:
    summary = overview(document)
    rows = []
    for slot in document["slots"]:
        idx = slot["slot"]
        href = html.escape(f"slot-{idx:02d}/cockpit/index.html", quote=True)
        cols = [html.escape(slot["assignee"] or "Unassigned"),
                html.escape(slot["stage"]), html.escape(slot["priority"]),
                html.escape(slot["due_date"] or "None"),
                html.escape(slot["private_note"] or "—")]
        rows.append(
            f'<tr><td>PRIVATE slot {idx:02d}</td><td>{cols[0]}</td>'
            f'<td class="{cols[1]}">{cols[1]}</td>'
            f'<td class="{cols[2]}">{cols[2]}</td><td>{cols[3]}</td>'
            f'<td>{cols[4]}</td></tr>')
    text = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta http-equiv="Content-Security-Policy" content="default-src \'none\'; '
        'style-src \'unsafe-inline\'; base-uri \'none\'; form-action \'none\';">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<title>PRIVATE HUMAN Coordination</title><style>'+CSS+'</style></head><body>'
        '<h1>PRIVATE HUMAN Coordination</h1><article><p><strong>Offline plan revision '+
        str(document["revision"])+'</strong> · '+str(summary["slots_not_unique_cases"])+
        ' original source-free slot(s). '+str(summary["pending_local_human_attention_slots"])+
        ' slots still in local HUMAN review.</p><p><small>'+html.escape(WARNING)+
        '</small></p></article><table><thead><tr>'
        '<th>Slot</th><th>Local operator label</th><th>Local stage</th>'
        '<th>Attention</th><th>Human review date</th><th>PRIVATE operator note</th>'
        '</tr></thead><tbody>'+''.join(rows)+'</tbody></table>'
        '<p><small>These are manual private coordination labels. They cannot close'
        ' the original source-owned HUMAN questions, verify fixes, authorize'
        ' access or establish reviewer identity. Open the separately received'
        ' source-free inbox to inspect the original anonymized summaries.</small></p>'
        '</body></html>\n')
    return text.encode("utf-8")


def publish(folder: Path, secret: Path, plan_file: Path, output: Path,
            *, linked_workroom: bool = False) -> dict:
    original, digest = admitted_inbox(folder, secret)
    plan, raw = decrypt(plan_file, secret, original, digest)
    require(output.is_absolute() and output != folder and
            folder not in output.parents and output != plan_file and
            output != secret and not output.exists())
    public = overview(plan)
    if linked_workroom:
        import linked_board
        html_raw = linked_board.render(plan)
    else:
        html_raw = render(plan)
    anonymous = native.workspace.pretty(public)
    data = {"kind": "lightup.private_human_coordination_browser",
            "schema_version": 1, "files": {"index.html": inbox.descriptor(html_raw),
                                           "anonymous-counts.json": inbox.descriptor(anonymous)},
            "source_inbox_manifest_sha256": digest,
            "encrypted_plan_sha256": hashlib.sha256(raw).hexdigest(),
            "warning": WARNING}
    if linked_workroom:
        data["navigation"] = linked_board.MODE
    require(inbox.inspect(folder, secret) == original and
            manifest_sha(folder) == digest and
            attest.private_file(plan_file, MAX_FILE) == raw)
    native.workspace.publish_bundle(
        output, {"index.html": html_raw, "anonymous-counts.json": anonymous},
        native.workspace.pretty(data))
    return public


def main() -> int:
    parser = argparse.ArgumentParser(description="Encrypted, append-only LOCAL HUMAN "
        "slot assignments and review schedule, never original remediation state")
    actions = parser.add_subparsers(dest="action", required=True)
    for command in ("start", "revise", "overview", "publish"):
        p = actions.add_parser(command)
        p.add_argument("--inbox", required=True, type=Path)
        p.add_argument("--key-file", required=True, type=Path)
        if command in ("revise", "overview", "publish"):
            p.add_argument("--plan", required=True, type=Path)
        if command in ("start", "revise"):
            p.add_argument("--output", required=True, type=Path)
        if command == "publish":
            p.add_argument("--output-dir", required=True, type=Path)
        if command == "revise":
            p.add_argument("--slot", required=True, type=int)
            p.add_argument("--assignee")
            p.add_argument("--stage", choices=STAGES)
            p.add_argument("--priority", choices=PRIORITIES)
            p.add_argument("--due-date")
            p.add_argument("--note")
            p.add_argument("--clear-due", action="store_true")
            p.add_argument("--clear-note", action="store_true")
    args = parser.parse_args()
    try:
        if args.action == "start":
            record = start(args.inbox, args.key_file, args.output)
            print("New PRIVATE encrypted HUMAN plan written exclusively.")
        elif args.action == "revise":
            record = revise(args.inbox, args.key_file, args.plan, args.output,
                            args.slot, args.assignee, args.stage, args.priority,
                            args.due_date, args.note, args.clear_due, args.clear_note)
            print("New immutable PRIVATE HUMAN plan revision created; previous left unchanged.")
        else:
            original, digest = admitted_inbox(args.inbox, args.key_file)
            record, _ = decrypt(args.plan, args.key_file, original, digest)
            if args.action == "publish":
                publish(args.inbox, args.key_file, args.plan, args.output_dir)
                print("PRIVATE HTML human-coordination board published in new 0700 directory.")
            else:
                print("REVIEW_ONLY: private HUMAN plan admitted under original inbox bytes.")
        counts = overview(record)
        print(f"Plan revision {record['revision']}; {counts['slots_not_unique_cases']} "
              f"source-free work slots; {counts['pending_local_human_attention_slots']} "
              "still requiring local HUMAN coordination.")
        print("No verified remediation, client consent, source authenticity or authority.")
        return 2
    except (OSError, ValueError, TypeError, KeyError, UnicodeError, RecursionError,
            OverflowError, InvalidTag, transport.binascii.Error, review.Hold):
        print("HOLD: PRIVATE HUMAN plan or inbox could not be admitted; no action authorized.",
              file=sys.stderr)
        return 3


if __name__ == "__main__":
    sys.exit(main())
