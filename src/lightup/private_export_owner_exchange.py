"""Source-bound PRIVATE encrypted single-owner HUMAN evidence exchange.

Offline human coordination only. This is not authentication of a recipient,
an action authority, evidence truth, a completed remediation or a real retest.
It never touches scans, network targets, domain records or grant storage.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
from getpass import getpass
import hashlib
from html import escape
import json
from pathlib import Path
import sys

from .private_export_encrypted import (
    _open_sealed, _passphrase, _read_encrypted, _seal,
)
from .private_export_encrypted_notes import _read_plan, MAGIC_PLAN
from .private_export_handoff import (
    _atomic_private_publish, _no_duplicate_keys, _output_path,
)
from .private_export_workdesk import _render as _workdesk_html, STAGES

OWNER_MAGIC = b"LIGHTUP-PRIVATE-HUMAN-OWNER-V1\x00"
REPLY_MAGIC = b"LIGHTUP-PRIVATE-HUMAN-REPLY-V1\x00"
OWNER_LIMIT = 512 * 1024
REPLY_LIMIT = 128 * 1024
OWNER_HEADER = {"kind", "version", "source_csv_sha256",
                "declared_client_id", "declared_engagement_id", "owner_alias",
                "authorizes_action", "certifies_remediation", "confirms_client_identity",
                "records"}
SOURCE_FIELDS = ("finding_id", "title", "severity", "retest_status", "remediation")
REPLY_STATES = ("no_update", "needs_clarification", "work_planned",
                "work_in_progress", "awaiting_evidence", "ready_for_human_review",
                "blocked")


def _decode(path: str, secret: str, magic: bytes, limit: int) -> tuple[dict, bytes]:
    original = Path(path).expanduser()
    max_size = len(magic) + 16 + 12 + limit + 16
    if not original.is_file() or original.stat().st_size > max_size:
        raise ValueError("missing or oversized encrypted owner envelope")
    encrypted = original.read_bytes()
    plaintext = _open_sealed(encrypted, secret, magic=magic, max_plaintext=limit)
    try:
        payload = json.loads(plaintext.decode("utf-8", "strict"),
                             object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid authenticated owner payload") from exc
    if type(payload) is not dict:
        raise ValueError("invalid owner payload root")
    return payload, encrypted


def _original_fingerprint(row: dict) -> str:
    original = {name: row[name] for name in SOURCE_FIELDS}
    raw = json.dumps(original, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8", "strict")
    return hashlib.sha256(raw).hexdigest()


def _owner_packet(manifest: dict, rows: list[dict[str, str]],
                  annotations: dict[str, dict], alias: str) -> dict:
    if type(alias) is not str or not alias or len(alias) > 80:
        raise ValueError("invalid human self-declared owner alias")
    if alias != alias.strip() or any(ord(c) < 32 for c in alias):
        raise ValueError("noncanonical owner alias")
    items = []
    for row in sorted(rows, key=lambda value: value["finding_id"]):
        current = annotations[row["finding_id"]]
        if current["owner_alias"] != alias:
            continue
        items.append({
            "source": {key: row[key] for key in SOURCE_FIELDS},
            "original_record_sha256": _original_fingerprint(row),
            "human_stage": current["stage"],
            "proposed_due_date": current["due_date"],
            "human_note": current["human_note"],
        })
    if not items:
        raise ValueError("no original findings explicitly assigned to this alias")
    return {
        "kind": "lightup.private_owner_brief",
        "version": 1,
        "source_csv_sha256": manifest["source_csv_sha256"],
        "declared_client_id": manifest["declared_client_id"],
        "declared_engagement_id": manifest["declared_engagement_id"],
        "owner_alias": alias,
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_client_identity": False,
        "records": items,
    }


def _validate_owner(data: dict) -> dict:
    if set(data) != OWNER_HEADER or data["kind"] != "lightup.private_owner_brief":
        raise ValueError("invalid original owner brief schema")
    if type(data["version"]) is not int or data["version"] != 1:
        raise ValueError("unknown owner brief version")
    if any(data[x] is not False for x in
           ("authorizes_action", "certifies_remediation", "confirms_client_identity")):
        raise ValueError("owner packet claims authority")
    for field in ("source_csv_sha256", "declared_client_id", "owner_alias"):
        if type(data[field]) is not str or not data[field].strip():
            raise ValueError("invalid owner source identity declaration")
    if data["declared_engagement_id"] is not None and (
        type(data["declared_engagement_id"]) is not str or
        not data["declared_engagement_id"].strip()
    ):
        raise ValueError("invalid declared engagement")
    if type(data["records"]) is not list or not 0 < len(data["records"]) <= 128:
        raise ValueError("invalid owner finding count")
    seen = set()
    for item in data["records"]:
        if type(item) is not dict or set(item) != {
            "source", "original_record_sha256", "human_stage",
            "proposed_due_date", "human_note"
        }:
            raise ValueError("invalid owner row")
        row = item["source"]
        if type(row) is not dict or set(row) != set(SOURCE_FIELDS):
            raise ValueError("invalid original finding shape")
        if any(type(row[key]) is not str for key in SOURCE_FIELDS):
            raise ValueError("invalid original finding values")
        identity = row["finding_id"]
        if not identity or identity in seen:
            raise ValueError("ambiguous owner finding identity")
        seen.add(identity)
        if (_original_fingerprint(row) != item["original_record_sha256"] or
                type(item["original_record_sha256"]) is not str):
            raise ValueError("original record digest mismatch")
        if type(item["human_stage"]) is not str or item["human_stage"] not in STAGES:
            raise ValueError("invalid declared human stage")
        for key, limit in (("proposed_due_date", 10), ("human_note", 900)):
            if type(item[key]) is not str or len(item[key]) > limit:
                raise ValueError("invalid owner human field")
    return data


def _recipient_summary(packet: dict) -> str:
    severity: dict[str, int] = {}
    for item in packet["records"]:
        key = item["source"]["severity"]
        severity[key] = severity.get(key, 0) + 1
    return "Original assigned findings: " + str(len(packet["records"])) + (
        " · " + ", ".join(name + ": " + str(number)
                        for name, number in sorted(severity.items()))
    )


def _recipient_html(packet: dict) -> bytes:
    cards = []
    for item in packet["records"]:
        row = item["source"]
        cards.append(
            '<article><h2>' + escape(row["title"]) + '</h2>'
            '<p>Source-reported severity: <strong>' + escape(row["severity"]) +
            '</strong> · Original retest label: ' + escape(row["retest_status"]) + '</p>'
            '<p>PRIVATE original finding ID: <code>' + escape(row["finding_id"]) +
            '</code></p><h3>Source-proposed remediation</h3><p class="note">' +
            escape(row["remediation"]) + '</p><h3>Current HUMAN follow-up (unverified)</h3>'
            '<p>' + escape(item["human_stage"]) + ' · Proposed due: ' +
            escape(item["proposed_due_date"] or "not set") + '</p>'
            '<p class="note">' + escape(item["human_note"] or "No HUMAN coordination note") +
            '</p></article>'
        )
    html = (
        '<!doctype html><html lang="en"><head><meta charset="utf-8">'
        '<meta name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<title>LightUp · PRIVATE individual HUMAN owner brief</title>'
        '<style>body{font:16px system-ui;max-width:920px;margin:4vh auto;padding:16px;'
        'line-height:1.5;background:#f6f8fc;color:#142238}'
        'article{background:white;border:1px solid #d2dce8;border-radius:12px;'
        'padding:20px;margin:18px 0}.notice{border-left:5px solid #ac6200;'
        'padding:18px;background:#fff2d4}.note{white-space:pre-wrap;'
        'overflow-wrap:anywhere}code{overflow-wrap:anywhere}</style></head><body>'
        '<h1>PRIVATE · one alias HUMAN evidence follow-up</h1>'
        '<p class="notice"><strong>HUMAN HOLD · NOT VERIFIED.</strong> '
        'Self-declared owner aliases are NOT authenticated recipients. '
        'Original severity, claimed retest status, suggested remediation and notes '
        'are unverified claims. No scope permission, fix, retest, active assessment '
        'or real owner/client identity is established. This HTML is UNENCRYPTED. '
        'Verify the recipient and approved private transport independently.</p>'
        '<p>' + _recipient_summary(packet) + '</p>' + "".join(cards) +
        '</body></html>'
    )
    return html.encode("utf-8")


def _get_owner_packet(path: str, phrase: str) -> tuple[dict, bytes]:
    data, ciphertext = _decode(path, phrase, OWNER_MAGIC, OWNER_LIMIT)
    return _validate_owner(data), ciphertext


def _put(path: str, payload: dict, magic: bytes, limit: int) -> None:
    raw = json.dumps(payload, ensure_ascii=False, sort_keys=True,
                     separators=(",", ":")).encode("utf-8", "strict")
    passphrase = _passphrase("New recipient encryption passphrase", confirm=True)
    encrypted = _seal(raw, passphrase, magic=magic, max_plaintext=limit)
    _atomic_private_publish(_output_path(path, ".luo" if magic == OWNER_MAGIC else ".lur"),
                            encrypted)


def _reply(packet: dict, owner_ciphertext: bytes) -> dict:
    if not sys.stdin.isatty():
        raise ValueError("interactive recipient feedback terminal required")
    responses = []
    for number, item in enumerate(packet["records"], 1):
        row = item["source"]
        print("Assigned original finding", number, "of", len(packet["records"]))
        print("Original source ID:", row["finding_id"])
        print("Original title:", row["title"][:160])
        print("Permitted HUMAN states:", ", ".join(REPLY_STATES))
        state = input("Unverified HUMAN progress state: ").strip()
        if state not in REPLY_STATES:
            raise ValueError("unknown owner response state")
        note = input("Optional PRIVATE HUMAN response (max 450 chars): ").strip()
        if len(note) > 450 or any(ord(c) < 32 for c in note):
            raise ValueError("invalid private response note")
        responses.append({
            "finding_id": row["finding_id"],
            "original_record_sha256": item["original_record_sha256"],
            "reported_human_state": state,
            "human_reply": note,
        })
    return {
        "kind": "lightup.private_owner_reply",
        "version": 1,
        "owner_brief_ciphertext_sha256": hashlib.sha256(owner_ciphertext).hexdigest(),
        "source_csv_sha256": packet["source_csv_sha256"],
        "owner_alias": packet["owner_alias"],
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_client_identity": False,
        "records": responses,
    }


def _validate_reply(data: dict, owner_packet: dict, owner_ciphertext: bytes) -> list[dict]:
    keys = {"kind", "version", "owner_brief_ciphertext_sha256",
            "source_csv_sha256", "owner_alias", "authorizes_action",
            "certifies_remediation", "confirms_client_identity", "records"}
    if (set(data) != keys or data["kind"] != "lightup.private_owner_reply"
            or type(data["version"]) is not int or data["version"] != 1):
        raise ValueError("invalid owner reply kind or fields")
    if any(data[x] is not False for x in
           ("authorizes_action", "certifies_remediation", "confirms_client_identity")):
        raise ValueError("owner reply claims security authority")
    if (data["owner_brief_ciphertext_sha256"] !=
            hashlib.sha256(owner_ciphertext).hexdigest() or
            data["source_csv_sha256"] != owner_packet["source_csv_sha256"] or
            data["owner_alias"] != owner_packet["owner_alias"]):
        raise ValueError("owner reply does not match exact encrypted brief")
    expected = {item["source"]["finding_id"]: item for item in owner_packet["records"]}
    items = data["records"]
    if type(items) is not list or len(items) != len(expected):
        raise ValueError("owner reply missing original records")
    seen = set()
    for item in items:
        if type(item) is not dict or set(item) != {
            "finding_id", "original_record_sha256", "reported_human_state", "human_reply"
        }:
            raise ValueError("invalid owner feedback entry")
        identity = item["finding_id"]
        if type(identity) is not str or identity not in expected or identity in seen:
            raise ValueError("unknown or duplicated reply finding")
        seen.add(identity)
        if item["original_record_sha256"] != expected[identity]["original_record_sha256"]:
            raise ValueError("stale or modified original finding")
        if (type(item["reported_human_state"]) is not str or
                item["reported_human_state"] not in REPLY_STATES or
                type(item["human_reply"]) is not str or
                len(item["human_reply"]) > 450 or
                any(ord(c) < 32 for c in item["human_reply"])):
            raise ValueError("invalid human reply body")
    return items


def _review_html(packet: dict, replies: list[dict]) -> bytes:
    original = {item["source"]["finding_id"]: item for item in packet["records"]}
    parts = []
    for item in replies:
        src = original[item["finding_id"]]["source"]
        parts.append(
            '<article><h2>' + escape(src["title"]) + '</h2><p>Original finding: <code>' +
            escape(item["finding_id"]) + '</code></p><p>Source claim: ' +
            escape(src["severity"]) + ' / ' + escape(src["retest_status"]) +
            '</p><p>Returned unverified HUMAN progress: <strong>' +
            escape(item["reported_human_state"]) + '</strong></p><p class="note">' +
            escape(item["human_reply"] or "No text supplied") + '</p></article>'
        )
    return (
        '<!doctype html><html lang="en"><head><meta charset="utf-8"><meta '
        'name="viewport" content="width=device-width,initial-scale=1">'
        '<meta http-equiv="Content-Security-Policy" content="default-src &#39;none&#39;; '
        'style-src &#39;unsafe-inline&#39;; base-uri &#39;none&#39;; form-action &#39;none&#39;">'
        '<title>LightUp · PRIVATE owner reply HUMAN review</title><style>'
        'body{font:16px system-ui;color:#15243a;background:#f5f7fb;max-width:880px;'
        'margin:35px auto;padding:20px;line-height:1.55}'
        'article{background:white;border:1px solid #d3dce8;border-radius:10px;'
        'padding:18px;margin:16px 0}.note{white-space:pre-wrap;overflow-wrap:anywhere}'
        'code{overflow-wrap:anywhere}.warning{padding:15px;border-left:5px solid #ab6900;'
        'background:#fff1d1}</style></head><body><h1>PRIVATE HUMAN owner response review</h1>'
        '<p class="warning">HUMAN HOLD: an encrypted reply and a matching checksum do '
        '<strong>not</strong> authenticate an owner, client, repair, permission or retest. '
        'The original database and source HUMAN plan remain unchanged. '
        'This locally written HTML is unencrypted. Verify the actual responder and '
        'original source independently before any separate human action.</p>'
        '<p>Original replies returned: ' + str(len(replies)) + '</p>' +
        "".join(parts) + '</body></html>'
    ).encode("utf-8")


def _read_original(source: str, plan: str) -> tuple[dict, list[dict], dict]:
    source_pass = _passphrase("Original encrypted findings source passphrase")
    manifest, rows, _ = _read_encrypted(source, source_pass)
    del source_pass
    note_pass = _passphrase("Original encrypted HUMAN workplan passphrase")
    annotations, _ = _read_plan(plan, note_pass, manifest, rows)
    del note_pass
    return manifest, rows, annotations


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Offline PRIVATE one-owner exchange; NOT authentication, scope, repair or retest"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    prepare = sub.add_parser("prepare", help="original source + plan → one-alias encrypted brief")
    prepare.add_argument("source")
    prepare.add_argument("plan")
    prepare.add_argument("--output", required=True)
    read = sub.add_parser("read", help="recipient decrypts one-owner brief, aggregate or PRIVATE HTML")
    read.add_argument("brief")
    read.add_argument("--output", help="optional unencrypted one-owner private HTML")
    reply = sub.add_parser("reply", help="recipient interactively writes an encrypted HUMAN-only response")
    reply.add_argument("brief")
    reply.add_argument("--output", required=True)
    review = sub.add_parser("review", help="operator cross-binds original source+plan+brief+reply")
    review.add_argument("source")
    review.add_argument("plan")
    review.add_argument("brief")
    review.add_argument("reply")
    review.add_argument("--output", required=True)
    for command in (prepare, read, reply, review):
        command.add_argument("--ack-private-handling", action="store_true")
    for command in (prepare,):
        command.add_argument("--ack-recipient-verified", action="store_true")
    read.add_argument("--ack-plaintext-html", action="store_true")
    review.add_argument("--ack-plaintext-html", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_handling:
            raise ValueError("private handling acknowledgment missing")
        if args.action == "prepare":
            if not args.ack_recipient_verified:
                raise ValueError("independent HUMAN recipient verification required")
            output = _output_path(args.output, ".luo")
            manifest, rows, notes = _read_original(args.source, args.plan)
            alias = input("Exact existing HUMAN owner alias (not an authenticated identity): ").strip()
            packet = _validate_owner(_owner_packet(manifest, rows, notes, alias))
            payload = json.dumps(packet, ensure_ascii=False, sort_keys=True,
                                 separators=(",", ":")).encode("utf-8", "strict")
            password = _passphrase("New recipient brief passphrase", confirm=True)
            ciphertext = _seal(payload, password, magic=OWNER_MAGIC, max_plaintext=OWNER_LIMIT)
            _atomic_private_publish(output, ciphertext)
            print("One-alias encrypted PRIVATE owner brief created. Verify recipient/transport independently.")
            print(_recipient_summary(packet))
            print("Unsigned encrypted-brief checksum:", hashlib.sha256(ciphertext).hexdigest())
            return 0
        if args.action in ("read", "reply"):
            password = _passphrase("Owner brief passphrase")
            packet, raw = _get_owner_packet(args.brief, password)
            del password
            if args.action == "read":
                print(_recipient_summary(packet))
                if args.output:
                    if not args.ack_plaintext_html:
                        raise ValueError("explicit plaintext owner report acknowledgment required")
                    dest = _output_path(args.output, ".html")
                    _atomic_private_publish(dest, _recipient_html(packet))
                    print("Wrote UNENCRYPTED private one-owner HTML, no other owner claims included.")
            else:
                dest = _output_path(args.output, ".lur")
                human_reply = _reply(packet, raw)
                _put(str(dest), human_reply, REPLY_MAGIC, REPLY_LIMIT)
                print("Private encrypted HUMAN-only reply created. No fixed/approved verdict issued.")
            return 0
        if not args.ack_plaintext_html:
            raise ValueError("private original source HUMAN review approval missing")
        dest = _output_path(args.output, ".html")
        manifest, rows, notes = _read_original(args.source, args.plan)
        owner_pass = _passphrase("Original encrypted owner brief passphrase")
        packet, ciphertext = _get_owner_packet(args.brief, owner_pass)
        del owner_pass
        canonical = _owner_packet(manifest, rows, notes, packet["owner_alias"])
        if canonical != packet:
            raise ValueError("stale owner packet or mismatching original source+HUMAN plan")
        reply_pass = _passphrase("Encrypted HUMAN owner reply passphrase")
        reply_payload, _ = _decode(args.reply, reply_pass, REPLY_MAGIC, REPLY_LIMIT)
        del reply_pass
        replies = _validate_reply(reply_payload, packet, ciphertext)
        _atomic_private_publish(dest, _review_html(packet, replies))
        print("Created PRIVATE source-bound HUMAN reply review. Original source and workplan unchanged.")
        return 0
    except (ValueError, OSError, EOFError, KeyboardInterrupt, UnicodeError):
        print("PRIVATE owner exchange HOLD: invalid source, owner, recipient, reply or output.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
