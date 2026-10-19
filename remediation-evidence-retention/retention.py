#!/usr/bin/env python3
"""Original-source-bound PRIVATE evidence retention review; no automatic deletion.

This additive companion consumes actual original HUMAN material receipts from
remediation-evidence-materials. It creates a NEW encrypted HUMAN review plan
and can reopen it only alongside current authorized source and unchanged
private original file bytes. It never executes, uploads or deletes evidence.
"""
from __future__ import annotations

import argparse
from datetime import date, timedelta
import hashlib
from html import escape
import json
import os
from pathlib import Path
import stat
import sys
import unicodedata

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "remediation-evidence-materials"))
import transfer

KIND = "lightup.private_evidence_retention_review"
DISPOSITION = "HUMAN_REVIEW_ONLY_NOT_DELETION_AUTHORITY"
MAX_PLAN = 64 * 1024
MAX_RECEIPT = 64 * 1024
MAX_NOTE = 400
MAX_HORIZON = 3660
DECISIONS = ("retain_pending_review", "legal_hold", "review_for_deletion")
WARNING = ("PRIVATE human review dates are not deletion authorizations, legal "
           "retention policy, proof of custody, verified security findings, "
           "consent, grants, remediation, retests or evidence of actual erasure.")
RECEIPT_FIELDS = {"kind", "schema_version", "disposition", "source_sha256",
                  "files", "warning", *transfer.human.FLAGS}
ENTRY_FIELDS = {"stored_as", "finding_id", "sha256", "byte_length",
                "decision", "review_on", "note"}
PLAN_FIELDS = {"kind", "schema_version", "disposition", "source_sha256",
               "receipt_sha256", "items", "warning", *transfer.human.FLAGS}


def _hold_if_not_private_directory(path: Path) -> Path:
    directory = path.expanduser().absolute()
    # A final is_symlink() check alone does not catch redirected ancestor
    # directories. PRIVATE material/output directories must use real literal
    # paths throughout; do not silently follow a symlinked parent.
    try:
        resolved = directory.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ValueError("Original PRIVATE directory path unavailable.") from exc
    if resolved != directory or directory.is_symlink():
        raise ValueError("PRIVATE directory or one of its ancestors is symlinked.")
    st = directory.stat()
    if (not stat.S_ISDIR(st.st_mode) or st.st_uid != os.getuid()
            or st.st_mode & 0o077):
        raise ValueError("A real owner-private 0700 material directory is required.")
    return directory


def _current(args, vault):
    original, packet, indexed, old_key_hash = transfer.current_human(
        args, vault, keep_passphrase_fingerprint=True)
    return packet, indexed, old_key_hash


def _read_material(directory: Path, packet: dict, indexed: dict, vault):
    """Verify the ENTIRE native receipt and ALL real local bytes before disclosure."""
    directory = _hold_if_not_private_directory(directory)
    raw = vault._private_input(directory / "PRIVATE-receipt.json", MAX_RECEIPT)
    body = transfer.human._json(raw, MAX_RECEIPT)
    if (set(body) != RECEIPT_FIELDS or transfer.canonical(body) != raw
            or body["kind"] != "lightup.private_local_material_receipt"
            or type(body["schema_version"]) is not int or body["schema_version"] != 1
            or body["disposition"] != "PRIVATE_HUMAN_UNVERIFIED_ONLY"
            or body["source_sha256"] != packet["source_sha256"]
            or body["warning"] != transfer.WARNING
            or any(body[k] is not False for k in transfer.human.FLAGS)):
        raise ValueError("Changed, stale or noncanonical original PRIVATE receipt.")
    files = body["files"]
    if type(files) is not list or not 1 <= len(files) <= transfer.MAX_FILES:
        raise ValueError("Native material receipt member count changed.")
    allowed = {"PRIVATE-receipt.json"}
    parsed = []
    seen = set()
    for ordinal, entry in enumerate(files, 1):
        if type(entry) is not dict or set(entry) != {
            "stored_as", "finding_id", "original_file_name", "sha256", "byte_length"
        }:
            raise ValueError("Original native receipt entry shape changed.")
        name = f"material-{ordinal:02d}.bin"
        if (type(entry["stored_as"]) is not str
                or type(entry["finding_id"]) is not str
                or type(entry["original_file_name"]) is not str
                or type(entry["sha256"]) is not str
                or type(entry["byte_length"]) is not int
                or entry["byte_length"] <= 0):
            raise ValueError("Exact native material receipt identity and byte types required.")
        if entry["stored_as"] != name:
            raise ValueError("Material filename is not the exact native neutral name.")
        key = (entry["finding_id"], entry["sha256"])
        source = indexed.get(key)
        if key in seen or source is None or any(
            entry[field] != source[field] for field in (
                "finding_id", "original_file_name", "sha256", "byte_length")
            if field != "original_file_name"
        ):
            raise ValueError("Receipt member no longer matches original HUMAN index.")
        if entry["original_file_name"] != source["file_name"]:
            raise ValueError("Original indexed filename changed.")
        seen.add(key)
        expected = source["byte_length"]
        if type(expected) is not int or not 0 < expected <= transfer.MAX_MATERIAL:
            raise ValueError("Original material size outside private transfer bounds.")
        payload = vault._private_input(directory / name, transfer.MAX_MATERIAL)
        if len(payload) != expected or transfer.digest(payload) != entry["sha256"]:
            raise ValueError("Actual local original evidence bytes differ.")
        parsed.append({"stored_as": name, "finding_id": entry["finding_id"],
                       "sha256": entry["sha256"], "byte_length": expected})
        allowed.add(name)
    if set(os.listdir(directory)) != allowed:
        raise ValueError("Unexpected/missing content in original extracted folder.")
    return parsed, transfer.digest(raw)


def _review_day(value: str) -> str:
    if type(value) is not str or len(value) != 10:
        raise ValueError("Review day must be a literal ISO yyyy-mm-dd date.")
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("Noncanonical retention review date.")
    today = date.today()
    if parsed < today or parsed > today + timedelta(days=MAX_HORIZON):
        raise ValueError("Review date must be today through ten years from today.")
    return value


def _safe_human_note(value: object) -> str:
    if (type(value) is not str or len(value) > MAX_NOTE
            or any(unicodedata.category(char).startswith("C")
                   or unicodedata.category(char) in ("Zl", "Zp")
                   for char in value)):
        raise ValueError("PRIVATE HUMAN notes must not contain controls, invisible format or bidi characters.")
    return value


def _new_decisions(files: list[dict], previous: list[dict] | None = None) -> list[dict]:
    selection = []
    print("PRIVATE EVIDENCE RETENTION · HUMAN REVIEW; no file deletion")
    print("Original source-matched private material members:", len(files))
    for number, row in enumerate(files):
        old = previous[number] if previous is not None else None
        print("Neutral local file:", row["stored_as"], "· bytes:", row["byte_length"])
        if old is not None:
            print("Current HUMAN-only decision:", old["decision"],
                  "· next review:", old["review_on"])
        decision = input("retain_pending_review / legal_hold / review_for_deletion"
                         + (" (Enter keeps previous): " if old else ": ")).strip()
        if old is not None and not decision:
            decision = old["decision"]
        if decision not in DECISIONS:
            raise ValueError("A known explicit HUMAN review decision is required.")
        if (old is not None and old["decision"] == "legal_hold"
                and decision != "legal_hold"):
            if input('Type "RECORD HUMAN REVIEW ONLY" to change this unverified HUMAN legal-hold label: ') != "RECORD HUMAN REVIEW ONLY":
                raise ValueError("Human did not deliberately acknowledge legal-hold review.")
        raw_day = input("NEXT HUMAN REVIEW ON (yyyy-mm-dd)"
                        + (" (Enter keeps previous if not past): " if old else ": ")).strip()
        day = _review_day(raw_day or (old["review_on"] if old else ""))
        note = input("Optional private HUMAN reason (<=400 characters)"
                     + (" (Enter keeps, <clear> removes): " if old else ": ")).strip()
        if old is not None and not note:
            note = old["note"]
        elif old is not None and note == "<clear>":
            note = ""
        note = _safe_human_note(note)
        selection.append({**row, "decision": decision, "review_on": day, "note": note})
    return selection


def _seal_review(args, vault, packet, indexed, old_hash: str,
                 previous: list[dict] | None = None,
                 previous_key_hash: str | None = None) -> None:
    files, receipt_sha = _read_material(args.directory, packet, indexed, vault)
    items = _new_decisions(files, previous)
    body = {"kind": KIND, "schema_version": 1, "disposition": DISPOSITION,
            "source_sha256": packet["source_sha256"], "receipt_sha256": receipt_sha,
            "items": items, "warning": WARNING,
            **{flag: False for flag in transfer.human.FLAGS}}
    plain = transfer.canonical(body)
    if len(plain) > MAX_PLAN:
        raise ValueError("Private review plan exceeded byte limit.")
    password = vault._password("NEW separate PRIVATE retention-plan passphrase: ", fresh=True)
    if transfer.digest(password) in (old_hash, previous_key_hash):
        raise ValueError("New HUMAN plan passphrase must differ from original/previous vault.")
    output = args.output.expanduser().absolute()
    existing = {args.human.expanduser().absolute()}
    if args.action == "renew":
        existing.add(args.plan.expanduser().absolute())
    if output.suffix.lower() != ".ltv" or output in existing:
        raise ValueError("A distinct new encrypted .ltv is required.")
    vault._exclusive_output(output, vault._seal(vault._inner(plain, "application/json"), password))
    print("New original-source-bound encrypted 0600 HUMAN retention review created.")
    print("Material:", len(items), "· no files changed, deleted, uploaded or approved.")


def _admit_plan(raw: bytes, files: list[dict], receipt_sha: str, packet: dict) -> list[dict]:
    body = transfer.human._json(raw, MAX_PLAN)
    if (set(body) != PLAN_FIELDS or transfer.canonical(body) != raw
            or body["kind"] != KIND or type(body["schema_version"]) is not int
            or body["schema_version"] != 1 or body["disposition"] != DISPOSITION
            or body["warning"] != WARNING
            or body["source_sha256"] != packet["source_sha256"]
            or body["receipt_sha256"] != receipt_sha
            or any(body[flag] is not False for flag in transfer.human.FLAGS)):
        raise ValueError("Private HUMAN review source/receipt continuity HOLD.")
    items = body["items"]
    if type(items) is not list or len(items) != len(files):
        raise ValueError("Incomplete HUMAN retention plan.")
    for item, source in zip(items, files):
        if (type(item) is not dict or set(item) != ENTRY_FIELDS
                or any(item[k] != source[k] for k in source)
                or item["decision"] not in DECISIONS or type(item["decision"]) is not str
                or _safe_human_note(item["note"]) != item["note"]):
            raise ValueError("HUMAN plan member changed.")
        # Old plans are allowed to become due; never treat age as automatic deletion.
        if type(item["review_on"]) is not str or len(item["review_on"]) != 10:
            raise ValueError("Invalid stored HUMAN review date.")
        d = date.fromisoformat(item["review_on"])
        if d.isoformat() != item["review_on"]:
            raise ValueError("Noncanonical stored review day.")
    return items


def _render_private(items: list[dict], source_digest: str) -> bytes:
    today = date.today().isoformat()
    parts = []
    due = 0
    for item in items:
        is_due = item["review_on"] <= today
        due += int(is_due)
        parts.append("<tr><td>" + escape(item["stored_as"]) +
            "</td><td>" + escape(item["finding_id"]) +
            "</td><td>" + escape(item["sha256"][:16]) + "…</td><td>" +
            escape(item["decision"].replace("_", " ")) + "</td><td>" +
            escape(item["review_on"]) + "</td><td>" +
            ("HUMAN REVIEW DUE" if is_due else "Scheduled") +
            "</td><td>" + escape(item["note"]) + "</td></tr>")
    html = """<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; connect-src 'none'; img-src 'none'; style-src 'unsafe-inline'; script-src 'none'; base-uri 'none'; form-action 'none'">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>PRIVATE Evidence Retention Review · HUMAN ONLY</title>
<style>body{font:16px system-ui,sans-serif;max-width:1100px;margin:2rem auto;padding:1rem;line-height:1.5;background:#f7f7f7;color:#222}table{width:100%;border-collapse:collapse;background:white}td,th{border:1px solid #aaa;text-align:left;padding:.6rem;vertical-align:top;overflow-wrap:anywhere}th{background:#eee}.warn{border-left:5px solid #444;padding:1rem;background:white}small{display:block;margin:1rem 0}</style>
</head><body><h1>PRIVATE HUMAN evidence retention review</h1>
<div class="warn"><strong>No automatic deletion or release.</strong> This report is a local human calendar, not legal retention authority, authenticated client permission, proof of evidence or verified remediation. Source drift and changed bytes must HOLD.</div>
<p>Review date: """ + escape(today) + """ · Private files: """ + str(len(items)) + """ · Human reviews due: """ + str(due) + """</p>
<small>Current authenticated original source SHA-256: """ + escape(source_digest) + """</small>
<table><caption>Source-bound locally reviewed evidence bytes — private</caption>
<thead><tr><th>Neutral file</th><th>Original finding (unverified)</th><th>SHA prefix</th><th>Human status</th><th>Next review</th><th>Attention</th><th>Private note</th></tr></thead><tbody>""" + "".join(parts) + """</tbody></table><p>""" + escape(WARNING) + """</p></body></html>"""
    return html.encode("utf-8", "strict")


def _load_current_plan(args, vault, packet, indexed) -> tuple[list[dict], str]:
    files, receipt_sha = _read_material(args.directory, packet, indexed, vault)
    if args.plan.suffix.lower() != ".ltv":
        raise ValueError("A native encrypted plan .ltv is required.")
    encrypted = vault._private_input(args.plan.expanduser().absolute(), vault.MAX_VAULT)
    passphrase = vault._password("Existing PRIVATE retention-plan passphrase: ", fresh=False)
    plain, mime, _ = vault._open(encrypted, passphrase)
    if mime != "application/json":
        raise ValueError("Retention plan MIME changed.")
    return _admit_plan(plain, files, receipt_sha, packet), transfer.digest(passphrase)


def _review(args, vault, packet, indexed) -> None:
    items, _ = _load_current_plan(args, vault, packet, indexed)
    due = sum(item["review_on"] <= date.today().isoformat() for item in items)
    if args.action == "inspect":
        print("Current ORIGINAL source and all local material bytes match encrypted HUMAN review.")
        print("Indexed files:", len(items), "· due for HUMAN review:", due)
        print("No deletion, permission, grant, remediation or retest inferred.")
        return
    output = args.output.expanduser().absolute()
    if output.suffix.lower() != ".html" or output in (
        args.human.expanduser().absolute(), args.plan.expanduser().absolute()):
        raise ValueError("New distinct private HTML path required.")
    html = _render_private(items, packet["source_sha256"])
    if len(html) > 100_000:
        raise ValueError("Private HTML exceeds output cap.")
    vault._exclusive_output(output, html)
    print("New scriptless owner-only 0600 private HUMAN retention review HTML created.")
    print("Indexed:", len(items), "· due for HUMAN review:", due, "· no deletion.")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    for action in ("stage", "renew", "inspect", "open-current"):
        p = sub.add_parser(action)
        for name in ("db", "email", "client-id", "engagement-id"):
            p.add_argument("--" + name, required=True)
        p.add_argument("--human", required=True, type=Path,
                       help="Original source-matched encrypted HUMAN Evidence Ledger .ltv")
        p.add_argument("--directory", required=True, type=Path,
                       help="Original existing 0700 actual-material extraction folder")
        if action != "stage":
            p.add_argument("--plan", required=True, type=Path,
                           help="Existing PRIVATE HUMAN retention-review encrypted .ltv")
        if action != "inspect":
            p.add_argument("--output", required=True, type=Path,
                           help="NEW owner-private encrypted .ltv or offline .html")
        p.add_argument("--ack-private-material", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_material or not sys.stdin.isatty():
            raise ValueError("Explicit approval and an interactive private terminal required.")
        vault = transfer.ORIGINAL._vault()
        packet, indexed, previous_password_hash = _current(args, vault)
        if args.action == "stage":
            _seal_review(args, vault, packet, indexed, previous_password_hash)
        elif args.action == "renew":
            previous, old_plan_hash = _load_current_plan(args, vault, packet, indexed)
            print("Current encrypted private HUMAN review loaded; original unchanged.")
            _seal_review(args, vault, packet, indexed, previous_password_hash,
                         previous=previous, previous_key_hash=old_plan_hash)
        else:
            _review(args, vault, packet, indexed)
        return 0
    except Exception:
        print("HUMAN HOLD: Current authenticated source, original receipt, local "
              "file bytes, privacy bounds or encrypted review not admitted. "
              "No complete retention artifact published.", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
