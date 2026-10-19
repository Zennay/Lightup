#!/usr/bin/env python3
"""Merge two PRIVATE encrypted original-source HUMAN workspaces, never security results.

Every conflicting human record requires a new local human choice on a private
terminal. Never merges findings, consents, grants, scans or verified retests.
No plaintext intermediate file is created.
"""
from __future__ import annotations

import argparse
import importlib.util
import json
import re
import sqlite3
import sys
from pathlib import Path

PATH = Path(__file__).with_name("workspace.py")
SPEC = importlib.util.spec_from_file_location("_lightup_private_human_workspace", PATH)
if SPEC is None or SPEC.loader is None:
    raise RuntimeError("Original source-bound HUMAN workspace module unavailable.")
work = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(work)
bridge = work.bridge

MAX_CASES = 350
MAX_ATTACHMENTS = 120
MAX_REQUESTS = 200
STATUSES = {"unassigned", "planned", "in_progress", "blocked", "ready_for_retest", "deferred", "completed"}
HUMAN_STAGES = {"unreviewed", "human_review", "follow_up", "archived"}
EVIDENCE_STAGES = {"missing", "submitted", "needs_changes", "ready_for_authorized_retest"}
REQ_KINDS = {"missing_evidence", "patch_change", "deployment_record", "rollback_plan", "retest_request", "followup_question", "other"}
REQ_STAGES = {"draft", "requested_human", "submitted_unverified", "needs_changes", "closed_human"}
CASE_FIELDS = {"finding_id", "owner", "status", "due_date", "next_action", "verification_plan", "blocker", "note", "updated_utc"}
EVIDENCE_FIELDS = {"finding_id", "stage", "reference", "reviewer", "next_step", "evidence"}
EVIDENCE_REFS = {"change_reference": 240, "deployment_reference": 240, "rollback_reference": 240,
                 "retest_request_reference": 240, "review_question": 700}
ARTIFACT_FIELDS = {"finding_id", "file_name", "byte_length", "sha256", "mime", "added_utc",
                   "human_reviewer", "human_stage", "human_note"}
REQUEST_FIELDS = {"request_id", "finding_id", "request_kind", "assignee", "due_date", "instructions",
                  "linked_sha256", "human_stage", "human_response", "created_utc", "updated_utc"}
UTC = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d\.\d{3}Z$")
DATE = re.compile(r"^\d{4}-\d\d-\d\d$")
HEX64 = re.compile(r"^[0-9a-f]{64}$")
HEX32 = re.compile(r"^[0-9a-f]{32}$")


def _text(v: object, maxlen: int, *, required: bool = False) -> str:
    if type(v) is not str or len(v) > maxlen or (required and not v.strip()) or (
        "\x00" in v or any(0x202a <= ord(c) <= 0x202e or 0x2066 <= ord(c) <= 0x2069 for c in v)
    ):
        raise ValueError("PRIVATE HUMAN note text is not canonical.")
    return v


def _date(v: object, nullable: bool = False) -> None:
    if nullable and v is None:
        return
    if not (type(v) is str and DATE.fullmatch(v)):
        raise ValueError("Invalid human calendar day.")
    from datetime import date
    if date.fromisoformat(v).isoformat() != v:
        raise ValueError("Invalid human calendar day.")


def _stamp(v: object, nullable: bool = False) -> None:
    if nullable and v is None:
        return
    if not (type(v) is str and UTC.fullmatch(v)):
        raise ValueError("Invalid human timestamp.")
    from datetime import datetime
    if datetime.fromisoformat(v.replace("Z", "+00:00")).isoformat(timespec="milliseconds").replace("+00:00", "Z") != v:
        raise ValueError("Invalid human timestamp.")


def _exact(v: object, expected: set[str]) -> dict:
    if type(v) is not dict or set(v) != expected:
        raise ValueError("Invalid PRIVATE HUMAN record shape.")
    return v


def _admit_case(v: object, ids: set[str]) -> dict:
    d = _exact(v, CASE_FIELDS)
    if d["finding_id"] not in ids or type(d["finding_id"]) is not str:
        raise ValueError("Original finding identity absent.")
    if d["status"] not in STATUSES or type(d["status"]) is not str:
        raise ValueError("Invalid HUMAN Casework stage.")
    for k, limit in (("owner", 120), ("next_action", 1800), ("verification_plan", 1600),
                     ("blocker", 1200), ("note", 1600)):
        _text(d[k], limit)
    _date(d["due_date"], True)
    _stamp(d["updated_utc"], True)
    return d


def _admit_evidence(v: object, ids: set[str]) -> dict:
    d = _exact(v, EVIDENCE_FIELDS)
    if type(d["finding_id"]) is not str or d["finding_id"] not in ids or (
        type(d["stage"]) is not str or d["stage"] not in EVIDENCE_STAGES
    ):
        raise ValueError("Invalid original HUMAN evidence reference.")
    for k, n in (("reference", 240), ("reviewer", 120), ("next_step", 500)):
        _text(d[k], n)
    refs = _exact(d["evidence"], set(EVIDENCE_REFS))
    for k, n in EVIDENCE_REFS.items():
        _text(refs[k], n)
    return d


def _admit_artifact(v: object, ids: set[str]) -> dict:
    d = _exact(v, ARTIFACT_FIELDS)
    if type(d["finding_id"]) is not str or d["finding_id"] not in ids:
        raise ValueError("Unknown original finding in local fingerprint.")
    name = _text(d["file_name"], 240, required=True)
    if any(ch in name for ch in "/\\") or any(ord(c) < 32 for c in name):
        raise ValueError("Invalid local evidence file name.")
    if type(d["byte_length"]) is not int or not 0 <= d["byte_length"] <= 16 * 1024 * 1024:
        raise ValueError("Invalid local evidence byte count.")
    if not (type(d["sha256"]) is str and HEX64.fullmatch(d["sha256"])):
        raise ValueError("Invalid local evidence checksum.")
    _text(d["mime"], 120)
    _stamp(d["added_utc"])
    _text(d["human_reviewer"], 120)
    _text(d["human_note"], 1200)
    if type(d["human_stage"]) is not str or d["human_stage"] not in HUMAN_STAGES:
        raise ValueError("Invalid local HUMAN stage.")
    return d


def _admit_request(v: object, ids: set[str]) -> dict:
    d = _exact(v, REQUEST_FIELDS)
    if type(d["finding_id"]) is not str or d["finding_id"] not in ids or (
        type(d["request_id"]) is not str or not HEX32.fullmatch(d["request_id"])
    ):
        raise ValueError("Invalid HUMAN request identity.")
    if type(d["request_kind"]) is not str or d["request_kind"] not in REQ_KINDS or (
        type(d["human_stage"]) is not str or d["human_stage"] not in REQ_STAGES
    ):
        raise ValueError("Invalid HUMAN request type/stage.")
    _text(d["assignee"], 120)
    _text(d["instructions"], 1400, required=True)
    _text(d["human_response"], 1800)
    if type(d["linked_sha256"]) is not str or (
        d["linked_sha256"] and not HEX64.fullmatch(d["linked_sha256"])
    ):
        raise ValueError("Invalid HUMAN fingerprint reference.")
    if d["due_date"] != "":
        _date(d["due_date"])
    _stamp(d["created_utc"])
    _stamp(d["updated_utc"])
    return d


def _records(packet: dict, ids: set[str]) -> dict[str, object]:
    mapped = {}
    for key, validator, maxrows, idfunc, exact_source in (
        ("casework", _admit_case, MAX_CASES, lambda d: d["finding_id"], True),
        ("evidence_review", _admit_evidence, MAX_CASES, lambda d: d["finding_id"], True),
        ("attachments", _admit_artifact, MAX_ATTACHMENTS, lambda d: (d["finding_id"], d["sha256"]), False),
        ("human_requests", _admit_request, MAX_REQUESTS, lambda d: d["request_id"], False),
    ):
        value = packet[key] if key in packet else ([] if key == "human_requests" else None)
        if value is None and key in ("casework", "evidence_review"):
            mapped[key] = None
            continue
        if type(value) is not list or len(value) > maxrows or (
            exact_source and len(value) != len(ids)
        ):
            raise ValueError("Incomplete, oversized or malformed original HUMAN collection.")
        result = {}
        for record in value:
            row = validator(record, ids)
            identifier = idfunc(row)
            if identifier in result:
                raise ValueError("Repeated original HUMAN record identity.")
            result[identifier] = row
        if exact_source and set(result) != ids:
            raise ValueError("Original source HUMANS are incomplete.")
        mapped[key] = result
    return mapped


def _private_read(path: Path, vault) -> tuple[dict, bytes, dict]:
    if path.suffix.lower() != ".ltv":
        raise ValueError("Encrypted PRIVATE HUMAN .ltv required.")
    ciphertext = vault._private_input(path.expanduser().absolute(), vault.MAX_VAULT)
    password = vault._password("Existing PRIVATE HUMAN collaboration passphrase: ", fresh=False)
    raw, mime, _ = vault._open(ciphertext, password)
    if mime != "application/json":
        raise ValueError("Invalid encrypted HUMAN source content.")
    manifest, source, human = work._admit_workspace(raw)
    packet = work._packet(human, source_digest=work._native_digest(source)[0],
                          count=manifest["original_finding_count"],
                          client=manifest["client_reference"], engagement=manifest["engagement_reference"])
    return manifest, source, packet


def _ordered(value: object) -> str:
    return json.dumps(value, ensure_ascii=True, sort_keys=True, separators=(",", ":"))


def _merge_preflight(a: dict, b: dict, ids: set[str]) -> tuple[dict, list]:
    left = _records(a, ids)
    right = _records(b, ids)
    merged = {}
    conflicts = []
    for collection in ("casework", "evidence_review", "attachments", "human_requests"):
        x, y = left[collection], right[collection]
        if x is None or y is None:
            merged[collection] = x if y is None else y
            continue
        result = {}
        for identifier in list(dict.fromkeys((*x, *y))):
            v, w = x.get(identifier), y.get(identifier)
            if v is None:
                result[identifier] = w
            elif w is None or v == w:
                result[identifier] = v
            else:
                # A changed original HUMAN note is never silently superseded.
                conflicts.append((collection, identifier, v, w))
        merged[collection] = result
    total_files = len(merged["attachments"]) + sum(k == "attachments" for k, *_ in conflicts)
    total_requests = len(merged["human_requests"]) + sum(k == "human_requests" for k, *_ in conflicts)
    if total_files > MAX_ATTACHMENTS or total_requests > MAX_REQUESTS:
        raise ValueError("Merged HUMAN collections exceed original offline application limits.")
    return merged, conflicts


def _resolve(collection: str, identifier: object, left: dict, right: dict) -> dict:
    """Preserve distinct human changes field by field; never guess a conflict."""
    if left.get("finding_id") != right.get("finding_id"):
        raise ValueError("Same HUMAN record key has conflicting ORIGINAL finding membership.")
    print("\nLOCAL PRIVATE HUMAN CONFLICT | " + collection + " | original record " + repr(identifier))
    combined = json.loads(json.dumps(left, ensure_ascii=False))
    for field in sorted(left):
        if field in ("finding_id", "request_id", "sha256") or left[field] == right[field]:
            continue
        if field == "evidence" and collection == "evidence_review":
            changes = [(sub, left[field][sub], right[field][sub]) for sub in sorted(left[field])
                       if left[field][sub] != right[field][sub]]
        else:
            changes = [(None, left[field], right[field])]
        for sub, a, b in changes:
            label = field + ("." + sub if sub is not None else "")
            print("Human field:", label)
            print("LEFT: ", _ordered(a))
            print("RIGHT:", _ordered(b))
            choice = input("Keep [L]eft / [R]ight / [H]OLD (default): ").strip().upper()
            if choice in ("", "H"):
                raise ValueError("Unresolved HUMAN conflict; no merged artifact created.")
            if choice not in ("L", "R"):
                raise ValueError("Unknown HUMAN decision; no merged artifact created.")
            selected = a if choice == "L" else b
            if sub is None:
                combined[field] = selected
            else:
                combined[field][sub] = selected
    return combined


def _assemble(a: dict, merged: dict, ids: list[str]) -> dict:
    answer = dict(a)
    answer["schema_version"] = 2
    answer["warning"] = ("PRIVATE HUMAN-only collaboration merge after current authentic original read. "
                         "Individual conflict decisions chosen locally by a human. Source labels and "
                         "progress statuses are unverified. No grant, client consent, scan, verified "
                         "finding, fix, retest or release has occurred.")
    for collection in ("casework", "evidence_review", "attachments", "human_requests"):
        records = merged[collection]
        if records is None:
            answer[collection] = None
        elif collection in ("casework", "evidence_review"):
            answer[collection] = [records[fid] for fid in ids]
        else:
            answer[collection] = list(records.values())
    return answer


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    p = ap.add_subparsers(dest="mode", required=True)
    for name in ("preview", "merge"):
        cmd = p.add_parser(name)
        cmd.add_argument("--left", type=Path, required=True)
        cmd.add_argument("--right", type=Path, required=True)
        for flag in ("db", "email", "client-id", "engagement-id"):
            cmd.add_argument("--" + flag, required=True)
        if name == "merge":
            cmd.add_argument("--output", type=Path, required=True)
            cmd.add_argument("--ack-private-human-review", action="store_true", required=True)
    args = ap.parse_args(argv)
    try:
        if not sys.stdin.isatty() or not sys.stdout.isatty():
            raise ValueError("Private interactive TTY required for encrypted HUMAN collaboration.")
        if args.left.expanduser().absolute() == args.right.expanduser().absolute():
            raise ValueError("Two distinct independent private HUMAN sources required.")
        if args.mode == "merge" and (args.output.suffix.lower() != ".ltv" or
            args.output.expanduser().absolute() in (
                args.left.expanduser().absolute(), args.right.expanduser().absolute()
            )):
            raise ValueError("Merged PRIVATE output must be a NEW distinct .ltv.")
        # Real current account, client and engagement read; no synthetic grants/consent.
        current_csv = bridge.original._authorized_summary(
            db=args.db, email=args.email,
            client_id=args.client_id, engagement_id=args.engagement_id)
        current_sha, current_count = bridge.original._strict_summary(current_csv)
        vault = bridge.original._vault()
        lman, source, left = _private_read(args.left, vault)
        rman, right_source, right = _private_read(args.right, vault)
        for manifest in (lman, rman):
            if (manifest["original_csv_sha256"] != current_sha or
                manifest["original_finding_count"] != current_count or
                manifest["client_reference"] != args.client_id or
                manifest["engagement_reference"] != args.engagement_id):
                raise ValueError("Source or current original authenticated engagement mismatch: HOLD.")
        if source != right_source or source != current_csv.encode("utf-8", "strict"):
            raise ValueError("HUMAN workspace source bytes differ; use original revision carry first.")
        source_rows = list(__import__("csv").DictReader(__import__("io").StringIO(current_csv)))
        ids = [row["finding_id"] for row in source_rows]
        if len(set(ids)) != len(ids) or len(ids) != current_count:
            raise ValueError("Invalid current original source identity.")
        merged, conflicts = _merge_preflight(left, right, set(ids))
        print("LightUp original authenticated PRIVATE HUMAN collaboration preview")
        print("Original source findings:", current_count)
        for collection in ("casework", "evidence_review", "attachments", "human_requests"):
            size = merged[collection]
            print(collection + " safely mapped records:", "not attached" if size is None else len(size))
            print(collection + " disputed HUMAN records:", sum(x[0] == collection for x in conflicts))
        print("Original LEFT and RIGHT encrypted source files remain unchanged.")
        print("No original security finding is verified, no remediation/retest inferred.")
        if args.mode == "preview":
            print("No new file created; use merge with explicit private TTY choices.")
            return 0
        if not args.ack_private_human_review:
            raise ValueError("Explicit independent HUMAN merge approval required.")
        for collection, identifier, v, w in conflicts:
            merged[collection][identifier] = _resolve(collection, identifier, v, w)
        answer = _assemble(left, merged, ids)
        # Re-admit the entire composed HUMAN schema before requesting a new password;
        # selection cannot silently create a dangling request or duplicate finding.
        _records(answer, set(ids))
        human = json.dumps(answer, ensure_ascii=False, separators=(",", ":")).encode("utf-8", "strict")
        # Re-admit with original cross-source packet envelope; recipient's browser
        # will STILL require original unmodified separate preview and Apply.
        raw = work._make_workspace(source, human, args.client_id, args.engagement_id)
        work._admit_workspace(raw)
        password = vault._password("NEW merged PRIVATE HUMAN passphrase: ", fresh=True)
        vault._exclusive_output(args.output.expanduser().absolute(),
                                vault._seal(vault._inner(raw, "application/json"), password))
        print("New owner-only encrypted HUMAN collaboration .ltv created. Source files preserved.")
        print("Open via workspace.py open-current. Original Ledger preview and manual Apply remain mandatory.")
        return 0
    except Exception:
        print("HOLD: no private HUMAN merge output. Review account, source identity and conflicts locally.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
