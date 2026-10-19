"""Explicit per-finding PRIVATE HUMAN revision choices; no automated transfer.

Prepare an unencrypted, source-byte-bound human selection sheet; apply it only
against the identical original admitted exports. Every choice begins FALSE.
The encrypted output is a new original-compatible .lun HUMAN draft, not
authorization, remediation, evidence attestation or client authentication.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import stat
import sys

from .private_export_encrypted import _passphrase, _seal
from .private_export_encrypted_notes import MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _no_duplicate_keys, _output_path
from .private_export_workdesk import MAX_PLAN, _load_resume_bytes
from .private_export_human_revision_source import _read_with_binding, _require_same_originals
from .private_export_human_revision import (
    _COLUMNS, _DEFAULT, _read_inputs, _review_revision,
)

KIND = "lightup.private_human_revision_choices"
MAX_CHOICES = 256 * 1024
AUTHORITY = ("authorizes_action", "certifies_remediation", "confirms_client_identity")
CHOICE_FIELDS = {
    "finding_id", "title", "severity", "record_sha256",
    "source_change", "copy_owner_and_note", "copy_stage_and_due",
}
DOCUMENT_FIELDS = {
    "kind", "version", "earlier_source_csv_sha256", "later_source_csv_sha256",
    "earlier_generated_utc", "later_generated_utc",
    "declared_client_id", "declared_engagement_id", "decisions",
    *AUTHORITY,
}


def _digest(row: dict[str, str]) -> str:
    """Unambiguous ordered five-column original source row digest (unsigned)."""
    values = [row[key] for key in _COLUMNS]
    return hashlib.sha256(json.dumps(
        values, ensure_ascii=False, separators=(",", ":"), allow_nan=False
    ).encode("utf-8", "strict")).hexdigest()


def _classify(before: list[dict[str, str]], after: list[dict[str, str]]) -> dict[str, str]:
    original = {row["finding_id"]: row for row in before}
    kinds = {}
    for row in after:
        old = original.get(row["finding_id"])
        if old is None:
            label = "new"
        elif all(old[col] == row[col] for col in _COLUMNS):
            label = "five_column_identical"
        else:
            label = "changed"
        kinds[row["finding_id"]] = label
    return kinds


def _make_choices(old_meta: dict, old_rows: list[dict[str, str]],
                  notes: dict, new_meta: dict, new_rows: list[dict[str, str]]) -> dict:
    # The shared original-source date/client/complete-membership admission also
    # runs before constructing any private file. No independent weaker parser.
    _review_revision(old_meta, old_rows, notes, new_meta, new_rows, carry_stage=False)
    classification = _classify(old_rows, new_rows)
    return {
        "kind": KIND,
        "version": 1,
        "earlier_source_csv_sha256": old_meta["source_csv_sha256"],
        "later_source_csv_sha256": new_meta["source_csv_sha256"],
        "earlier_generated_utc": old_meta["generated_utc"],
        "later_generated_utc": new_meta["generated_utc"],
        "declared_client_id": new_meta["declared_client_id"],
        "declared_engagement_id": new_meta["declared_engagement_id"],
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_client_identity": False,
        "decisions": [
            {
                "finding_id": row["finding_id"],
                "title": row["title"],
                "severity": row["severity"],
                "record_sha256": _digest(row),
                "source_change": classification[row["finding_id"]],
                "copy_owner_and_note": False,
                "copy_stage_and_due": False,
            }
            for row in new_rows
        ],
    }


def _read_private_choices(path: str) -> dict:
    """No-follow and owner-private: never admit a shared/public selection sheet."""
    if not hasattr(os, "O_NOFOLLOW"):
        raise ValueError("private no-follow HUMAN selection admission unavailable")
    flags = os.O_RDONLY | os.O_NOFOLLOW | getattr(os, "O_CLOEXEC", 0)
    fd = os.open(Path(path).expanduser(), flags)
    try:
        info = os.fstat(fd)
        if (not stat.S_ISREG(info.st_mode) or info.st_size > MAX_CHOICES
                or info.st_mode & 0o077):
            raise ValueError("private HUMAN selection must be a bounded owner-only regular file")
        with os.fdopen(fd, "rb", closefd=False) as stream:
            data = stream.read(MAX_CHOICES + 1)
    finally:
        os.close(fd)
    if len(data) > MAX_CHOICES:
        raise ValueError("oversize private HUMAN selection")
    try:
        parsed = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_no_duplicate_keys)
    except (UnicodeError, json.JSONDecodeError) as exc:
        raise ValueError("invalid private HUMAN selection") from exc
    if type(parsed) is not dict:
        raise ValueError("invalid private HUMAN selection object")
    return parsed


def _apply_choices(document: dict, expected: dict, template: dict,
                   manifest: dict, rows: list[dict[str, str]]) -> tuple[bytes, dict]:
    """Whole-sheet atomic admission: changed/new rows can never carry."""
    if set(document) != DOCUMENT_FIELDS or any(
        type(document[key]) is not type(expected[key]) or
        document[key] != expected[key]
        for key in DOCUMENT_FIELDS - {"decisions"}
    ):
        raise ValueError("source revision selection header mismatch or forbidden authority")
    decisions = document["decisions"]
    reference = expected["decisions"]
    if type(decisions) is not list or len(decisions) != len(reference):
        raise ValueError("incomplete private revision choice membership")
    approved = {}
    for row, baseline in zip(decisions, reference):
        if type(row) is not dict or set(row) != CHOICE_FIELDS:
            raise ValueError("malformed HUMAN choice row")
        for key in CHOICE_FIELDS - {"copy_owner_and_note", "copy_stage_and_due"}:
            if type(row[key]) is not type(baseline[key]) or row[key] != baseline[key]:
                raise ValueError("stale private revision choice source row")
        owner = row["copy_owner_and_note"]
        stage = row["copy_stage_and_due"]
        if type(owner) is not bool or type(stage) is not bool:
            raise ValueError("non-boolean HUMAN carry decision")
        if (owner or stage) and baseline["source_change"] != "five_column_identical":
            raise ValueError("changed/new source row cannot carry HUMAN annotation")
        if stage and not owner:
            raise ValueError("HUMAN stage/date requires explicit owner/note consent")
        approved[row["finding_id"]] = (owner, stage)
    if len(approved) != len(reference):
        raise ValueError("duplicate HUMAN source choice")

    selections = template["records"]
    for row in selections:
        fid = row["finding_id"]
        owner, stage = approved[fid]
        if not owner:
            row.update(_DEFAULT)
        elif not stage:
            row["stage"] = "unassigned"
            row["due_date"] = ""
    blob = json.dumps(template, ensure_ascii=False, separators=(",", ":"),
                      allow_nan=False).encode("utf-8", "strict")
    if len(blob) > MAX_PLAN:
        raise ValueError("new encrypted plan exceeds original workdesk budget")
    # Re-admit original source and original exact-plan semantics one last time.
    _load_resume_bytes(blob, manifest, rows)
    summary = {
        "original_new_source_records": len(rows),
        "explicit_owner_note_carries": sum(owner for owner, _ in approved.values()),
        "explicit_stage_date_carries": sum(stage for _, stage in approved.values()),
        "reset_to_unassigned": sum(not stage for _, stage in approved.values()),
    }
    return blob, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="PRIVATE source-locked per-finding HUMAN revision approvals; DRAFT/HOLD"
    )
    commands = parser.add_subparsers(dest="action", required=True)
    for name in ("prepare", "apply"):
        cmd = commands.add_parser(
            name, help=("export owner-private editable FALSE-by-default choices"
                        if name == "prepare" else "apply complete private choices to new encrypted .lun")
        )
        cmd.add_argument("earlier_source")
        cmd.add_argument("earlier_plan")
        cmd.add_argument("later_source")
        cmd.add_argument("--output", required=True)
        cmd.add_argument("--ack-private-handling", action="store_true")
        cmd.add_argument("--ack-same-real-client", action="store_true")
    commands.choices["prepare"].add_argument("--ack-plaintext-original-ids", action="store_true")
    commands.choices["apply"].add_argument("--choices", required=True)
    commands.choices["apply"].add_argument("--ack-manual-human-decisions", action="store_true")
    args = parser.parse_args(argv)
    try:
        if not args.ack_private_handling or not args.ack_same_real_client:
            raise ValueError("private handling and independently verified real-client acknowledgment required")
        if args.action == "prepare":
            if not args.ack_plaintext_original_ids:
                raise ValueError("unedited original-ID plaintext export requires separate acknowledgment")
            output = _output_path(args.output, ".json")
        else:
            if not args.ack_manual_human_decisions:
                raise ValueError("manual human decision verification required")
            output = _output_path(args.output, ".lun")
        old_meta, old_rows, notes, new_meta, new_rows, binding = _read_with_binding(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        expected = _make_choices(old_meta, old_rows, notes, new_meta, new_rows)
        if args.action == "prepare":
            data = json.dumps(expected, ensure_ascii=False, indent=2,
                              allow_nan=False).encode("utf-8", "strict")
            if len(data) > MAX_CHOICES:
                raise ValueError("original-ID HUMAN selection file exceeds limit")
            _require_same_originals(args.earlier_source, args.earlier_plan, args.later_source, binding)
            _atomic_private_publish(output, data)
            print("NEW private, UNENCRYPTED, FALSE-by-default per-finding selection sheet.")
            print("Original new-source rows:", len(new_rows))
            print("Review each complete original ID/title and change marker manually.")
            print("Never set copy flags true for new/changed rows; missing never means fixed.")
        else:
            document = _read_private_choices(args.choices)
            migrated, _ = _review_revision(
                old_meta, old_rows, notes, new_meta, new_rows, carry_stage=True
            )
            blob, summary = _apply_choices(document, expected, migrated, new_meta, new_rows)
            secret = _passphrase("NEW encrypted HUMAN selection plan passphrase", confirm=True)
            ciphertext = _seal(blob, secret, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN)
            del secret
            _require_same_originals(args.earlier_source, args.earlier_plan, args.later_source, binding)
            _atomic_private_publish(output, ciphertext)
            print("NEW original-compatible AES-256-GCM source-bound HUMAN .lun published.")
            for label, count in summary.items():
                print(label + ":", count)
            print("Unsigned local ciphertext SHA-256:", hashlib.sha256(ciphertext).hexdigest())
        print("HOLD: Not proof of real client identity, consent, evidence equality, fixes or retests.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN per-finding review HOLD: source/selection/output rejected.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
