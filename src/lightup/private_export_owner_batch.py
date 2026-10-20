"""Atomically incorporate several distinct encrypted single-owner HUMAN replies.

Every encrypted brief and every received encrypted reply must bind to one
unchanged original source/plan. ALL pairs are admitted before any new encrypted
plan is published. No source finding, retest, grant, consent or source plan
changes. This is operator-supervised UNVERIFIED HUMAN follow-up only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from .private_export_encrypted import _passphrase, _seal
from .private_export_encrypted_notes import MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_owner_accept import _reviewed_note
from .private_export_owner_exchange import (
    REPLY_MAGIC, REPLY_LIMIT, _decode, _get_owner_packet, _owner_packet,
    _read_original, _validate_reply,
)
from .private_export_workdesk import _load_resume_bytes, MAX_PLAN


def _bounded_batch(
    manifest: dict,
    rows: list[dict],
    old_notes: dict[str, dict],
    pairs: list[tuple[str, str]],
) -> tuple[dict[str, dict], dict]:
    if type(pairs) is not list or not 1 <= len(pairs) <= 32:
        raise ValueError("expected one to 32 HUMAN reply pairs")
    proposed: dict[str, dict] = {}
    seen_owners: set[str] = set()
    seen_ids: set[str] = set()
    summary: dict[str, int] = {"owners": 0, "records": 0, "notes_appended": 0}
    for brief_path, reply_path in pairs:
        brief_secret = _passphrase("Original one-owner brief passphrase")
        packet, original_ciphertext = _get_owner_packet(brief_path, brief_secret)
        del brief_secret
        if packet != _owner_packet(manifest, rows, old_notes, packet["owner_alias"]):
            raise ValueError("owner brief does not match unchanged original source and plan")
        if packet["owner_alias"] in seen_owners:
            raise ValueError("duplicate owner alias in batch")
        seen_owners.add(packet["owner_alias"])
        response_secret = _passphrase("Corresponding HUMAN reply passphrase")
        response_payload, _ = _decode(reply_path, response_secret, REPLY_MAGIC, REPLY_LIMIT)
        del response_secret
        response_items = _validate_reply(response_payload, packet, original_ciphertext)
        for response in response_items:
            identifier = response["finding_id"]
            if identifier in seen_ids:
                raise ValueError("duplicated finding across owner replies")
            seen_ids.add(identifier)
            present = old_notes[identifier]
            note = _reviewed_note(
                present["human_note"], response["reported_human_state"],
                response["human_reply"],
            )
            if note != present["human_note"]:
                proposed[identifier] = note
        summary["owners"] += 1
        summary["records"] += len(response_items)
    summary["notes_appended"] = len(proposed)
    next_notes = {key: value.copy() for key, value in old_notes.items()}
    for identifier, note in proposed.items():
        next_notes[identifier]["human_note"] = note
    return next_notes, summary


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Manual encrypted multiple-owner HUMAN follow-up; no fixes, auth or retest"
    )
    parser.add_argument("original_source", help="exact encrypted findings source .lue")
    parser.add_argument("original_plan", help="exact encrypted HUMAN plan .lun")
    parser.add_argument(
        "--pair", nargs=2, action="append", metavar=("BRIEF_LUO", "REPLY_LUR"),
        required=True, help="repeat once per independently reviewed real owner"
    )
    parser.add_argument("--output", required=True, help="NEW encrypted HUMAN plan .lun")
    parser.add_argument("--ack-human-reviewed-all", action="store_true")
    parser.add_argument("--ack-independent-owner-identities", action="store_true")
    args = parser.parse_args(argv)
    try:
        if (not args.ack_human_reviewed_all or
                not args.ack_independent_owner_identities):
            raise ValueError("independent HUMAN identity/claim review is required")
        if len(args.pair) > 32:
            raise ValueError("too many owner replies")
        output = _output_path(args.output, ".lun")
        manifest, rows, notes = _read_original(args.original_source, args.original_plan)
        next_notes, summary = _bounded_batch(
            manifest, rows, notes, [(brief, reply) for brief, reply in args.pair]
        )
        plan = {
            "kind": "lightup.private_human_workplan",
            "version": 1,
            "source_csv_sha256": manifest["source_csv_sha256"],
            "declared_client_id": manifest["declared_client_id"],
            "declared_engagement_id": manifest["declared_engagement_id"],
            "authorizes_action": False,
            "certifies_remediation": False,
            "confirms_client_identity": False,
            "records": [next_notes[row["finding_id"]] for row in rows],
        }
        contents = json.dumps(
            plan, sort_keys=True, ensure_ascii=False, separators=(",", ":")
        ).encode("utf-8", "strict")
        _load_resume_bytes(contents, manifest, rows)
        if not sys.stdin.isatty():
            raise ValueError("interactive HUMAN operator confirmation required")
        print("Distinct human alias replies admitted:", summary["owners"])
        print("Original findings covered by replies:", summary["records"])
        print("Private UNVERIFIED human notes proposed:", summary["notes_appended"])
        print("No source, owner, due-date, original human stage, finding, retest, grant,")
        print("consent or actual issue resolution will be changed by this operation.")
        if input("Type APPLY BATCH UNVERIFIED HUMAN NOTES: ").strip() != (
            "APPLY BATCH UNVERIFIED HUMAN NOTES"
        ):
            raise ValueError("operator did not approve batch incorporation")
        new_secret = _passphrase("New HUMAN workplan encryption passphrase", confirm=True)
        cipher = _seal(contents, new_secret, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN)
        _atomic_private_publish(output, cipher)
        print("Created new encrypted original-source HUMAN plan; originals unchanged.")
        print("Unsigned new encrypted plan SHA-256:", hashlib.sha256(cipher).hexdigest())
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("BATCH HUMAN HOLD: invalid original source, owner/reply binding, batch or destination.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
