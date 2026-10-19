"""Human-reviewed encrypted owner reply notes → NEW exact-source HUMAN workplan.

No change to original SQLite findings, retest status, security grants, source
archive or original HUMAN workplan. This never asserts authentic ownership or
a completed fix: incoming states are explicit unverified text only.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys

from .private_export_encrypted import _passphrase, _seal
from .private_export_encrypted_notes import MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_owner_exchange import (
    OWNER_LIMIT, REPLY_LIMIT, OWNER_MAGIC, REPLY_MAGIC,
    _decode, _get_owner_packet, _owner_packet, _read_original, _validate_reply,
)
from .private_export_workdesk import _load_resume_bytes, MAX_PLAN


def _reviewed_note(existing: str, state: str, comment: str) -> str:
    if state == "no_update" and not comment:
        return existing
    line = "UNVERIFIED HUMAN OWNER REPLY [" + state + "]"
    if comment:
        line += ": " + comment
    result = (existing + "\n" + line) if existing else line
    if len(result) > 900:
        raise ValueError("owner reply would exceed bounded original note")
    return result


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="MANUAL source-bound reply incorporation; no authorization, fix, retest or SQLite write"
    )
    parser.add_argument("source", help="exact original encrypted findings .lue")
    parser.add_argument("workplan", help="exact original encrypted HUMAN plan .lun")
    parser.add_argument("brief", help="exact original one-owner encrypted brief .luo")
    parser.add_argument("reply", help="recipient HUMAN encrypted reply .lur")
    parser.add_argument("--output", required=True, help="NEW independent encrypted HUMAN plan .lun")
    parser.add_argument("--ack-human-reviewed-reply", action="store_true")
    parser.add_argument("--ack-source-recipient-verified", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not args.ack_human_reviewed_reply or not args.ack_source_recipient_verified:
            raise ValueError("independently confirmed HUMAN review acknowledgment missing")
        output = _output_path(args.output, ".lun")
        manifest, rows, annotations = _read_original(args.source, args.workplan)
        passphrase = _passphrase("Original single-owner encrypted brief passphrase")
        packet, ciphertext = _get_owner_packet(args.brief, passphrase)
        del passphrase
        expected = _owner_packet(manifest, rows, annotations, packet["owner_alias"])
        if packet != expected:
            raise ValueError("owner brief or original source HUMAN annotations changed")
        return_pass = _passphrase("Received encrypted HUMAN reply passphrase")
        returned, _ = _decode(args.reply, return_pass, REPLY_MAGIC, REPLY_LIMIT)
        del return_pass
        responses = _validate_reply(returned, packet, ciphertext)
        revised = {finding_id: values.copy() for finding_id, values in annotations.items()}
        changed = 0
        for response in responses:
            identity = response["finding_id"]
            current = revised[identity]
            next_note = _reviewed_note(
                current["human_note"], response["reported_human_state"],
                response["human_reply"]
            )
            if next_note != current["human_note"]:
                current["human_note"] = next_note
                changed += 1
        new_plan = {
            "kind": "lightup.private_human_workplan",
            "version": 1,
            "source_csv_sha256": manifest["source_csv_sha256"],
            "declared_client_id": manifest["declared_client_id"],
            "declared_engagement_id": manifest["declared_engagement_id"],
            "authorizes_action": False,
            "certifies_remediation": False,
            "confirms_client_identity": False,
            "records": [revised[row["finding_id"]] for row in rows],
        }
        clear = json.dumps(new_plan, sort_keys=True, ensure_ascii=False,
                           separators=(",", ":")).encode("utf-8", "strict")
        _load_resume_bytes(clear, manifest, rows)
        if not sys.stdin.isatty():
            raise ValueError("operator interactive review confirmation required")
        print("Exact-source HUMAN reply entries:", len(responses))
        print("Original assigned notes proposed to append:", changed)
        print("Original status, finding, owner, due date and grants WILL NOT CHANGE.")
        print("No source authenticity, response ownership or fixes have been verified by code.")
        decision = input("Type APPLY UNVERIFIED HUMAN NOTES after independent review: ").strip()
        if decision != "APPLY UNVERIFIED HUMAN NOTES":
            raise ValueError("HUMAN note incorporation declined")
        next_pass = _passphrase("New encrypted HUMAN workplan passphrase", confirm=True)
        encrypted = _seal(clear, next_pass, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN)
        _atomic_private_publish(output, encrypted)
        print("Created NEW private encrypted HUMAN workplan; original plan and findings unchanged.")
        print("Original-source case remains HUMAN HOLD, no security closure or retest.")
        print("Unsigned new encrypted file SHA-256:", hashlib.sha256(encrypted).hexdigest())
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt):
        print("PRIVATE HUMAN note incorporation HOLD: invalid source, recipient, claims or output.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
