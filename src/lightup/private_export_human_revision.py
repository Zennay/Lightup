"""Original encrypted source -> new encrypted HUMAN plan, revision-safe and offline.

This optional bridge uses the original guarded .lue/.lun readers unchanged.
No tenant reauthentication, consent, fix assertion, retest, active network or
persistent record mutation is implied by decrypting a historical export.
Only an independently identified human can approve this local copy operation.
"""
from __future__ import annotations

import argparse
from collections import Counter
from html import escape
import hashlib
import json
import sys
from datetime import datetime, timezone

from .private_export_encrypted import _passphrase, _read_encrypted, _seal
from .private_export_encrypted_notes import _read_plan, MAGIC_PLAN
from .private_export_handoff import _atomic_private_publish, _output_path
from .private_export_workdesk import KIND, MAX_PLAN, _load_resume_bytes
from .private_export_human_revision_source import _read_with_binding, _require_same_originals

_FALSE_FLAGS = (
    "authorizes_action", "certifies_remediation", "confirms_client_identity"
)
_DEFAULT = {
    "stage": "unassigned", "owner_alias": "", "due_date": "", "human_note": ""
}
_COLUMNS = ("finding_id", "title", "severity", "retest_status", "remediation")


def _review_revision(old_manifest: dict, old_rows: list[dict[str, str]],
                     old_annotations: dict, new_manifest: dict,
                     new_rows: list[dict[str, str]], *, carry_stage: bool) -> tuple[dict, dict]:
    """Compare complete canonical original five-column rows, never just IDs.

    Changes in evidence outside the five-column export remain UNKNOWN.
    Default migration deliberately resets stage and due even for identical
    rows; opt-in stage/schedule transfer is a HUMAN planning convenience only.
    """
    if any(old_manifest[field] != new_manifest[field] for field in (
        "declared_client_id", "declared_engagement_id"
    )):
        raise ValueError("declared client/engagement mismatch; no revision carry")
    # Prevent accidentally applying later planning to a source that itself
    # declares it was exported earlier. Timestamp is a self-declared sanity
    # precondition, NOT evidence of chronology or authentic source ownership.
    before_at = datetime.fromisoformat(old_manifest["generated_utc"])
    after_at = datetime.fromisoformat(new_manifest["generated_utc"])
    if after_at.astimezone(timezone.utc) <= before_at.astimezone(timezone.utc):
        raise ValueError("later export does not declare a strictly newer timestamp")
    previous = {row["finding_id"]: row for row in old_rows}
    current = {row["finding_id"]: row for row in new_rows}
    if set(old_annotations) != set(previous):
        raise ValueError("original human plan membership mismatch")

    identical = {fid for fid in previous.keys() & current.keys()
                 if all(previous[fid][field] == current[fid][field]
                        for field in _COLUMNS)}
    modified = previous.keys() & current.keys() - identical
    added = current.keys() - previous.keys()
    absent = previous.keys() - current.keys()
    # Exact equality of the five exported columns is necessary but NOT proof
    # of equality of non-exported original source evidence.
    output = []
    for row in new_rows:
        fid = row["finding_id"]
        record = {"finding_id": fid, **_DEFAULT}
        if fid in identical:
            old = old_annotations[fid]
            record["owner_alias"] = old["owner_alias"]
            record["human_note"] = old["human_note"]
            if carry_stage:
                record["stage"] = old["stage"]
                record["due_date"] = old["due_date"]
        output.append(record)
    annotations = {
        "kind": KIND,
        "version": 1,
        "source_csv_sha256": new_manifest["source_csv_sha256"],
        "declared_client_id": new_manifest["declared_client_id"],
        "declared_engagement_id": new_manifest["declared_engagement_id"],
        "authorizes_action": False,
        "certifies_remediation": False,
        "confirms_client_identity": False,
        "records": output,
    }
    summary = {
        "old": len(previous), "new": len(current),
        "same_five_columns": len(identical), "modified": len(modified),
        "newly_present": len(added), "absent_not_fixed": len(absent),
        "owner_and_note_copied": len(identical),
        "stage_and_date_copied": len(identical) if carry_stage else 0,
        "reset_for_human_review": len(current) if not carry_stage else len(current) - len(identical),
        "source_reported_severity": dict(sorted(Counter(
            row["severity"] for row in new_rows).items())),
    }
    return annotations, summary


def _private_html(summary: dict) -> bytes:
    labels = (
        ("Earlier original findings", summary["old"]),
        ("Later original findings", summary["new"]),
        ("Identical five-column original rows", summary["same_five_columns"]),
        ("Changed original rows; annotations reset", summary["modified"]),
        ("Newly present original rows", summary["newly_present"]),
        ("Absent original rows; NOT verified fixed", summary["absent_not_fixed"]),
        ("HUMAN owner aliases/notes eligible to copy", summary["owner_and_note_copied"]),
        ("HUMAN stages/dates eligible to copy (only with opt-in)", summary["stage_and_date_copied"]),
        ("Rows requiring HUMAN stage/date review", summary["reset_for_human_review"]),
    )
    rows = "".join(
        "<tr><th scope='row'>" + escape(name) + "</th><td>" + str(count) +
        "</td></tr>" for name, count in labels
    )
    severity = "".join(
        "<tr><th scope='row'>" + escape(key) + "</th><td>" + str(count) +
        "</td></tr>" for key, count in summary["source_reported_severity"].items()
    )
    html = (
        "<!doctype html><html lang='en'><meta charset='utf-8'>"
        "<meta name='viewport' content='width=device-width,initial-scale=1'>"
        "<meta http-equiv='Content-Security-Policy' content=\"default-src 'none'; style-src 'unsafe-inline'; base-uri 'none'; form-action 'none'\">"
        "<title>LightUp private HUMAN revision carry review</title>"
        "<style>body{font:16px/1.55 system-ui,sans-serif;color:#15253b;background:#f2f6fc;"
        "margin:0}main{max-width:860px;margin:auto;padding:32px}table{border-collapse:collapse;"
        "width:100%;background:white}th,td{border-bottom:1px solid #ccd5e2;padding:12px;text-align:left}"
        "th{font-weight:600}td{text-align:right}aside{background:#fff0d6;border-left:5px solid #ae6613;"
        "padding:18px;margin:24px 0}h1{line-height:1.2}</style><main>"
        "<h1>PRIVATE HUMAN revision carry review</h1>"
        "<aside><strong>INCUBATE · PLAN/LAB ONLY · DRAFT/HOLD.</strong> "
        "Human coordination only. No permission, client identity, source ownership, "
        "evidence equality, verified remediation or retest follows from this report. "
        "Five exported columns omit underlying finding evidence; equality here "
        "does NOT prove evidence remained the same. Missing never means fixed. "
        "Original source names, client IDs, hashes, titles, targets, owner aliases, "
        "dates and private notes are deliberately not included. This output is "
        "UNENCRYPTED; use approved local storage and manual recipient review.</aside>"
        "<h2>Original source comparison</h2><table><tbody>" + rows + "</tbody></table>"
        "<h2>Later source-declared severity</h2><table><tbody>" + severity +
        "</tbody></table><p>All migrated entries remain unverified HUMAN proposals. "
        "No original finding, evidence, source or HUMAN plan was changed.</p></main></html>"
    )
    return html.encode("utf-8")


def _read_unbound_inputs(earlier: str, plan: str, later: str) -> tuple[dict, list, dict, dict, list]:
    source_secret = _passphrase("Earlier original encrypted source passphrase")
    first_manifest, first_rows, _ = _read_encrypted(earlier, source_secret)
    del source_secret

    plan_secret = _passphrase("Earlier encrypted HUMAN plan passphrase")
    annotations, _ = _read_plan(plan, plan_secret, first_manifest, first_rows)
    del plan_secret

    later_secret = _passphrase("Later original encrypted source passphrase")
    next_manifest, next_rows, _ = _read_encrypted(later, later_secret)
    del later_secret
    return first_manifest, first_rows, annotations, next_manifest, next_rows


def _read_inputs(earlier: str, plan: str, later: str) -> tuple[dict, list, dict, dict, list]:
    """Original reader plus exact-ciphertext owner-private before/after hold."""
    from .private_export_human_revision_source import _read_with_binding
    manifest, rows, notes, later_manifest, later_rows, _binding = _read_with_binding(
        earlier, plan, later
    )
    return manifest, rows, notes, later_manifest, later_rows


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="LightUp PRIVATE encrypted original-source HUMAN revision bridge; DRAFT/HOLD"
    )
    sub = parser.add_subparsers(dest="action", required=True)
    for action, help_text in (
        ("preview", "anonymous counts, optional private scriptless 0600 HTML"),
        ("carry", "create a NEW encrypted exact-later-source HUMAN .lun"),
    ):
        command = sub.add_parser(action, help=help_text)
        command.add_argument("earlier_source", help="original earlier encrypted .lue")
        command.add_argument("earlier_plan", help="earlier exact-source encrypted .lun")
        command.add_argument("later_source", help="newer original encrypted .lue")
        command.add_argument("--ack-private-handling", action="store_true")
        command.add_argument("--ack-same-real-client", action="store_true")
        command.add_argument("--output", help="new .lun for carry; optional PRIVATE .html for preview")
        command.add_argument("--carry-stage", action="store_true",
                             help="also copy unverified HUMAN stage/due for identical five-column rows")
        command.add_argument("--ack-human-stage-carryover", action="store_true")
    sub.choices["preview"].add_argument("--ack-plaintext-html", action="store_true")
    sub.choices["carry"].add_argument("--ack-human-carryover", action="store_true")
    args = parser.parse_args(argv)

    try:
        if not args.ack_private_handling or not args.ack_same_real_client:
            raise ValueError("separate PRIVATE and real-client human acknowledgment required")
        if args.carry_stage and not args.ack_human_stage_carryover:
            raise ValueError("explicit HUMAN stage/date revision carry approval required")
        if args.action == "preview":
            if args.output and not args.ack_plaintext_html:
                raise ValueError("unencrypted HTML recipient/privacy acknowledgment required")
            output = _output_path(args.output, ".html") if args.output else None
        else:
            if not args.ack_human_carryover or not args.output:
                raise ValueError("explicit HUMAN carry and new encrypted output required")
            output = _output_path(args.output, ".lun")

        old_meta, old_rows, previous, new_meta, new_rows, binding = _read_with_binding(
            args.earlier_source, args.earlier_plan, args.later_source
        )
        next_plan, summary = _review_revision(
            old_meta, old_rows, previous, new_meta, new_rows,
            carry_stage=args.carry_stage
        )
        # Re-admit the entire new HUMAN plan against the untouched new original
        # source BEFORE any private destination gets published.
        serialized = json.dumps(
            next_plan, ensure_ascii=False, separators=(",", ":"), allow_nan=False
        ).encode("utf-8", "strict")
        if len(serialized) > MAX_PLAN:
            raise ValueError("new HUMAN plan exceeds source-bound size budget")
        _load_resume_bytes(serialized, new_meta, new_rows)
        if args.action == "carry":
            fresh_passphrase = _passphrase("New encrypted HUMAN plan passphrase", confirm=True)
            ciphertext = _seal(
                serialized, fresh_passphrase, magic=MAGIC_PLAN, max_plaintext=MAX_PLAN
            )
            del fresh_passphrase
            _require_same_originals(args.earlier_source, args.earlier_plan, args.later_source, binding)
            _atomic_private_publish(output, ciphertext)
            print("Created NEW exact-later-source encrypted HUMAN coordination plan.")
            print("Unsigned local ciphertext SHA-256:", hashlib.sha256(ciphertext).hexdigest())
        elif output:
            _require_same_originals(args.earlier_source, args.earlier_plan, args.later_source, binding)
            _atomic_private_publish(output, _private_html(summary))
            print("Created UNENCRYPTED local PRIVATE ID-free human revision brief.")
        for key, value in summary.items():
            if key != "source_reported_severity":
                print(key + ":", value)
        print("HOLD: No unchanged evidence, real client identity, fixes, retests, consent or authority established.")
        return 0
    except (ValueError, OSError, UnicodeError, EOFError, KeyboardInterrupt) as exc:
        # Original source, decrypted field content, paths and passphrase details
        # are never echoed back into scripts/logs on failure.
        print("HUMAN revision carry HOLD: source/plan/identity/output admission failed.",
              file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
