#!/usr/bin/env python3
"""Compare two original PRIVATE Lineage workroom receipts, without invoking assessments.

Only human-selected source byte fingerprints are compared. No scope, consent,
authenticated chronology, finding, remediation or permission is inferred.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import stat
import sys
from pathlib import Path

from private_workroom import FLAGS, no_duplicate_keys, open_parent_nofollow, read_private

SCHEMA = "lightup.private_lineage_receipt.v1"
MAX_INPUT = 8_192
MAX_OUTPUT = 32_768
EXPECTED = {
    "schema", "status", *FLAGS, "catalog_sha256", "reports_sha256",
    "human_draft_sha256", "workroom_sha256", "report_count",
    "human_draft_present", "origin_verified", "operator_identity_verified",
    "client_consent_verified", "human_go",
}
HASH = re.compile(r"[0-9a-f]{64}\Z")


def hold() -> None:
    raise ValueError("HOLD: invalid or changed original PRIVATE receipt")


def digest(value: object) -> bool:
    return type(value) is str and HASH.fullmatch(value) is not None


def decode_receipt(raw: bytes) -> dict:
    try:
        data = json.loads(raw.decode("utf-8", "strict"), object_pairs_hook=no_duplicate_keys,
                          parse_constant=lambda value: hold())
    except (UnicodeError, ValueError, TypeError, RecursionError):
        hold()
    if (type(data) is not dict or set(data) != EXPECTED
            or data["schema"] != SCHEMA or data["status"] != "PRIVATE_REVIEW_ONLY"):
        hold()
    if any(data[key] is not False for key in FLAGS):
        hold()
    if any(data[key] is not False for key in (
        "origin_verified", "operator_identity_verified", "client_consent_verified", "human_go"
    )):
        hold()
    report_count = data["report_count"]
    report_hashes = data["reports_sha256"]
    if (type(report_count) is not int or not 1 <= report_count <= 8
            or type(report_hashes) is not list or len(report_hashes) != report_count
            or not all(digest(item) for item in report_hashes)):
        hold()
    if not digest(data["catalog_sha256"]) or not digest(data["workroom_sha256"]):
        hold()
    if type(data["human_draft_present"]) is not bool:
        hold()
    if data["human_draft_present"] != (data["human_draft_sha256"] is not None):
        hold()
    if data["human_draft_sha256"] is not None and not digest(data["human_draft_sha256"]):
        hold()
    expected_bytes = (json.dumps(data, sort_keys=True, separators=(",", ":")) + "\n").encode()
    if raw != expected_bytes:
        hold()
    return data


def summarize(before: dict, after: dict) -> dict:
    old = before["reports_sha256"]
    new = after["reports_sha256"]
    # Duplicated original fingerprints cannot establish a unique relocation.
    unique = len(set(old)) == len(old) and len(set(new)) == len(new)
    old_positions = {value: idx for idx, value in enumerate(old, 1)}
    new_positions = {value: idx for idx, value in enumerate(new, 1)}
    removed = [idx for idx, value in enumerate(old, 1) if value not in new_positions]
    added = [idx for idx, value in enumerate(new, 1) if value not in old_positions]
    moved = [
        {"before_slot": idx, "after_slot": new_positions[value]}
        for idx, value in enumerate(old, 1)
        if unique and value in new_positions and new_positions[value] != idx
    ]
    return {
        "schema": "lightup.private_lineage_receipt_delta.v1",
        "status": "PRIVATE_HUMAN_REVIEW_ONLY",
        **{flag: False for flag in FLAGS},
        "origin_verified": False,
        "operator_identity_verified": False,
        "client_consent_verified": False,
        "human_go": False,
        "before_slots": len(old),
        "after_slots": len(new),
        "catalog_bytes_changed": before["catalog_sha256"] != after["catalog_sha256"],
        "human_draft_bytes_changed": before["human_draft_sha256"] != after["human_draft_sha256"],
        "workroom_bytes_changed": before["workroom_sha256"] != after["workroom_sha256"],
        "report_source_slots_changed": old != new,
        "ambiguous_duplicate_source_bytes": not unique,
        "old_only_slots": removed,
        "new_only_slots": added,
        "uniquely_moved_sources": moved,
        "human_selected_order_not_proven_chronology": True,
        "missing_source_not_remediated": True,
    }


def render(data: dict) -> bytes:
    def slots(values: list[int]) -> str:
        return ", ".join(str(value) for value in values) if values else "None"

    rows = [
        ("Original Studio catalog bytes changed", data["catalog_bytes_changed"]),
        ("Original HUMAN draft bytes changed", data["human_draft_bytes_changed"]),
        ("PRIVATE workroom HTML bytes changed", data["workroom_bytes_changed"]),
        ("Original selected report slots changed", data["report_source_slots_changed"]),
        ("Duplicate original fingerprints — movement ambiguous", data["ambiguous_duplicate_source_bytes"]),
    ]
    table = "".join(
        "<tr><th scope=\"row\">" + label + "</th><td>" +
        ("YES" if value else "NO") + "</td></tr>" for label, value in rows
    )
    moved = ", ".join(
        str(item["before_slot"]) + " → " + str(item["after_slot"])
        for item in data["uniquely_moved_sources"]
    ) or "None"
    html = (
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">"
        "<meta http-equiv=\"Content-Security-Policy\" content=\""
        "default-src 'none'; base-uri 'none'; connect-src 'none'; form-action 'none'; "
        "img-src 'none'; style-src 'none'; script-src 'none'\">"
        "<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">"
        "<title>LightUp PRIVATE source receipt comparison — HOLD</title></head>"
        "<body><main><h1>PRIVATE original-source continuity desk</h1>"
        "<p><strong>HOLD · HUMAN REVIEW ONLY.</strong> Two unsigned original "
        "private receipts are compared in the operator-selected order. "
        "No scanner, original validation, chronology, authenticated source identity, "
        "remediation, client/operator consent or HUMAN GO is established.</p>"
        "<p>Before: " + str(data["before_slots"]) + " report slots; after: " +
        str(data["after_slots"]) + " report slots.</p>"
        "<table border=\"1\"><caption>Exact private-byte equality indicators</caption>"
        "<thead><tr><th scope=\"col\">Human review category</th>"
        "<th scope=\"col\">Changed?</th></tr></thead><tbody>" + table + "</tbody></table>"
        "<h2>Original report-slot reconciliation</h2>"
        "<p>Previous-only positions (not 'fixed'): " + slots(data["old_only_slots"]) + ".</p>"
        "<p>New-only positions (not new verified findings): " + slots(data["new_only_slots"]) + ".</p>"
        "<p>Uniquely fingerprinted source moved from → to: " + moved + ".</p>"
        "<p>Duplicate source digests make movement ambiguous; do not infer "
        "a unique original or chronology from matching hashes.</p>"
        "<p>Only ordinal positions and booleans appear in this PRIVATE report. "
        "It can still reveal sensitive work patterns in small sets. Keep owner-private; "
        "never distribute as anonymous clearance or a remediation certificate.</p>"
        "</main></body></html>\n"
    )
    raw = html.encode("utf-8")
    if len(raw) > MAX_OUTPUT:
        hold()
    return raw


def stable_sources(before_path: Path, after_path: Path) -> tuple[bytes, bytes, dict, dict]:
    if os.path.realpath(before_path) == os.path.realpath(after_path):
        hold()
    before_raw = read_private(before_path, MAX_INPUT)
    after_raw = read_private(after_path, MAX_INPUT)
    return before_raw, after_raw, decode_receipt(before_raw), decode_receipt(after_raw)


def main(argv: list[str]) -> int:
    cli = argparse.ArgumentParser(description="Offline PRIVATE source-receipt change desk (not an assessment)")
    cli.add_argument("--before", required=True, type=Path, help="First owner-private canonical source receipt")
    cli.add_argument("--after", required=True, type=Path, help="Second owner-private canonical source receipt")
    cli.add_argument("--output-dir", required=True, type=Path, help="Existing isolated owner-only 0700 directory")
    cli.add_argument("--verify-existing", action="store_true", help="Strict read-only exact packet reopen")
    args = cli.parse_args(argv)
    before_raw, after_raw, before, after = stable_sources(args.before, args.after)
    result = summarize(before, after)
    payloads = {
        "lightup-private-lineage-source-delta.json":
            (json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n").encode("utf-8"),
        "lightup-private-lineage-source-delta.html": render(result),
    }
    if (os.path.realpath(args.output_dir) in {
        os.path.realpath(args.before.parent), os.path.realpath(args.after.parent)
    }):
        hold()
    fd, dirname = open_parent_nofollow(args.output_dir / "workroom-placeholder")
    created: list[str] = []
    try:
        parent = os.fstat(fd)
        if (not stat.S_ISDIR(parent.st_mode) or parent.st_uid != os.getuid()
                or stat.S_IMODE(parent.st_mode) != 0o700):
            hold()
        inventory = set(os.listdir(fd))
        if args.verify_existing:
            if inventory != set(payloads):
                hold()
            for filename, expected in payloads.items():
                if read_private(args.output_dir / filename, len(expected)) != expected:
                    hold()
            print("PRIVATE SOURCE RECEIPT DELTA MATCH — REVIEW_ONLY, NOT AUTHORIZED")
            return 0
        if inventory:
            hold()
        # Reopen both exact original unsigned sources immediately before output.
        if read_private(args.before, MAX_INPUT) != before_raw or read_private(args.after, MAX_INPUT) != after_raw:
            hold()
        try:
            for filename, data in payloads.items():
                output = os.open(filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
                                 0o600, dir_fd=fd)
                created.append(filename)
                with os.fdopen(output, "wb") as file:
                    os.fchmod(file.fileno(), 0o600)
                    file.write(data)
                    file.flush()
                    os.fsync(file.fileno())
            os.fsync(fd)
        except BaseException:
            for filename in reversed(created):
                os.unlink(filename, dir_fd=fd)
            os.fsync(fd)
            raise
    finally:
        os.close(fd)
    print("PRIVATE two-file source continuity desk created; review only, not cleared.")
    print("No source identity, consent, chronology, scan or remediation inferred.")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main(sys.argv[1:]))
    except (OSError, ValueError, TypeError, OverflowError, RecursionError, UnicodeError):
        print("HOLD: invalid or changed PRIVATE originals, directory or output. No authorization.", file=sys.stderr)
        raise SystemExit(2) from None
