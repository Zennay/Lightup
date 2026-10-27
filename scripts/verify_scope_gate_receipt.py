"""Offline fail-closed validation of pinned scope-authorization CI receipts.

Input is a locally supplied JSON document; this command does not query GitHub,
contact targets, start a runner or grant authorization.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

SHA = re.compile(r"[0-9a-f]{40}\Z")
LANES = ("hosted", "permanent_vps")


def verify_receipt(payload: object) -> tuple[bool, tuple[str, ...]]:
    errors: list[str] = []
    if type(payload) is not dict:
        return False, ("receipt must be an object",)
    sha = payload.get("commit_sha")
    if type(sha) is not str or SHA.fullmatch(sha) is None:
        errors.append("commit_sha must be an exact 40-character lowercase SHA")
    approval = payload.get("review_approved")
    if approval is not True:
        errors.append("review_approved must be exactly true")
    if type(payload.get("review_reference")) is not str or not payload["review_reference"].strip():
        errors.append("review_reference is required")
    runs = payload.get("runs")
    if type(runs) is not dict or set(runs) != set(LANES):
        errors.append("runs must contain exactly hosted and permanent_vps")
        return False, tuple(errors)
    ids: set[int] = set()
    for lane in LANES:
        run = runs[lane]
        if type(run) is not dict:
            errors.append(f"{lane} must be an object")
            continue
        if type(run.get("run_id")) is not int or run["run_id"] <= 0:
            errors.append(f"{lane} run_id must be a positive integer")
        elif run["run_id"] in ids:
            errors.append("run IDs must be distinct")
        else:
            ids.add(run["run_id"])
        if run.get("status") != "completed" or run.get("conclusion") != "success":
            errors.append(f"{lane} must have completed/success")
        if type(sha) is str and run.get("head_sha") != sha:
            errors.append(f"{lane} head_sha differs from commit_sha")
        tests = run.get("tests_passed")
        if type(tests) is not int or tests <= 0:
            errors.append(f"{lane} tests_passed must be a positive integer")
    return not errors, tuple(errors)


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print("usage: python scripts/verify_scope_gate_receipt.py receipt.json", file=sys.stderr)
        return 2
    try:
        payload = json.loads(Path(argv[1]).read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        print(f"receipt unavailable or invalid JSON: {exc}", file=sys.stderr)
        return 2
    passed, errors = verify_receipt(payload)
    if not passed:
        for error in errors:
            print(f"DENY: {error}", file=sys.stderr)
        return 1
    print("RECEIPT_OK (offline evidence shape only; NOT target authorization)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
