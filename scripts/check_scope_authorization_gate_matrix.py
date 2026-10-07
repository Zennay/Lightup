#!/usr/bin/env python3
"""Offline integrity check for the ToolExecutor authorization release-gate matrix.

This validates the review specification only. It is NOT an authorization,
executor, integration or security-test pass.
"""
from pathlib import Path
import re
import sys

MATRIX = Path(__file__).resolve().parents[1] / "docs/scope-authorization-tool-executor-release-gate-matrix.md"
EXPECTED_IDS = frozenset({
    "L1", "L2", "L3", "G1", "G2", "G3",
    "S1", "S2", "S3", "S4", "T1", "T2", "T3", "T4",
})
REQUIRED = (
    "zero handler invocations",
    "zero newly persisted evidence",
    "unchanged grant/run snapshot objects",
    "immutable runner receipt",
    "No DNS/network I/O",
    "PR #107",
    "#954",
)


def check(text: str) -> list[str]:
    errors: list[str] = []
    ids = re.findall(r"^\| ([LGST]\d+) \|", text, re.MULTILINE)
    if len(ids) != len(set(ids)):
        errors.append("Duplicate case ID")
    if set(ids) != EXPECTED_IDS:
        errors.append(
            "Case ID mismatch: missing="
            + repr(sorted(EXPECTED_IDS - set(ids)))
            + ", unexpected=" + repr(sorted(set(ids) - EXPECTED_IDS))
        )
    for phrase in REQUIRED:
        if phrase.casefold() not in text.casefold():
            errors.append(f"Missing review contract: {phrase}")
    for row in text.splitlines():
        if re.match(r"^\| [LGST]\d+ \|", row) and row.count("|") != 4:
            errors.append(f"Malformed matrix row: {row[:100]}")
    return errors


def main() -> int:
    try:
        data = MATRIX.read_text(encoding="utf-8")
    except OSError as exc:
        print(f"ERROR: cannot read gate matrix: {exc}", file=sys.stderr)
        return 2
    failures = check(data)
    if failures:
        for failure in failures:
            print(f"FAIL: {failure}", file=sys.stderr)
        return 1
    print(f"PASS: {len(EXPECTED_IDS)} documented cases; specification integrity only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
