"""Local-only evidence/remediation review intake preflight (explicit opt-in).

No network, provider, model dispatch, target interaction, remediation, retest,
database changes, or security verdict. Only bounded metadata JSON is read.
Output deliberately carries aggregate counts and static rejection codes, not
original values, target identities, evidence refs, payloads or exception text.

Usage:
    PYTHONPATH=src python scripts/check_remediation_review_intake_optin.py --input synthetic.json
"""
from __future__ import annotations

import argparse
import json
import math
from pathlib import Path
from typing import Any

from lightup.ai.remediation_input_preflight_optin import (
    prepare_remediation_review_inputs,
)

MAX_INPUT_BYTES = 1_048_576


class _LocalIntakeError(ValueError):
    """Controlled error with a non-sensitive, fixed output code."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _distinct_pairs(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for name, value in pairs:
        if name in output:
            # Do not include caller-controlled key names in stderr or JSON.
            raise _LocalIntakeError("duplicate_json_key")
        output[name] = value
    return output


def _finite_number(token: str) -> float:
    value = float(token)
    if not math.isfinite(value):
        raise _LocalIntakeError("nonfinite_json_number")
    return value


def _invalid_json_constant(_value: str) -> None:
    raise _LocalIntakeError("nonstandard_json_constant")


def inspect_local_document(source: Path) -> tuple[str, int, int]:
    """Return a sanitized status and two counts; never return caller text."""
    # Refuse symlinks and non-regular files; a local operator must explicitly
    # supply a real file. Limit reads irrespective of the metadata size check.
    if source.is_symlink() or not source.is_file():
        raise _LocalIntakeError("invalid_local_file")
    try:
        with source.open("rb") as handle:
            raw = handle.read(MAX_INPUT_BYTES + 1)
    except OSError:
        raise _LocalIntakeError("unreadable_local_file") from None

    if len(raw) > MAX_INPUT_BYTES:
        raise _LocalIntakeError("input_too_large")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        raise _LocalIntakeError("invalid_utf8") from None

    try:
        decoded = json.loads(
            text,
            object_pairs_hook=_distinct_pairs,
            parse_float=_finite_number,
            parse_constant=_invalid_json_constant,
        )
    except _LocalIntakeError:
        raise
    except (ValueError, TypeError, OverflowError, RecursionError):
        raise _LocalIntakeError("invalid_json") from None

    try:
        prepared = prepare_remediation_review_inputs(decoded)
    except (ValueError, TypeError, OverflowError, RecursionError):
        # Preserve no exception messages; even legitimate values never leak.
        raise _LocalIntakeError("invalid_review_metadata") from None

    return (
        "ready",
        len(prepared.findings),
        sum(len(finding.evidence_ids) for finding in prepared.findings),
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Validate a bounded local LightUp evidence-review JSON fixture without model calls"
    )
    parser.add_argument("--input", type=Path, required=True, help="local UTF-8 JSON fixture")
    args = parser.parse_args(argv)

    try:
        status, findings, refs = inspect_local_document(args.input)
    except _LocalIntakeError as exc:
        print(json.dumps({
            "status": "rejected",
            "code": exc.code,
            "model_dispatched": False,
            "authorized": False,
        }, separators=(",", ":"), sort_keys=True))
        return 2

    print(json.dumps({
        "status": status,
        "finding_count": findings,
        "evidence_reference_count": refs,
        "metadata_only": True,
        "model_dispatched": False,
        "authorized": False,
    }, separators=(",", ":"), sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
