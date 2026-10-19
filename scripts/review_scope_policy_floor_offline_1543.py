#!/usr/bin/env python3
"""Opt-in, non-authorizing policy floor review for synthetic LightUp change-review inputs.

This is deliberately NOT connected to LightUp policy loading, execution, CI, or
authorization. REVIEW_ONLY (3) is not approval; HOLD (2) is a review veto.
The input is a bounded, fictional JSON snapshot, never a trusted policy source.
"""
from __future__ import annotations

import json
import sys
from typing import Any

MAX_INPUT_BYTES = 16384
SCHEMA = "lightup.scope.synthetic_policy_floor.v1"
RANK = {"PASS": 0, "PASS_WITH_WARNING": 1, "REVIEW_REQUIRED": 2, "BLOCK": 3}
SEVERITY_FLOOR = {
    "critical": "BLOCK",
    "high": "REVIEW_REQUIRED",
    "medium": "PASS_WITH_WARNING",
    "low": "PASS_WITH_WARNING",
    "info": "PASS",
}
EXTRA_FLOOR = {
    "surface_change_verdict": "REVIEW_REQUIRED",
    "incomplete_coverage_verdict": "REVIEW_REQUIRED",
}
FALSE_FLAGS = {
    "authorized": False,
    "client_consent_verified": False,
    "operator_consent_verified": False,
    "dispatch_allowed": False,
    "grant_allowed": False,
    "merge_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}
HOLD = 2
REVIEW_ONLY = 3


class PolicyHold(ValueError):
    """A policy cannot be safely reviewed; never expose submitted strings."""


def _object_pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise PolicyHold("duplicate")
        result[key] = value
    return result


def _reject_constant(_constant: str) -> None:
    raise PolicyHold("constant")


def _exact_ascii(text: Any, limit: int = 128) -> bool:
    return type(text) is str and 1 <= len(text) <= limit and text.isascii()


def _floor(candidate: Any, minimum: str) -> bool:
    return (
        type(candidate) is str
        and candidate in RANK
        and RANK[candidate] >= RANK[minimum]
    )


def check_snapshot(document: Any) -> bool:
    """Review a synthetic policy floor. No result can create authorization."""
    if type(document) is not dict or set(document) != {"schema", "policy"}:
        return False
    if type(document["schema"]) is not str or document["schema"] != SCHEMA:
        return False
    policy = document["policy"]
    required = {
        "severity_verdicts", "surface_change_verdict",
        "incomplete_coverage_verdict", "ignore_rules",
        "ignore_paths", "min_confidence",
    }
    if type(policy) is not dict or set(policy) != required:
        return False
    verdicts = policy["severity_verdicts"]
    if type(verdicts) is not dict or set(verdicts) != set(SEVERITY_FLOOR):
        return False
    if not all(
        _floor(verdicts[severity], floor)
        for severity, floor in SEVERITY_FLOOR.items()
    ):
        return False
    if not all(_floor(policy[key], floor) for key, floor in EXTRA_FLOOR.items()):
        return False
    # The source change-review allows suppressions; this separate gate
    # deliberately refuses suppressions for an independent review lane.
    if type(policy["ignore_rules"]) is not list or policy["ignore_rules"]:
        return False
    if type(policy["ignore_paths"]) is not list or policy["ignore_paths"]:
        return False
    # A positive confidence threshold can silently suppress high-severity
    # hypotheses; no implicit string/bool/NaN coercions are acceptable.
    confidence = policy["min_confidence"]
    if type(confidence) not in (int, float) or confidence != 0:
        return False
    return True


def evaluate(data: bytes) -> int:
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES or not data:
        return HOLD
    try:
        document = json.loads(
            data.decode("utf-8", errors="strict"),
            object_pairs_hook=_object_pairs_no_duplicates,
            parse_constant=_reject_constant,
        )
        return REVIEW_ONLY if check_snapshot(document) else HOLD
    except (UnicodeError, ValueError, OverflowError, RecursionError, TypeError):
        return HOLD


def receipt(exit_code: int) -> str:
    result = {
        "schema": SCHEMA,
        "status": "REVIEW_ONLY" if exit_code == REVIEW_ONLY else "HOLD",
        "basis": "untrusted_synthetic_policy_only",
        **FALSE_FLAGS,
    }
    return json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n"


def main() -> int:
    # No options, paths, subprocesses, network, file reads, or runtime imports.
    try:
        code = HOLD if len(sys.argv) != 1 else evaluate(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    except (OSError, ValueError, UnicodeError):
        code = HOLD
    message = receipt(code)
    try:
        written = sys.stdout.write(message)
        if written != len(message):
            return HOLD
        sys.stdout.flush()
    except (OSError, ValueError, UnicodeError):
        return HOLD
    return code


if __name__ == "__main__":
    raise SystemExit(main())
