"""Unwired synthetic risk-decision audit reviewer; never decides approvals."""
from __future__ import annotations

import json
import re
import sys

MAX_INPUT_BYTES = 3072
_CANONICAL_APPROVAL = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z", re.ASCII)
_SYNTHETIC_ACTOR = re.compile(r"[a-z][a-z0-9-]{1,31}\Z", re.ASCII)
_FIELDS = frozenset(("approval_id", "requested_by", "reviewer_id", "status", "decided_by", "decided_at"))
_FLAGS = {
    "grants_authority": False,
    "permits_execution": False,
    "dispatch_allowed": False,
    "scans_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}


class _Reject(ValueError):
    pass


def _unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    obj: dict[str, object] = {}
    for key, value in pairs:
        if key in obj:
            raise _Reject("duplicate key")
        obj[key] = value
    return obj


def _bad_constant(_value: str) -> object:
    raise _Reject("non-JSON number")


def review_record(record: object) -> dict[str, object]:
    """No database, no mutation, no decision authority. Typed synthetic subset."""
    eligible = False
    # Exact outer dict is insufficient: str-subclass keys can override
    # hashing/equality during dict_keys comparisons. Admit keys first.
    if (
        type(record) is dict
        and len(record) == len(_FIELDS)
        and all(type(key) is str for key in record)
        and record.keys() == _FIELDS
    ):
        approval = record["approval_id"]
        requester = record["requested_by"]
        reviewer = record["reviewer_id"]
        status = record["status"]
        decided_by = record["decided_by"]
        decided_at = record["decided_at"]
        if (
            type(approval) is str and _CANONICAL_APPROVAL.fullmatch(approval)
            and type(requester) is str and _SYNTHETIC_ACTOR.fullmatch(requester)
            and type(reviewer) is str and _SYNTHETIC_ACTOR.fullmatch(reviewer)
            and requester != reviewer
            and type(status) is str and status == "pending"
            and decided_by is None and decided_at is None
        ):
            eligible = True
    return {"decision": "REVIEW_ONLY" if eligible else "HOLD", **_FLAGS}


def review_json(data: bytes) -> dict[str, object]:
    if type(data) is not bytes or len(data) > MAX_INPUT_BYTES:
        return review_record(None)
    try:
        data_obj = json.loads(data.decode("utf-8", "strict"), object_pairs_hook=_unique, parse_constant=_bad_constant)
    except (ValueError, TypeError, UnicodeError, RecursionError):
        return review_record(None)
    return review_record(data_obj)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    # Block truthy/equality-spoofed caller argv before reading even one byte.
    opt_in = (
        type(args) is list and len(args) == 1
        and type(args[0]) is str and args[0] == "--offline-synthetic-only"
    )
    receipt = review_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1)) if opt_in else review_record(None)
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["decision"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
