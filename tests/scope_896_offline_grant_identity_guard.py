"""Unwired synthetic-only live-grant identity syntax review, never authority."""
from __future__ import annotations

import json
import re
import sys
from uuid import UUID

MAX_INPUT_BYTES = 1024
_CANONICAL_UUID4 = re.compile(
    r"[0-9a-f]{8}-[0-9a-f]{4}-4[0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\Z",
    re.ASCII,
)
_FLAGS = {
    "grants_authority": False,
    "permits_execution": False,
    "dispatch_allowed": False,
    "scans_allowed": False,
    "deploy_allowed": False,
    "release_allowed": False,
}


class _Rejected(ValueError):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise _Rejected("duplicate JSON key")
        result[key] = value
    return result


def _non_json_constant(_value: str) -> object:
    raise _Rejected("non-JSON number")


def review_identity(grant_id: object) -> dict[str, object]:
    """Exact string, canonical UUID4 *syntax* only; no SQLite or grant lookup."""
    suitable = False
    if type(grant_id) is str and _CANONICAL_UUID4.fullmatch(grant_id):
        try:
            suitable = str(UUID(grant_id, version=4)) == grant_id
        except ValueError:
            suitable = False
    return {"decision": "REVIEW_ONLY" if suitable else "HOLD", **_FLAGS}


def review_json(raw: bytes) -> dict[str, object]:
    if type(raw) is not bytes or len(raw) > MAX_INPUT_BYTES:
        return review_identity(None)
    try:
        envelope = json.loads(
            raw.decode("utf-8", errors="strict"),
            object_pairs_hook=_unique_pairs,
            parse_constant=_non_json_constant,
        )
        if type(envelope) is not dict or envelope.keys() != {"grant_id"}:
            return review_identity(None)
        return review_identity(envelope["grant_id"])
    except (ValueError, UnicodeError, TypeError, RecursionError):
        return review_identity(None)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    receipt = review_identity(None) if args != ["--offline-synthetic-only"] else review_json(sys.stdin.buffer.read(MAX_INPUT_BYTES + 1))
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["decision"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
