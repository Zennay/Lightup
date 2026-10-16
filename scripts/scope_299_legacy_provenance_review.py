"""HOLD-only, privacy-minimal offline legacy provenance shape diagnostic (#299).

This independent, intentionally non-installed tool consumes one synthetic JSON
object on stdin. It never issues a grant, checks ownership or contacts targets.
A canonical *shape* is not proof of permission or source-code safety.

Usage: python scripts/scope_299_legacy_provenance_review.py --offline-synthetic-only
"""
from __future__ import annotations

import json
import sys


MAX_STDIN_BYTES = 4096
MAX_NESTING_DEPTH = 32
_REQUIRED_KEYS = frozenset(("owner", "reference"))
_FALSE_CAPABILITIES = {
    "can_authorize": False,
    "can_dispatch": False,
    "can_deploy": False,
    "can_merge": False,
    "can_release": False,
    "can_scan": False,
}


def canonical_text(value: object) -> bool:
    """Only an exact printable, already-trimmed nonempty string is shape-valid.

    Conservative presentation hygiene is advisory; this is NOT an authorization
    predicate and does not replace durable issuance / revocation validation.
    """
    return (
        type(value) is str
        and bool(value)
        and value == value.strip()
        and all(character.isprintable() for character in value)
    )


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("noncanonical synthetic packet")
        result[key] = value
    return result


def _reject_json_constant(_value: str) -> None:
    raise ValueError("noncanonical synthetic packet")


def _exceeds_json_depth(raw: bytes) -> bool:
    """Bytewise lexical depth cap, invariant across Python JSON implementations.

    Ignore delimiters inside JSON strings, including escaped quote/backslash.
    The full JSON decoder separately validates syntax and matching brackets.
    """
    depth = 0
    quoted = False
    escaped = False
    for byte in raw:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:  # backslash
                escaped = True
            elif byte == 34:  # quote
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):  # [ or {
            depth += 1
            if depth > MAX_NESTING_DEPTH:
                return True
        elif byte in (93, 125):  # ] or }
            depth -= 1
            if depth < 0:
                return True
    # Remaining unclosed nesting/quotes are rejected by json.loads.
    return False


def review_bytes(raw: bytes) -> tuple[str, int]:
    """Return only a bounded fixed diagnostic code and a nonzero exit code.

    Exit 2 = parsed synthetic input (shape valid OR invalid, still HOLD).
    Exit 3 = malformed, ambiguous or oversized input (also HOLD).
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_STDIN_BYTES:
        return "invalid_packet", 3
    if _exceeds_json_depth(raw):
        return "invalid_packet", 3
    try:
        candidate = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return "invalid_packet", 3
    if type(candidate) is not dict or frozenset(candidate) != _REQUIRED_KEYS:
        return "invalid_packet", 3
    if canonical_text(candidate["owner"]) and canonical_text(candidate["reference"]):
        return "canonical_shape_only", 2
    return "noncanonical_shape", 2


def render_receipt(reason: str) -> str:
    # Do not serialize any caller-provided value (including exceptions).
    if reason not in {"invalid_packet", "canonical_shape_only", "noncanonical_shape"}:
        reason = "invalid_packet"
    receipt = {"status": "HOLD", "reason": reason, **_FALSE_CAPABILITIES}
    return json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args != ["--offline-synthetic-only"]:
        print(render_receipt("invalid_packet"))
        return 3
    # Single bounded standard-input read. No paths, files, sockets or DNS.
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    reason, code = review_bytes(raw)
    print(render_receipt(reason))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
