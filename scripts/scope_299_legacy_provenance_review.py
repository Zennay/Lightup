"""HOLD-only, privacy-minimal offline legacy provenance shape diagnostic (#299).

This independent, intentionally non-installed tool consumes one synthetic JSON
object on stdin. It never issues a grant, checks ownership or contacts targets.
A canonical *shape* is not proof of permission or source-code safety.

Usage: python scripts/scope_299_legacy_provenance_review.py --offline-synthetic-only
       python scripts/scope_299_legacy_provenance_review.py --offline-synthetic-pair-only
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


def _parse_bounded_packet(raw: bytes) -> object:
    """One strict bounded parser, shared by single and paired synthetic modes.

    Malformed packets return None and can never yield a partial comparison.
    JSON null is also invalid in both mode schemas.
    """
    if type(raw) is not bytes or not raw or len(raw) > MAX_STDIN_BYTES:
        return None
    if _exceeds_json_depth(raw):
        return None
    try:
        return json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=_reject_json_constant,
        )
    except (UnicodeError, ValueError, TypeError, RecursionError):
        return None


def _is_provenance_object(candidate: object) -> bool:
    return type(candidate) is dict and frozenset(candidate) == _REQUIRED_KEYS


def _canonical_provenance_shape(candidate: dict[str, object]) -> bool:
    return canonical_text(candidate["owner"]) and canonical_text(candidate["reference"])


def review_bytes(raw: bytes) -> tuple[str, int]:
    """Review one fictional legacy provenance shape without granting authority.

    Exit 2 = parsed synthetic input (canonical OR noncanonical, always HOLD).
    Exit 3 = malformed or oversized input (also HOLD).
    """
    candidate = _parse_bounded_packet(raw)
    if not _is_provenance_object(candidate):
        return "invalid_packet", 3
    if _canonical_provenance_shape(candidate):
        return "canonical_shape_only", 2
    return "noncanonical_shape", 2


def review_pair_bytes(raw: bytes) -> tuple[str, int]:
    """Compare exactly two *untrusted* synthetic provenance snapshots.

    A matching pair is NOT issuer authentication, customer consent or a live
    grant. One malformed member invalidates the entire review, never a
    partially accepted amendment.
    """
    candidate = _parse_bounded_packet(raw)
    if type(candidate) is not dict or frozenset(candidate) != {"before", "after"}:
        return "invalid_packet", 3
    before, after = candidate["before"], candidate["after"]
    if not _is_provenance_object(before) or not _is_provenance_object(after):
        return "invalid_packet", 3
    if not _canonical_provenance_shape(before) or not _canonical_provenance_shape(after):
        return "noncanonical_shape", 2
    if before["owner"] != after["owner"] or before["reference"] != after["reference"]:
        return "provenance_changed", 2
    return "unchanged_shape_only", 2


def render_receipt(reason: str) -> str:
    # Do not serialize any caller-provided value (including exceptions).
    if reason not in {"invalid_packet", "canonical_shape_only", "noncanonical_shape", "provenance_changed", "unchanged_shape_only"}:
        reason = "invalid_packet"
    receipt = {"status": "HOLD", "reason": reason, **_FALSE_CAPABILITIES}
    return json.dumps(receipt, ensure_ascii=True, separators=(",", ":"), sort_keys=True)


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args not in (["--offline-synthetic-only"], ["--offline-synthetic-pair-only"]):
        print(render_receipt("invalid_packet"))
        return 3
    # Single bounded standard-input read. No paths, files, sockets or DNS.
    raw = sys.stdin.buffer.read(MAX_STDIN_BYTES + 1)
    reviewer = review_pair_bytes if args == ["--offline-synthetic-pair-only"] else review_bytes
    reason, code = reviewer(raw)
    print(render_receipt(reason))
    return code


if __name__ == "__main__":
    raise SystemExit(main())
