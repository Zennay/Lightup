"""Strict offline consistency review of self-declared lab-inventory hash chains.

Self-recomputed checksums are NOT signatures, trusted chronology, provenance,
ownership, consent, permits, or evidence that omitted versions never existed.
"""
from __future__ import annotations

import hashlib
import json
import re
import sys

try:
    from scripts.check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable,
        _receipt, parse_document,
    )
except ModuleNotFoundError:  # standalone scripts/ CLI
    from check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _canonical_literally_reviewable,
        _receipt, parse_document,
    )

_DOMAIN = b"LIGHTUP-OFFLINE-LAB-CHAIN-V1\x00"
_SHA256_LOWER = re.compile(r"[0-9a-f]{64}\Z", re.ASCII)
_FIELDS = frozenset({"version", "lab_literals", "previous_digest", "digest"})


def record_digest(version: int, literals: set[str], previous_digest: str | None) -> str:
    """Public, domain-separated deterministic *checksum*, not a MAC or signature."""
    canonical = json.dumps(
        {
            "lab_literals": sorted(literals),
            "previous_digest": previous_digest,
            "version": version,
        },
        ensure_ascii=True,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("ascii")
    return hashlib.sha256(_DOMAIN + canonical).hexdigest()


def review_chain(document: object) -> dict[str, object]:
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "revisions"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
    ):
        return _receipt("HOLD", "INVALID_CHAIN_SHAPE")
    revisions = document["revisions"]
    if type(revisions) is not list or not (2 <= len(revisions) <= 4):
        return _receipt("HOLD", "INVALID_CHAIN_LENGTH")

    last_literals: set[str] | None = None
    last_digest: str | None = None
    for position, entry in enumerate(revisions, start=1):
        if type(entry) is not dict or set(entry) != _FIELDS:
            return _receipt("HOLD", "INVALID_REVISION_SHAPE")
        if type(entry["version"]) is not int or entry["version"] != position:
            return _receipt("HOLD", "NONCONTIGUOUS_REVISION")
        claimed_parent = entry["previous_digest"]
        if position == 1:
            if claimed_parent is not None:
                return _receipt("HOLD", "INVALID_CHAIN_ROOT")
        elif type(claimed_parent) is not str or claimed_parent != last_digest:
            return _receipt("HOLD", "BROKEN_DIGEST_LINK")
        digest = entry["digest"]
        if type(digest) is not str or _SHA256_LOWER.fullmatch(digest) is None:
            return _receipt("HOLD", "INVALID_DIGEST_FORMAT")
        try:
            literals = _canonical_literally_reviewable(entry["lab_literals"])
        except (ValueError, TypeError, AttributeError, OverflowError):
            return _receipt("HOLD", "INVALID_LAB_LITERAL")
        if last_literals is not None and not literals.issubset(last_literals):
            return _receipt("HOLD", "TRANSIENT_SCOPE_WIDENING")
        if digest != record_digest(position, literals, claimed_parent):
            return _receipt("HOLD", "CHECKSUM_MISMATCH")
        last_literals, last_digest = literals, digest

    return _receipt("REVIEW_ONLY", "SELF_DECLARED_CHAIN_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_chain(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_CHAIN_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
