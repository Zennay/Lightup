"""Offline syntactic intersection of proposed and declared lab IP literals.

Neither JSON content nor a REVIEW_ONLY result is trusted ownership, consent,
a permit, a scan authorization, an actual allowlist, or an execution gate.
"""
from __future__ import annotations

import ipaddress
import json
import sys

try:
    from scripts.check_scope_lab_literal_offline import review_literal
except ModuleNotFoundError:  # direct invocation from repository's scripts/ folder
    from check_scope_lab_literal_offline import review_literal

MAX_MANIFEST_BYTES = 8192
MAX_LITERALS = 32
AUTHORITY_FIELDS = (
    "authorization_verified",
    "permit_issued",
    "execution_enabled",
    "merge_approved",
    "release_approved",
)


def _receipt(status: str, reason: str) -> dict[str, object]:
    return {
        "schema_version": 1,
        "status": status,
        "reason": reason,
        **{field: False for field in AUTHORITY_FIELDS},
    }


def _pairs_no_duplicates(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON key")
        result[key] = value
    return result


def parse_document(raw: object) -> object:
    """Parse strictly bounded ASCII JSON without accepting duplicate keys."""
    if type(raw) is not bytes or not raw or len(raw) > MAX_MANIFEST_BYTES:
        raise ValueError("invalid document length/type")
    try:
        return json.loads(
            raw.decode("ascii"), object_pairs_hook=_pairs_no_duplicates,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite")),
        )
    except (UnicodeDecodeError, ValueError, TypeError, RecursionError) as exc:
        raise ValueError("invalid document syntax") from exc


def _canonical_literally_reviewable(values: object) -> set[str]:
    if type(values) is not list or not (1 <= len(values) <= MAX_LITERALS):
        raise ValueError("invalid literal collection")
    admitted: set[str] = set()
    for value in values:
        if type(value) is not str or review_literal(value)["status"] != "REVIEW_ONLY":
            raise ValueError("invalid lab literal shape")
        # Exact, canonical textual identity: reject e.g. IPv6 uppercase,
        # redundant hextets and representation-aliasing between two entries.
        if str(ipaddress.ip_address(value)) != value:
            raise ValueError("noncanonical literal identity")
        if value in admitted:
            raise ValueError("duplicate literal identity")
        admitted.add(value)
    return admitted


def review_inventory(document: object) -> dict[str, object]:
    """Shape-only result; declaration does NOT prove inventory provenance."""
    if type(document) is not dict or set(document) != {
        "schema_version", "declared_lab_literals", "proposed_literals"
    } or type(document.get("schema_version")) is not int or document["schema_version"] != 1:
        return _receipt("HOLD", "INVALID_MANIFEST_SHAPE")
    try:
        declared = _canonical_literally_reviewable(document["declared_lab_literals"])
        proposed = _canonical_literally_reviewable(document["proposed_literals"])
    except (ValueError, TypeError, AttributeError, OverflowError):
        return _receipt("HOLD", "INVALID_LAB_LITERAL")
    if not proposed <= declared:
        return _receipt("HOLD", "UNDECLARED_LITERAL")
    return _receipt("REVIEW_ONLY", "DECLARED_LITERAL_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        # Bounded read: no filesystem, network, DNS, registry or target access.
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_inventory(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_MANIFEST_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    # Both statuses are nonzero: a shell && must never mint permission.
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
