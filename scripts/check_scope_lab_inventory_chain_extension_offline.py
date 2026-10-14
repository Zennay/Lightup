"""Offline non-authorizing review of two self-declared lab-inventory chains.

Candidate must preserve EVERY prior revision exactly and add a narrowing step.
Both supplied chains are untrusted, not signed, provenance, consent, or scope.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _receipt, parse_document,
    )
    from scripts.check_scope_lab_inventory_chain_offline import review_chain
except ModuleNotFoundError:  # standalone direct scripts/ execution
    from check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _receipt, parse_document,
    )
    from check_scope_lab_inventory_chain_offline import review_chain


def review_extension(document: object) -> dict[str, object]:
    if (
        type(document) is not dict
        or set(document) != {"schema_version", "previous_chain", "candidate_chain"}
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
    ):
        return _receipt("HOLD", "INVALID_COMPARISON_SHAPE")

    previous, candidate = document["previous_chain"], document["candidate_chain"]
    if review_chain(previous)["status"] != "REVIEW_ONLY":
        return _receipt("HOLD", "INVALID_PREVIOUS_CHAIN")
    if review_chain(candidate)["status"] != "REVIEW_ONLY":
        return _receipt("HOLD", "INVALID_CANDIDATE_CHAIN")

    old = previous["revisions"]
    new = candidate["revisions"]
    if len(new) <= len(old):
        return _receipt("HOLD", "STALE_OR_ROLLED_BACK_CHAIN")
    if new[:len(old)] != old:
        return _receipt("HOLD", "REWRITTEN_CHAIN_PREFIX")
    return _receipt("REVIEW_ONLY", "APPENDED_CHAIN_SHAPE_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_extension(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_COMPARISON_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
