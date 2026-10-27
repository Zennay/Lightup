"""Atomic offline consistency dossier across all six opt-in lab scope reviewers.

Only syntactic cross-binding of untrusted JSON. A clean dossier is never
verified consent, authorization, inventory ownership, grant, permit or release.
"""
from __future__ import annotations

import json
import sys

try:
    from scripts.check_scope_lab_literal_offline import review_literal
    from scripts.check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _receipt, parse_document,
    )
    from scripts.check_scope_lab_inventory_narrowing_offline import review_narrowing
    from scripts.check_scope_lab_inventory_history_offline import review_history
    from scripts.check_scope_lab_inventory_chain_offline import review_chain
    from scripts.check_scope_lab_inventory_chain_extension_offline import review_extension
    from scripts.check_scope_lab_inventory_offline import review_inventory
except ModuleNotFoundError:  # direct scripts/ invocation
    from check_scope_lab_literal_offline import review_literal
    from check_scope_lab_inventory_offline import (
        MAX_MANIFEST_BYTES, _receipt, parse_document, review_inventory,
    )
    from check_scope_lab_inventory_narrowing_offline import review_narrowing
    from check_scope_lab_inventory_history_offline import review_history
    from check_scope_lab_inventory_chain_offline import review_chain
    from check_scope_lab_inventory_chain_extension_offline import review_extension

_FIELDS = frozenset({
    "schema_version", "literal", "inventory", "narrowing", "history",
    "chain", "extension",
})


def review_dossier(document: object) -> dict[str, object]:
    if (
        type(document) is not dict
        or set(document) != _FIELDS
        or type(document.get("schema_version")) is not int
        or document["schema_version"] != 1
    ):
        return _receipt("HOLD", "INVALID_DOSSIER_SHAPE")
    literal, inventory, narrowing, history, chain, extension = (
        document["literal"], document["inventory"], document["narrowing"],
        document["history"], document["chain"], document["extension"],
    )
    try:
        reviews = (
            review_literal(literal),
            review_inventory(inventory),
            review_narrowing(narrowing),
            review_history(history),
            review_chain(chain),
            review_extension(extension),
        )
    except (ValueError, TypeError, AttributeError, KeyError, OverflowError):
        return _receipt("HOLD", "INPUT_REVIEW_UNAVAILABLE")
    if any(receipt["status"] != "REVIEW_ONLY" for receipt in reviews):
        return _receipt("HOLD", "INPUT_REVIEW_HELD")

    # Every involved source is still self-declared and untrusted. The checks
    # below deny contradictory statements WITHIN that one submitted dossier.
    try:
        proposed = set(inventory["proposed_literals"])
        declared = set(inventory["declared_lab_literals"])
        previous = set(narrowing["previous_lab_literals"])
        next_values = set(narrowing["proposed_lab_literals"])
        history_values = [set(row) for row in history["lab_literal_versions"]]
        revisions = chain["revisions"]
        chain_values = [set(row["lab_literals"]) for row in revisions]
        prior_chain = extension["previous_chain"]
        candidate_chain = extension["candidate_chain"]
        expected_prior = {
            "schema_version": 1,
            "revisions": revisions[:-1],
        }
    except (TypeError, KeyError, ValueError, AttributeError):
        return _receipt("HOLD", "DOSSIER_MISMATCH")

    if (
        literal not in proposed
        or not proposed <= declared
        or proposed != next_values
        or len(history_values) != len(chain_values)
        or len(chain_values) < 3
        or history_values != chain_values
        or previous != history_values[-2]
        or proposed != history_values[-1]
        or candidate_chain != chain
        or prior_chain != expected_prior
    ):
        return _receipt("HOLD", "DOSSIER_MISMATCH")
    return _receipt("REVIEW_ONLY", "CROSS_BOUND_UNTRUSTED_SHAPES_ONLY")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if args:
        result = _receipt("HOLD", "CLI_ARGUMENTS_DISALLOWED")
    else:
        raw = sys.stdin.buffer.read(MAX_MANIFEST_BYTES + 1)
        try:
            result = review_dossier(parse_document(raw))
        except ValueError:
            result = _receipt("HOLD", "INVALID_DOSSIER_JSON")
    print(json.dumps(result, sort_keys=True, separators=(",", ":")))
    return 3 if result["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
