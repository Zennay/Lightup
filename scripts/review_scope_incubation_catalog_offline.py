#!/usr/bin/env python3
"""Opt-in single-checkout capability catalog metadata audit; never authorize."""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.capabilities import get_capabilities
from lightup.capability_registry_incubation_catalog_review import review_incubation_catalog
from export_scope_capability_registry_offline import snapshot_manifest


def main(args: list[str]) -> int:
    if type(args) is not list or args:
        receipt = {"status": "HOLD", "reason": "no_arguments_permitted"}
    else:
        try:
            receipt = review_incubation_catalog(snapshot_manifest(get_capabilities())).as_dict()
        except (ValueError, TypeError, OverflowError, RecursionError):
            receipt = {"status": "HOLD", "reason": "invalid_local_registry"}
    for key in ("authorization_verified", "permit_issued", "execution_enabled",
                "merge_approved", "release_approved"):
        receipt[key] = False
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
