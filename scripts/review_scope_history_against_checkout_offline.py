#!/usr/bin/env python3
"""Local-only history-to-checkout registry consistency preflight.

The local checkout is NOT authenticated provenance. No target, Git, credentials,
tenant state, grant, authorization or network interactions are performed.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.capabilities import get_capabilities
from lightup.capability_registry_checkout_review import review_history_against_local_registry
from export_scope_capability_registry_offline import snapshot_manifest
from review_scope_capability_registry_offline import read_local_regular_file

_AUTHORITY_FIELDS = ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved")


def main(paths: list[str]) -> int:
    if type(paths) is not list or not 2 <= len(paths) <= 16 or any(type(item) is not str for item in paths):
        receipt: dict[str, object] = {"status": "HOLD", "reason": "invalid_history_arguments"}
    else:
        try:
            seen: set[tuple[int, int]] = set()
            declared: list[bytes] = []
            for path in paths:
                data, identity = read_local_regular_file(path)
                if identity in seen:
                    raise ValueError("duplicate physical snapshot")
                seen.add(identity)
                declared.append(data)
            # Use exact real model types, enums, flags and canonical Unicode
            # constraints through the already validated offline exporter.
            local = snapshot_manifest(get_capabilities())
            receipt = review_history_against_local_registry(tuple(declared), local).as_dict()
        except (OSError, ValueError, TypeError, OverflowError, RecursionError):
            receipt = {"status": "HOLD", "reason": "invalid_history_or_local_registry"}
    for field in _AUTHORITY_FIELDS:
        receipt[field] = False
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
