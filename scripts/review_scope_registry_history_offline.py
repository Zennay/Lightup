#!/usr/bin/env python3
"""Read-only bounded CLI for non-authorizing capability registry history review.

Each argument is a distinct physical local JSON file, ordered oldest to newest.
No Git provenance, release, approval or execution authority is implied.
"""
from __future__ import annotations

import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.capability_registry_history_review import review_capability_registry_history
from review_scope_capability_registry_offline import read_local_regular_file


def main(arguments: list[str]) -> int:
    receipt: dict[str, object]
    if type(arguments) is not list or not 2 <= len(arguments) <= 16 or any(type(arg) is not str for arg in arguments):
        receipt = {"status": "HOLD", "reason": "invalid_history_arguments"}
    else:
        try:
            identities: set[tuple[int, int]] = set()
            snapshots: list[bytes] = []
            for path in arguments:
                contents, identity = read_local_regular_file(path)
                if identity in identities:
                    raise ValueError("duplicate physical history snapshot")
                identities.add(identity)
                snapshots.append(contents)
            receipt = review_capability_registry_history(tuple(snapshots)).as_dict()
        except (OSError, ValueError, TypeError, OverflowError):
            receipt = {"status": "HOLD", "reason": "invalid_local_history_files"}
    for key in ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved"):
        receipt[key] = False
    print(json.dumps(receipt, separators=(",", ":"), sort_keys=True))
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
