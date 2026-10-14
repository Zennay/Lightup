#!/usr/bin/env python3
"""Read-only, source-local LightUp capability incubation posture check.

Succeeds only as REVIEW_ONLY / exit 3: it cannot authorize target execution.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from lightup.capabilities import get_capabilities
from lightup.capability_registry_incubation_review import review_incubation_capability_posture
from export_scope_capability_registry_offline import snapshot_manifest

_DENY = ("authorization_verified", "permit_issued", "execution_enabled", "merge_approved", "release_approved")


def main(args: list[str]) -> int:
    if type(args) is not list or args:
        receipt: dict[str, object] = {"status": "HOLD", "reason": "no_arguments_accepted"}
    else:
        try:
            receipt = review_incubation_capability_posture(snapshot_manifest(get_capabilities())).as_dict()
        except (ValueError, TypeError, OverflowError, RecursionError):
            receipt = {"status": "HOLD", "reason": "invalid_source_registry"}
    for key in _DENY:
        receipt[key] = False
    sys.stdout.write(json.dumps(receipt, sort_keys=True, separators=(",", ":")) + "\n")
    return 3 if receipt["status"] == "REVIEW_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
