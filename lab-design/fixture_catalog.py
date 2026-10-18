#!/usr/bin/env python3
"""Export the original installed LightUp fixture ground truth without starting it."""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
from pathlib import Path
import sys

from native_bridge import (Hold, build_native_catalog, ensure, private_create,
                           private_ip, read_catalog)

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))


def build_catalog(target: str, profile_names: list[str]) -> dict:
    from lightup.labfixtures import PROFILES, expected_findings

    # The original local fixture binds loopback; a private-subnet IP is NOT a
    # valid alias for a loopback fixture. Do not fabricate fixture bindings.
    target = private_ip(target)
    ensure(ipaddress.ip_address(target).is_loopback)
    ensure(len(profile_names) >= 1 and len(profile_names) <= len(PROFILES))
    ensure(len(profile_names) == len(set(profile_names)))
    ensure(all(p in PROFILES for p in profile_names))
    records = []
    for name in profile_names:
        source = PROFILES[name]
        ground_truth = [
            {"identifier": item.identifier, "title": item.title,
             "capability_id": item.capability_id, "severity": item.severity}
            for item in expected_findings(source)
        ]
        records.append({
            "scenario_id": "fixture-" + name,
            "name": "Installed fixture: " + name,
            "description": source.description,
            "targets": [target],
            "expected_findings": ground_truth
        })
    return {"schema": "lightup.lab_design_catalog.v1", "status": "DRAFT_ONLY",
            "authorized": False, "consent_verified": False,
            "dispatch_allowed": False, "release_allowed": False,
            "scenarios": records}


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Export ORIGINAL offline fixture profile declarations. No fixture server or scan.")
    parser.add_argument("--target", default="127.0.0.1",
                        help="numeric loopback-only fixture identity (127.x or ::1)")
    parser.add_argument("--profile", action="append",
                        help="one or more ORIGINAL fixture IDs; default all")
    parser.add_argument("--output", type=Path, required=True,
                        help="NEW PRIVATE .json file, owner-only 0600, never overwritten")
    args = parser.parse_args()
    try:
        from lightup.labfixtures import PROFILES
        names = args.profile or sorted(PROFILES)
        catalog = build_catalog(args.target, names)
        payload = (json.dumps(catalog, indent=2, sort_keys=True) + "\n").encode("utf-8")
        ensure(0 < len(payload) <= 262144)
        ensure(args.output.suffix == ".json")
        # Create the source as a private catalog before using the same original
        # native constructor path as ordinary human-authored Studio catalogs.
        # No runnable fixture is constructed or started.
        build_native_catalog(catalog["scenarios"])
        private_create(args.output, payload)
        print("PRIVATE source-bound fixture catalog written (no fixture started).")
        print("Source declarations:", len(names), "original planted findings:",
              sum(len(s["expected_findings"]) for s in catalog["scenarios"]))
        print("Payload SHA-256 (not authenticated provenance):", hashlib.sha256(payload).hexdigest())
        print("No original target, named fixture address, operator approval or grant shown.")
        return 0
    except (Hold, ValueError, OSError, TypeError, ImportError) as exc:
        print("HOLD: original fixture catalog could not be safely admitted or written; "
              "no fixture/scan started.", file=sys.stderr)
        return 3


if __name__ == "__main__":
    raise SystemExit(main())
