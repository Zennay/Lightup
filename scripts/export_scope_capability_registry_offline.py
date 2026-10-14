#!/usr/bin/env python3
"""Export current local registry metadata for independent OFFLINE review only.

No trusted release identity, authorization, permit or network scan is implied.
Successful metadata export deliberately exits 3 (never success/0).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from lightup.capabilities import Capability, CapabilityState, get_capabilities
from lightup.capability_registry_drift_review import _decode_manifest


def snapshot_manifest(records: tuple[Capability, ...]) -> bytes:
    if type(records) is not tuple or not 1 <= len(records) <= 128:
        raise ValueError("invalid local registry container")
    result = []
    for record in records:
        if type(record) is not Capability or type(record.state) is not CapabilityState:
            raise ValueError("noncanonical registry entry")
        if type(record.capability_id) is not str or type(record.requires_explicit_activation) is not bool:
            raise ValueError("noncanonical registry metadata")
        result.append({
            "capability_id": record.capability_id,
            "state": record.state.value,
            "requires_explicit_activation": record.requires_explicit_activation,
        })
    result.sort(key=lambda item: item["capability_id"])
    encoded = json.dumps({"capabilities": result}, separators=(",", ":"), ensure_ascii=True).encode("ascii")
    _decode_manifest(encoded)  # Validate the exact metadata contract used by the reviewer.
    return encoded


def main(args: list[str]) -> int:
    if args:
        print("HOLD: exporter takes no arguments", file=sys.stderr)
        return 2
    try:
        data = snapshot_manifest(get_capabilities())
    except (ValueError, TypeError, OverflowError):
        print("HOLD: local capability registry metadata invalid", file=sys.stderr)
        return 2
    sys.stdout.buffer.write(data + b"\n")
    return 3


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
