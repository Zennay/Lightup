"""Offline, non-authorizing LightUp scope release dependency inventory.

Claims are deliberately untrusted. Even an entirely self-reported complete packet
cannot mint scan, dispatch, grant, merge, deploy or release authority.
"""
from __future__ import annotations

import json
import sys

GATES = (
    "client_consent",
    "asset_and_capability_scope",
    "live_grant_and_revocation",
    "operator_step_up",
    "durable_prehandler_evidence",
    "installed_ingress_and_egress",
    "permanent_vps_ci",
    "independent_security_privacy_review",
    "explicit_human_release",
)
FLAGS = (
    "scan_allowed", "grant_allowed", "dispatch_allowed",
    "merge_allowed", "deploy_allowed", "release_allowed",
)
MAX_BYTES = 8192


class InvalidPacket(ValueError):
    pass


def _unique_pairs(pairs: list[tuple[str, object]]) -> dict[str, object]:
    output: dict[str, object] = {}
    for key, value in pairs:
        if key in output:
            raise InvalidPacket("duplicate key")
        output[key] = value
    return output


def _reject_constant(value: str) -> None:
    raise InvalidPacket("nonfinite number")


def assess(raw: bytes) -> dict[str, object]:
    """Accept shape-only fictional declarations, NEVER validate actual authority."""
    if type(raw) is not bytes or len(raw) > MAX_BYTES:
        raise InvalidPacket("input exceeds byte budget")
    try:
        data = json.loads(raw.decode("utf-8", "strict"),
                          object_pairs_hook=_unique_pairs,
                          parse_constant=_reject_constant)
    except (ValueError, UnicodeError, RecursionError, TypeError) as exc:
        raise InvalidPacket("invalid packet") from exc
    if type(data) is not dict or set(data) != {"schema", "checks"}:
        raise InvalidPacket("unexpected packet structure")
    if type(data["schema"]) is not int or data["schema"] != 1:
        raise InvalidPacket("unsupported schema")
    checks = data["checks"]
    if type(checks) is not dict or set(checks) != set(GATES):
        raise InvalidPacket("missing or unknown gate")
    if any(type(v) is not str or v not in {"MISSING", "BLOCKED", "SELF_REPORTED"}
           for v in checks.values()):
        raise InvalidPacket("invalid gate status")
    # Stable, self-contained identifiers only. Never reproduce the supplied text.
    return {
        "status": "HOLD",
        "provenance": "SELF_ASSERTED_UNVERIFIED",
        "reason_code": "INDEPENDENT_SOURCE_AND_HUMAN_REVIEW_REQUIRED",
        "needs_attention": [g for g in GATES if checks[g] != "SELF_REPORTED"],
        "self_reported_count": sum(checks[g] == "SELF_REPORTED" for g in GATES),
        **{flag: False for flag in FLAGS},
    }


def main() -> int:
    try:
        # Never consume unbounded stdin; ignore surplus and never echo data.
        raw = sys.stdin.buffer.read(MAX_BYTES + 1)
        result = assess(raw)
    except (InvalidPacket, OSError):
        result = {
            "status": "HOLD",
            "provenance": "UNVERIFIED",
            "reason_code": "INVALID_OR_INCOMPLETE_PACKET",
            "needs_attention": list(GATES),
            "self_reported_count": 0,
            **{flag: False for flag in FLAGS},
        }
    sys.stdout.write(json.dumps(result, separators=(",", ":"), sort_keys=True) + "\n")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
