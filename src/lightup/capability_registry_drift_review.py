"""Offline, non-authorizing capability registry drift review.

This module never grants execution or interprets a human approval. Feed it only
local, fictional or otherwise authorized metadata snapshots; no target I/O.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_STATES = frozenset({"planning", "lab_only", "disabled"})
_MAX_CAPABILITIES = 128
_MAX_PAYLOAD_BYTES = 32_768


@dataclass(frozen=True)
class RegistryReview:
    status: str
    reason: str
    baseline_fingerprint: str | None
    candidate_fingerprint: str | None
    changed_capabilities: tuple[str, ...]
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "baseline_fingerprint": self.baseline_fingerprint,
            "candidate_fingerprint": self.candidate_fingerprint,
            "changed_capabilities": list(self.changed_capabilities),
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def _reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    output: dict[str, Any] = {}
    for key, value in pairs:
        if key in output:
            raise ValueError("duplicate manifest JSON key")
        output[key] = value
    return output


def _decode_manifest(raw: bytes) -> dict[str, tuple[str, bool]]:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_PAYLOAD_BYTES:
        raise ValueError("manifest must be bounded bytes")
    # Canonical manifests contain exactly one list and at most 128 entry objects.
    # Bound structural nesting before invoking the JSON decoder on hostile input.
    if raw.count(b"[") != 1 or raw.count(b"{") > _MAX_CAPABILITIES + 1:
        raise ValueError("invalid manifest structure")
    try:
        obj = json.loads(raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
                         parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid manifest JSON") from exc
    if type(obj) is not dict or set(obj) != {"capabilities"}:
        raise ValueError("manifest envelope must contain capabilities only")
    records = obj["capabilities"]
    if type(records) is not list or not 1 <= len(records) <= _MAX_CAPABILITIES:
        raise ValueError("invalid capability count")
    output: dict[str, tuple[str, bool]] = {}
    for record in records:
        if type(record) is not dict or set(record) != {"capability_id", "state", "requires_explicit_activation"}:
            raise ValueError("invalid capability fields")
        ident = record["capability_id"]
        state = record["state"]
        activation = record["requires_explicit_activation"]
        if type(ident) is not str or len(ident) > 64 or _ID.fullmatch(ident) is None:
            raise ValueError("noncanonical capability identifier")
        if type(state) is not str or state not in _STATES:
            raise ValueError("invalid capability state")
        if type(activation) is not bool:
            raise ValueError("noncanonical explicit-activation flag")
        if ident in output:
            raise ValueError("duplicate capability identifier")
        output[ident] = (state, activation)
    return output


def _fingerprint(records: dict[str, tuple[str, bool]]) -> str:
    canonical = [
        {"capability_id": name, "state": records[name][0], "requires_explicit_activation": records[name][1]}
        for name in sorted(records)
    ]
    blob = json.dumps({"capabilities": canonical}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(blob.encode("ascii")).hexdigest()


def review_capability_registry_drift(baseline: bytes, candidate: bytes) -> RegistryReview:
    """Fail closed. Even REVIEW_ONLY conveys no authority of any kind."""
    try:
        before = _decode_manifest(baseline)
        after = _decode_manifest(candidate)
    except (ValueError, TypeError, OverflowError, RecursionError):
        return RegistryReview("HOLD", "invalid_manifest", None, None, ())
    changed = tuple(sorted(k for k in before.keys() | after.keys() if before.get(k) != after.get(k)))
    return RegistryReview(
        "HOLD" if changed else "REVIEW_ONLY",
        "registry_drift_requires_independent_review" if changed else "identical_metadata_only",
        _fingerprint(before), _fingerprint(after), changed,
    )
