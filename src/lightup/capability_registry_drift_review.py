"""Offline, non-authorizing capability registry drift review.

Strict local metadata comparison only: no consent, permit, deployment, or target I/O.
Both legacy three-field and current five-field manifests fail closed on drift.
"""
from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from hashlib import sha256
from typing import Any

_ID = re.compile(r"[a-z][a-z0-9]*(?:-[a-z0-9]+)*\Z", re.ASCII)
_STATES = frozenset({"planning", "lab_only", "disabled"})
_MAX_CAPABILITIES = 128
_MAX_PAYLOAD_BYTES = 32_768
_LEGACY_FIELDS = frozenset({"capability_id", "state", "requires_explicit_activation"})
_FULL_FIELDS = _LEGACY_FIELDS | {"name", "description"}
RegistryFields = tuple[str, bool, str | None, str | None]


@dataclass(frozen=True)
class RegistryReview:
    status: str
    reason: str
    baseline_fingerprint: str | None
    candidate_fingerprint: str | None
    changed_capabilities: tuple[str, ...]
    changed_fields: tuple[tuple[str, tuple[str, ...]], ...] = ()
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
            "changed_fields": {name: list(fields) for name, fields in self.changed_fields},
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


def _shape_gate(raw: bytes) -> None:
    """Bound JSON depth without counting punctuation inside quoted strings."""
    inside_string = False
    escaped = False
    depth = 0
    objects = 0
    arrays = 0
    for byte in raw:
        if inside_string:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                inside_string = False
        elif byte == 34:
            inside_string = True
        elif byte in (123, 91):
            depth += 1
            if depth > 3:
                raise ValueError("nested manifest structure")
            if byte == 123:
                objects += 1
            else:
                arrays += 1
            if objects > _MAX_CAPABILITIES + 1 or arrays > 1:
                raise ValueError("invalid manifest structure")
        elif byte in (125, 93):
            depth -= 1
            if depth < 0:
                raise ValueError("unbalanced manifest structure")
    if depth != 0 or inside_string or arrays != 1 or objects < 2:
        raise ValueError("invalid manifest structure")


def _semantic_text(value: object, limit: int) -> str:
    if type(value) is not str or not 1 <= len(value) <= limit or value.strip() != value:
        raise ValueError("invalid capability text metadata")
    if unicodedata.normalize("NFC", value) != value:
        raise ValueError("noncanonical Unicode capability text")
    if any(unicodedata.category(ch).startswith("C") or (ch.isspace() and ch != " ") for ch in value):
        raise ValueError("unsafe capability text metadata")
    return value


def _decode_manifest(raw: bytes) -> dict[str, RegistryFields]:
    if type(raw) is not bytes or not 1 <= len(raw) <= _MAX_PAYLOAD_BYTES:
        raise ValueError("manifest must be bounded bytes")
    _shape_gate(raw)
    try:
        obj = json.loads(
            raw.decode("utf-8"),
            object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")),
        )
    except (UnicodeError, json.JSONDecodeError, RecursionError) as exc:
        raise ValueError("invalid manifest JSON") from exc
    if type(obj) is not dict or set(obj) != {"capabilities"}:
        raise ValueError("manifest envelope must contain capabilities only")
    records = obj["capabilities"]
    if type(records) is not list or not 1 <= len(records) <= _MAX_CAPABILITIES:
        raise ValueError("invalid capability count")
    output: dict[str, RegistryFields] = {}
    for record in records:
        if type(record) is not dict or frozenset(record) not in (_LEGACY_FIELDS, _FULL_FIELDS):
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
        name, description = None, None
        if "name" in record:
            name = _semantic_text(record["name"], 128)
            description = _semantic_text(record["description"], 512)
        output[ident] = (state, activation, name, description)
    return output


def _fingerprint(records: dict[str, RegistryFields]) -> str:
    canonical: list[dict[str, object]] = []
    for ident in sorted(records):
        state, activation, name, description = records[ident]
        entry: dict[str, object] = {
            "capability_id": ident,
            "state": state,
            "requires_explicit_activation": activation,
        }
        if name is not None:
            entry["name"] = name
            entry["description"] = description
        canonical.append(entry)
    blob = json.dumps({"capabilities": canonical}, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return "sha256:" + sha256(blob.encode("ascii")).hexdigest()


def review_capability_registry_drift(baseline: bytes, candidate: bytes) -> RegistryReview:
    """Fail closed. Even REVIEW_ONLY conveys no authority of any kind."""
    try:
        before = _decode_manifest(baseline)
        after = _decode_manifest(candidate)
    except (ValueError, TypeError, OverflowError, RecursionError):
        return RegistryReview("HOLD", "invalid_manifest", None, None, ())
    field_names = ("state", "requires_explicit_activation", "name", "description")
    change_details: list[tuple[str, tuple[str, ...]]] = []
    for capability_id in sorted(before.keys() | after.keys()):
        if capability_id not in before:
            fields = ("added",)
        elif capability_id not in after:
            fields = ("removed",)
        else:
            original, proposed = before[capability_id], after[capability_id]
            fields = tuple(field_names[index] for index in range(4) if original[index] != proposed[index])
        if fields:
            change_details.append((capability_id, fields))
    changed = tuple(capability_id for capability_id, _ in change_details)
    return RegistryReview(
        "HOLD" if changed else "REVIEW_ONLY",
        "registry_drift_requires_independent_review" if changed else "identical_metadata_only",
        _fingerprint(before), _fingerprint(after), changed,
        changed_fields=tuple(change_details),
    )
