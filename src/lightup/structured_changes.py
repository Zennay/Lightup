"""Structured, offline change parsers for Future Security.

These parsers compare supplied base/head documents. They never fetch data,
execute target code, or grant authorization. Raw documents are not retained:
ChangeSets receive only bounded metadata, SHA-256 content references, and
conservative inferred semantic signals.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from typing import Any, Mapping

from .changes import (
    ChangeObject,
    ChangeObjectKind,
    ChangeSet,
    SemanticChangeSignal,
    SemanticSignalDirection,
    SemanticSignalKind,
    validate_repo_path,
)
from .twin import FactProvenance


_MAX_DOCUMENT_BYTES = 512 * 1024
_MAX_STRUCTURED_SIGNALS = 128
_OPENAPI_METHODS = {
    "get",
    "put",
    "post",
    "delete",
    "options",
    "head",
    "patch",
    "trace",
}

_TERRAFORM_NETWORK_KEYS = {
    "ingress",
    "egress",
    "cidr",
    "cidr_block",
    "cidr_blocks",
    "ipv6_cidr_block",
    "ipv6_cidr_blocks",
    "source_ranges",
    "destination_ranges",
    "security_group",
    "security_groups",
    "network_policy",
    "network_policies",
    "public_access",
    "public_access_block",
}
_TERRAFORM_IAM_KEYS = {
    "principal",
    "principals",
    "permission",
    "permissions",
    "action",
    "actions",
    "policy",
    "policies",
    "role",
    "roles",
    "assume_role_policy",
    "managed_policy_arns",
}
_TERRAFORM_SECURITY_CONFIG_KEYS = {
    "tls",
    "ssl",
    "encryption",
    "encrypted",
    "kms_key_id",
    "force_ssl",
    "https_only",
}


class StructuredContentError(ValueError):
    """Raised internally for unsupported or malformed structured content."""


def _content_digest(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def _evidence_ref(digest: str) -> str:
    return f"content-sha256:{digest}"


def _parse_json_document(content: str, *, path: str) -> Any:
    if not isinstance(content, str):
        raise StructuredContentError(f"structured content for {path!r} must be text")
    encoded = content.encode("utf-8")
    if len(encoded) > _MAX_DOCUMENT_BYTES:
        raise StructuredContentError(f"structured content too large for {path!r}")
    try:
        return json.loads(content)
    except json.JSONDecodeError as exc:
        raise StructuredContentError(
            f"invalid JSON for {path!r}: line {exc.lineno} column {exc.colno}"
        ) from exc


def _stable_value_digest(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _signal_id(
    *,
    path: str,
    kind: SemanticSignalKind,
    direction: SemanticSignalDirection,
    summary: str,
    evidence_refs: tuple[str, ...],
) -> str:
    material = "\x1f".join(
        (
            path,
            kind.value,
            direction.value,
            summary,
            *evidence_refs,
        )
    ).encode("utf-8")
    return f"signal:{sha256(material).hexdigest()[:24]}"


def _make_signal(
    *,
    path: str,
    kind: SemanticSignalKind,
    direction: SemanticSignalDirection,
    summary: str,
    evidence_refs: tuple[str, ...],
    confidence: float,
) -> SemanticChangeSignal:
    refs = tuple(sorted(set(evidence_refs)))
    return SemanticChangeSignal(
        signal_id=_signal_id(
            path=path,
            kind=kind,
            direction=direction,
            summary=summary,
            evidence_refs=refs,
        ),
        object_path=path,
        kind=kind,
        direction=direction,
        summary=summary,
        evidence_refs=refs,
        confidence=confidence,
        provenance=FactProvenance.INFERRED,
    )


def _merge_signals(
    existing: tuple[SemanticChangeSignal, ...],
    additions: tuple[SemanticChangeSignal, ...],
) -> tuple[SemanticChangeSignal, ...]:
    merged: dict[
        tuple[str, str, str, str],
        SemanticChangeSignal,
    ] = {}

    for signal in (*existing, *additions):
        signal.validate()
        key = (
            signal.object_path,
            signal.kind.value,
            signal.direction.value,
            signal.summary,
        )
        previous = merged.get(key)
        if previous is None:
            merged[key] = signal
            continue

        refs = tuple(sorted(set((*previous.evidence_refs, *signal.evidence_refs))))
        confidence = max(previous.confidence, signal.confidence)
        merged[key] = _make_signal(
            path=signal.object_path,
            kind=signal.kind,
            direction=signal.direction,
            summary=signal.summary,
            evidence_refs=refs,
            confidence=confidence,
        )

    return tuple(
        sorted(
            merged.values(),
            key=lambda item: (
                item.object_path,
                item.kind.value,
                item.direction.value,
                item.summary,
            ),
        )
    )


def _openapi_operations(document: Any) -> set[tuple[str, str]]:
    if not isinstance(document, Mapping):
        raise StructuredContentError("OpenAPI document root must be an object")
    if not isinstance(document.get("openapi") or document.get("swagger"), str):
        raise StructuredContentError("OpenAPI document requires openapi/swagger version")

    paths = document.get("paths", {})
    if paths is None:
        paths = {}
    if not isinstance(paths, Mapping):
        raise StructuredContentError("OpenAPI paths must be an object")

    operations: set[tuple[str, str]] = set()
    for raw_path, raw_item in paths.items():
        if not isinstance(raw_path, str) or not raw_path.startswith("/"):
            continue
        if not isinstance(raw_item, Mapping):
            continue
        for raw_method in raw_item:
            if not isinstance(raw_method, str):
                continue
            method = raw_method.lower()
            if method in _OPENAPI_METHODS:
                operations.add((method.upper(), raw_path))
    return operations


def _openapi_signals(
    *,
    path: str,
    base_document: Any,
    head_document: Any,
    base_ref: str | None,
    head_ref: str | None,
) -> tuple[SemanticChangeSignal, ...]:
    before = _openapi_operations(base_document)
    after = _openapi_operations(head_document)
    signals: list[SemanticChangeSignal] = []

    for method, route in sorted(after - before):
        if head_ref is None:
            continue
        signals.append(
            _make_signal(
                path=path,
                kind=SemanticSignalKind.API_SURFACE,
                direction=SemanticSignalDirection.ADDED,
                summary=f"OpenAPI operation added: {method} {route}",
                evidence_refs=(head_ref,),
                confidence=0.78,
            )
        )

    for method, route in sorted(before - after):
        if base_ref is None:
            continue
        signals.append(
            _make_signal(
                path=path,
                kind=SemanticSignalKind.API_SURFACE,
                direction=SemanticSignalDirection.REMOVED,
                summary=f"OpenAPI operation removed: {method} {route}",
                evidence_refs=(base_ref,),
                confidence=0.78,
            )
        )

    return tuple(signals[:_MAX_STRUCTURED_SIGNALS])


def _terraform_key_kind(key: str) -> SemanticSignalKind | None:
    normalized = key.lower()
    if normalized in _TERRAFORM_NETWORK_KEYS:
        return SemanticSignalKind.NETWORK_BOUNDARY
    if normalized in _TERRAFORM_IAM_KEYS:
        return SemanticSignalKind.IAM_POLICY
    if normalized in _TERRAFORM_SECURITY_CONFIG_KEYS:
        return SemanticSignalKind.SECURITY_CONFIG
    return None


def _terraform_security_fields(document: Any) -> dict[
    tuple[SemanticSignalKind, str],
    str,
]:
    if not isinstance(document, Mapping):
        raise StructuredContentError("Terraform JSON root must be an object")

    resources = document.get("resource", {})
    if resources is None:
        resources = {}
    if not isinstance(resources, Mapping):
        raise StructuredContentError("Terraform JSON resource must be an object")

    fields: dict[tuple[SemanticSignalKind, str], str] = {}

    def walk(value: Any, prefix: tuple[str, ...]) -> None:
        if isinstance(value, Mapping):
            for raw_key, child in value.items():
                if not isinstance(raw_key, str):
                    continue
                path_parts = (*prefix, raw_key)
                kind = _terraform_key_kind(raw_key)
                if kind is not None:
                    fields[(kind, ".".join(path_parts))] = _stable_value_digest(child)
                walk(child, path_parts)
        elif isinstance(value, list):
            for index, child in enumerate(value):
                walk(child, (*prefix, str(index)))

    for resource_type, names in resources.items():
        if not isinstance(resource_type, str) or not isinstance(names, Mapping):
            continue
        for resource_name, body in names.items():
            if not isinstance(resource_name, str):
                continue
            walk(body, ("resource", resource_type, resource_name))

    return fields


def _terraform_signals(
    *,
    path: str,
    base_document: Any,
    head_document: Any,
    base_ref: str | None,
    head_ref: str | None,
) -> tuple[SemanticChangeSignal, ...]:
    before = _terraform_security_fields(base_document)
    after = _terraform_security_fields(head_document)
    signals: list[SemanticChangeSignal] = []

    keys = sorted(
        set(before) | set(after),
        key=lambda item: (item[0].value, item[1]),
    )
    for key in keys:
        kind, field_path = key
        before_digest = before.get(key)
        after_digest = after.get(key)
        if before_digest == after_digest:
            continue

        if before_digest is None:
            direction = SemanticSignalDirection.ADDED
            refs = (head_ref,) if head_ref else ()
        elif after_digest is None:
            direction = SemanticSignalDirection.REMOVED
            refs = (base_ref,) if base_ref else ()
        else:
            direction = SemanticSignalDirection.MODIFIED
            refs = tuple(ref for ref in (base_ref, head_ref) if ref)

        if not refs:
            continue
        label = {
            SemanticSignalKind.NETWORK_BOUNDARY: "network boundary",
            SemanticSignalKind.IAM_POLICY: "IAM/trust",
            SemanticSignalKind.SECURITY_CONFIG: "security configuration",
        }[kind]
        signals.append(
            _make_signal(
                path=path,
                kind=kind,
                direction=direction,
                summary=f"Terraform {label} field changed: {field_path}",
                evidence_refs=refs,
                confidence=0.76,
            )
        )
        if len(signals) >= _MAX_STRUCTURED_SIGNALS:
            break

    return tuple(signals)


def _replace_object_metadata(
    change_object: ChangeObject,
    *,
    parser: str,
    base_digest: str | None,
    head_digest: str | None,
    analyzed: bool,
) -> ChangeObject:
    metadata = dict(change_object.metadata)
    metadata["structured_parser"] = parser
    metadata["structured_analyzed"] = "true" if analyzed else "false"
    if base_digest is not None:
        metadata["base_content_sha256"] = base_digest
    if head_digest is not None:
        metadata["head_content_sha256"] = head_digest
    return replace(change_object, metadata=tuple(sorted(metadata.items())))


def enrich_changeset_with_structured_content(
    changeset: ChangeSet,
    *,
    path: str,
    base_content: str | None,
    head_content: str | None,
) -> ChangeSet:
    """Enrich one changed object from supplied structured base/head content.

    None represents an absent side of an added/removed file. Malformed,
    unsupported, or oversized content is recorded as explicit uncertainty
    instead of producing speculative signals.
    """

    changeset.validate()
    normalized_path = validate_repo_path(path)
    matching = [obj for obj in changeset.objects if obj.path == normalized_path]
    if len(matching) != 1:
        raise ValueError(f"ChangeSet has no unique object for {normalized_path!r}")
    change_object = matching[0]

    lower = normalized_path.lower()
    if change_object.kind is ChangeObjectKind.API_SPEC and lower.endswith(".json"):
        parser = "openapi_json"
    elif (
        change_object.kind is ChangeObjectKind.IAC
        and lower.endswith((".tf.json", ".tfvars.json"))
    ):
        parser = "terraform_json"
    else:
        uncertainty = f"structured_parser_unsupported:{normalized_path}"
        return replace(
            changeset,
            uncertainties=tuple(sorted(set((*changeset.uncertainties, uncertainty)))),
        )

    base_digest = _content_digest(base_content) if base_content is not None else None
    head_digest = _content_digest(head_content) if head_content is not None else None
    base_ref = _evidence_ref(base_digest) if base_digest else None
    head_ref = _evidence_ref(head_digest) if head_digest else None

    try:
        if base_content is None:
            base_document: Any = {
                "openapi": "3.0.0",
                "paths": {},
            } if parser == "openapi_json" else {"resource": {}}
        else:
            base_document = _parse_json_document(base_content, path=normalized_path)

        if head_content is None:
            head_document: Any = {
                "openapi": "3.0.0",
                "paths": {},
            } if parser == "openapi_json" else {"resource": {}}
        else:
            head_document = _parse_json_document(head_content, path=normalized_path)

        if parser == "openapi_json":
            additions = _openapi_signals(
                path=normalized_path,
                base_document=base_document,
                head_document=head_document,
                base_ref=base_ref,
                head_ref=head_ref,
            )
        else:
            additions = _terraform_signals(
                path=normalized_path,
                base_document=base_document,
                head_document=head_document,
                base_ref=base_ref,
                head_ref=head_ref,
            )
    except StructuredContentError as exc:
        message = str(exc)
        reason = "too_large" if "too large" in message else "invalid"
        uncertainty = f"structured_content_{reason}:{normalized_path}"
        updated_object = _replace_object_metadata(
            change_object,
            parser=parser,
            base_digest=base_digest,
            head_digest=head_digest,
            analyzed=False,
        )
        updated_objects = tuple(
            updated_object if obj.path == normalized_path else obj
            for obj in changeset.objects
        )
        result = replace(
            changeset,
            objects=updated_objects,
            uncertainties=tuple(sorted(set((*changeset.uncertainties, uncertainty)))),
        )
        result.validate()
        return result

    updated_object = _replace_object_metadata(
        change_object,
        parser=parser,
        base_digest=base_digest,
        head_digest=head_digest,
        analyzed=True,
    )
    updated_objects = tuple(
        updated_object if obj.path == normalized_path else obj
        for obj in changeset.objects
    )
    result = replace(
        changeset,
        objects=updated_objects,
        semantic_signals=_merge_signals(changeset.semantic_signals, additions),
    )
    result.validate()
    return result
