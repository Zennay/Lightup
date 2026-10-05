"""Structured, network-free document enrichment for Future Security ChangeSets.

Parsers are intentionally conservative. They extract declared OpenAPI operations and
Terraform resource/security-boundary declarations from caller-supplied content,
retain only SHA-256 evidence references plus bounded metadata, and never promote
inferred change signals to verified security effects.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from typing import Any, Mapping

from .changes import (
    ChangeObject,
    ChangeObjectKind,
    ChangeOperation,
    ChangeSet,
    SemanticChangeSignal,
    SemanticSignalDirection,
    SemanticSignalKind,
    validate_repo_path,
)


_MAX_STRUCTURED_BYTES = 512 * 1024
_HTTP_METHODS = {"get", "put", "post", "delete", "patch", "options", "head", "trace"}
_YAML_METHOD = re.compile(r"^(get|put|post|delete|patch|options|head|trace)\s*:\s*$", re.I)
_TF_BLOCK = re.compile(
    r'^\s*(resource|data|module)\s+"([^"]+)"(?:\s+"([^"]+)")?\s*\{'
)
_TF_ATTRIBUTE = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*=")
_TF_NESTED_BLOCK = re.compile(r"^\s*([A-Za-z_][A-Za-z0-9_]*)\s*\{")

_NETWORK_TOKENS = {
    "ingress",
    "egress",
    "cidr_block",
    "cidr_blocks",
    "source_ranges",
    "source_ranges_ipv6",
    "security_group",
    "security_groups",
    "network_acl",
    "firewall",
    "public_access",
    "publicly_accessible",
}
_IAM_TOKENS = {
    "action",
    "actions",
    "assume_role_policy",
    "binding",
    "bindings",
    "iam",
    "member",
    "members",
    "permission",
    "permissions",
    "policy",
    "principal",
    "principals",
    "role",
    "roles",
}


def _direction_for_operation(operation: ChangeOperation) -> SemanticSignalDirection:
    if operation is ChangeOperation.ADDED:
        return SemanticSignalDirection.ADDED
    if operation is ChangeOperation.REMOVED:
        return SemanticSignalDirection.REMOVED
    return SemanticSignalDirection.MODIFIED


def _signal(
    *,
    path: str,
    kind: SemanticSignalKind,
    direction: SemanticSignalDirection,
    summary: str,
    evidence_ref: str,
    confidence: float = 0.7,
) -> SemanticChangeSignal:
    material = "\x1f".join(
        (path, kind.value, direction.value, summary, evidence_ref)
    ).encode("utf-8")
    return SemanticChangeSignal(
        signal_id=f"signal:{sha256(material).hexdigest()[:24]}",
        object_path=path,
        kind=kind,
        direction=direction,
        summary=summary,
        evidence_refs=(evidence_ref,),
        confidence=confidence,
    )


def _openapi_json_signals(
    *,
    path: str,
    content: str,
    evidence_ref: str,
    direction: SemanticSignalDirection,
) -> tuple[SemanticChangeSignal, ...]:
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("OpenAPI JSON root must be an object")
    paths = parsed.get("paths", {})
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")

    signals: list[SemanticChangeSignal] = []
    for route, operation_map in sorted(paths.items(), key=lambda item: str(item[0])):
        if not isinstance(route, str) or not route.startswith("/"):
            continue
        if not isinstance(operation_map, dict):
            continue
        for method in sorted(operation_map):
            method_name = str(method).lower()
            if method_name not in _HTTP_METHODS:
                continue
            signals.append(
                _signal(
                    path=path,
                    kind=SemanticSignalKind.API_SURFACE,
                    direction=direction,
                    summary=f"OpenAPI operation declared: {method_name.upper()} {route}",
                    evidence_ref=evidence_ref,
                    confidence=0.8,
                )
            )
    return tuple(signals)


def _openapi_yaml_signals(
    *,
    path: str,
    content: str,
    evidence_ref: str,
    direction: SemanticSignalDirection,
) -> tuple[SemanticChangeSignal, ...]:
    """Parse the common indentation-based OpenAPI YAML paths shape.

    This deliberately supports only plain mapping keys. Anchors, aliases, folded
    keys and other advanced YAML constructs remain explicit parser uncertainty.
    """

    lines = content.splitlines()
    paths_indent: int | None = None
    current_route: str | None = None
    route_indent: int | None = None
    signals: list[SemanticChangeSignal] = []

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()

        if paths_indent is None:
            if stripped == "paths:":
                paths_indent = indent
            continue

        if indent <= paths_indent:
            break

        if stripped.startswith("/") and stripped.endswith(":"):
            current_route = stripped[:-1].strip()
            route_indent = indent
            continue

        if current_route is None or route_indent is None or indent <= route_indent:
            continue

        match = _YAML_METHOD.match(stripped)
        if not match:
            continue
        method = match.group(1).upper()
        signals.append(
            _signal(
                path=path,
                kind=SemanticSignalKind.API_SURFACE,
                direction=direction,
                summary=f"OpenAPI operation declared: {method} {current_route}",
                evidence_ref=evidence_ref,
                confidence=0.72,
            )
        )

    if paths_indent is None:
        raise ValueError("OpenAPI YAML paths mapping not found")
    return tuple(signals)


def _terraform_signals(
    *,
    path: str,
    content: str,
    evidence_ref: str,
    direction: SemanticSignalDirection,
) -> tuple[SemanticChangeSignal, ...]:
    signals: list[SemanticChangeSignal] = []
    active_kind: str | None = None
    active_type: str | None = None
    active_name: str | None = None
    active_depth = 0
    network_seen = False
    iam_seen = False

    def flush() -> None:
        nonlocal active_kind, active_type, active_name, active_depth, network_seen, iam_seen
        if active_type is None:
            return
        identity = active_type if active_name is None else f"{active_type}.{active_name}"
        type_lower = active_type.lower()
        network = network_seen or any(token in type_lower for token in _NETWORK_TOKENS)
        iam = iam_seen or any(token in type_lower for token in _IAM_TOKENS)
        if network:
            signals.append(
                _signal(
                    path=path,
                    kind=SemanticSignalKind.NETWORK_BOUNDARY,
                    direction=direction,
                    summary=f"Terraform network-boundary declaration present: {identity}",
                    evidence_ref=evidence_ref,
                    confidence=0.72,
                )
            )
        if iam:
            signals.append(
                _signal(
                    path=path,
                    kind=SemanticSignalKind.IAM_POLICY,
                    direction=direction,
                    summary=f"Terraform IAM/trust declaration present: {identity}",
                    evidence_ref=evidence_ref,
                    confidence=0.72,
                )
            )
        active_kind = active_type = active_name = None
        active_depth = 0
        network_seen = iam_seen = False

    for raw in content.splitlines():
        line = raw.split("#", 1)[0].split("//", 1)[0]
        if not line.strip():
            continue

        if active_type is None:
            match = _TF_BLOCK.match(line)
            if not match:
                continue
            active_kind, active_type, active_name = match.groups()
            active_depth = line.count("{") - line.count("}")
            if active_depth <= 0:
                flush()
            continue

        attribute = _TF_ATTRIBUTE.match(line)
        if attribute:
            key = attribute.group(1).lower()
            network_seen = network_seen or key in _NETWORK_TOKENS
            iam_seen = iam_seen or key in _IAM_TOKENS

        nested = _TF_NESTED_BLOCK.match(line)
        if nested:
            key = nested.group(1).lower()
            network_seen = network_seen or key in _NETWORK_TOKENS
            iam_seen = iam_seen or key in _IAM_TOKENS

        active_depth += line.count("{") - line.count("}")
        if active_depth <= 0:
            flush()

    if active_type is not None:
        raise ValueError("unterminated Terraform block")
    return tuple(signals)


def _updated_object(
    obj: ChangeObject,
    *,
    digest: str,
    parser: str,
    analyzed: bool,
) -> ChangeObject:
    metadata = dict(obj.metadata)
    metadata.update(
        {
            "structured_analyzed": "true" if analyzed else "false",
            "structured_parser": parser,
            "structured_sha256": digest,
        }
    )
    return replace(obj, metadata=tuple(sorted(metadata.items())))


def enrich_changeset_with_structured_documents(
    changeset: ChangeSet,
    documents: Mapping[str, str],
) -> ChangeSet:
    """Add conservative structured-document signals without retaining raw content."""

    changeset.validate()
    by_path = {obj.path: obj for obj in changeset.objects}
    replacements: dict[str, ChangeObject] = {}
    new_signals: list[SemanticChangeSignal] = []
    uncertainties = set(changeset.uncertainties)

    for raw_path, content in sorted(documents.items()):
        path = validate_repo_path(raw_path)
        obj = by_path.get(path)
        if obj is None:
            raise ValueError(f"structured document references unknown change object {path!r}")
        if obj.kind not in {ChangeObjectKind.API_SPEC, ChangeObjectKind.IAC}:
            raise ValueError(f"structured parsing is unsupported for {obj.kind.value} object {path!r}")
        if not isinstance(content, str):
            raise ValueError(f"structured content for {path!r} must be text")

        encoded = content.encode("utf-8")
        digest = sha256(encoded).hexdigest()
        evidence_ref = f"content-sha256:{digest}"
        suffix = PurePosixPath(path.lower()).suffix
        parser = "unsupported"

        if len(encoded) > _MAX_STRUCTURED_BYTES:
            replacements[path] = _updated_object(
                obj,
                digest=digest,
                parser=parser,
                analyzed=False,
            )
            uncertainties.add(f"structured_content_too_large:{path}")
            continue

        direction = _direction_for_operation(obj.operation)
        try:
            if obj.kind is ChangeObjectKind.API_SPEC and suffix == ".json":
                parser = "openapi-json"
                parsed = _openapi_json_signals(
                    path=path,
                    content=content,
                    evidence_ref=evidence_ref,
                    direction=direction,
                )
            elif obj.kind is ChangeObjectKind.API_SPEC and suffix in {".yaml", ".yml"}:
                parser = "openapi-yaml-bounded"
                parsed = _openapi_yaml_signals(
                    path=path,
                    content=content,
                    evidence_ref=evidence_ref,
                    direction=direction,
                )
            elif obj.kind is ChangeObjectKind.IAC and suffix == ".tf":
                parser = "terraform-hcl-bounded"
                parsed = _terraform_signals(
                    path=path,
                    content=content,
                    evidence_ref=evidence_ref,
                    direction=direction,
                )
            else:
                replacements[path] = _updated_object(
                    obj,
                    digest=digest,
                    parser=parser,
                    analyzed=False,
                )
                uncertainties.add(f"structured_parser_unsupported:{path}")
                continue
        except (ValueError, json.JSONDecodeError):
            replacements[path] = _updated_object(
                obj,
                digest=digest,
                parser=parser,
                analyzed=False,
            )
            uncertainties.add(f"structured_parse_failed:{path}")
            continue

        replacements[path] = _updated_object(
            obj,
            digest=digest,
            parser=parser,
            analyzed=True,
        )
        new_signals.extend(parsed)

    objects = tuple(replacements.get(obj.path, obj) for obj in changeset.objects)
    semantic_signals = tuple(
        sorted(changeset.semantic_signals + tuple(new_signals), key=lambda signal: signal.signal_id)
    )
    enriched = replace(
        changeset,
        objects=objects,
        semantic_signals=semantic_signals,
        uncertainties=tuple(sorted(uncertainties)),
    )
    enriched.validate()
    return enriched


@dataclass(frozen=True)
class StructuredDocumentDelta:
    """Caller-supplied base/head document pair for offline delta analysis."""

    base_content: str | None
    head_content: str | None


def _document_digest(content: str | None) -> str | None:
    if content is None:
        return None
    return sha256(content.encode("utf-8")).hexdigest()


def _delta_signal(
    *,
    path: str,
    kind: SemanticSignalKind,
    direction: SemanticSignalDirection,
    summary: str,
    evidence_refs: tuple[str, ...],
    confidence: float,
) -> SemanticChangeSignal:
    refs = tuple(sorted(set(evidence_refs)))
    if not refs:
        raise ValueError("structured delta signals require evidence_refs")
    material = "\x1f".join(
        (path, kind.value, direction.value, summary, *refs)
    ).encode("utf-8")
    return SemanticChangeSignal(
        signal_id=f"signal:{sha256(material).hexdigest()[:24]}",
        object_path=path,
        kind=kind,
        direction=direction,
        summary=summary,
        evidence_refs=refs,
        confidence=confidence,
    )


def _json_fingerprint(value: Any) -> str:
    payload = json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return sha256(payload).hexdigest()


def _openapi_json_delta_model(content: str) -> dict[
    tuple[SemanticSignalKind, str],
    str,
]:
    parsed = json.loads(content)
    if not isinstance(parsed, dict):
        raise ValueError("OpenAPI JSON root must be an object")
    if not isinstance(parsed.get("openapi") or parsed.get("swagger"), str):
        raise ValueError("OpenAPI JSON requires an openapi/swagger version")

    paths = parsed.get("paths", {})
    if paths is None:
        paths = {}
    if not isinstance(paths, dict):
        raise ValueError("OpenAPI paths must be an object")

    model: dict[tuple[SemanticSignalKind, str], str] = {}
    for route, operation_map in paths.items():
        if not isinstance(route, str) or not route.startswith("/"):
            continue
        if not isinstance(operation_map, dict):
            continue
        for method, operation in operation_map.items():
            method_name = str(method).lower()
            if method_name not in _HTTP_METHODS:
                continue
            identity = f"{method_name.upper()} {route}"
            model[(SemanticSignalKind.API_SURFACE, identity)] = _json_fingerprint(operation)
    return model


def _openapi_yaml_delta_model(content: str) -> dict[
    tuple[SemanticSignalKind, str],
    str,
]:
    """Bounded YAML model: operation presence only, never value semantics."""

    lines = content.splitlines()
    paths_indent: int | None = None
    current_route: str | None = None
    route_indent: int | None = None
    model: dict[tuple[SemanticSignalKind, str], str] = {}

    for raw in lines:
        if not raw.strip() or raw.lstrip().startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip(" "))
        stripped = raw.strip()

        if paths_indent is None:
            if stripped == "paths:":
                paths_indent = indent
            continue

        if indent <= paths_indent:
            break

        if stripped.startswith("/") and stripped.endswith(":"):
            current_route = stripped[:-1].strip()
            route_indent = indent
            continue

        if current_route is None or route_indent is None or indent <= route_indent:
            continue
        match = _YAML_METHOD.match(stripped)
        if not match:
            continue
        identity = f"{match.group(1).upper()} {current_route}"
        model[(SemanticSignalKind.API_SURFACE, identity)] = "declared"

    if paths_indent is None:
        raise ValueError("OpenAPI YAML paths mapping not found")
    return model


def _terraform_delta_model(content: str) -> dict[
    tuple[SemanticSignalKind, str],
    str,
]:
    """Fingerprint security-relevant Terraform blocks without retaining values."""

    model: dict[tuple[SemanticSignalKind, str], str] = {}
    active_kind: str | None = None
    active_type: str | None = None
    active_name: str | None = None
    active_depth = 0
    network_seen = False
    iam_seen = False
    block_lines: list[str] = []

    def flush() -> None:
        nonlocal active_kind, active_type, active_name, active_depth
        nonlocal network_seen, iam_seen, block_lines
        if active_kind is None or active_type is None:
            return
        identity = (
            f"{active_kind}.{active_type}"
            if active_name is None
            else f"{active_kind}.{active_type}.{active_name}"
        )
        type_lower = active_type.lower()
        network = network_seen or any(token in type_lower for token in _NETWORK_TOKENS)
        iam = iam_seen or any(token in type_lower for token in _IAM_TOKENS)
        fingerprint = sha256("\n".join(block_lines).encode("utf-8")).hexdigest()
        if network:
            model[(SemanticSignalKind.NETWORK_BOUNDARY, identity)] = fingerprint
        if iam:
            model[(SemanticSignalKind.IAM_POLICY, identity)] = fingerprint

        active_kind = active_type = active_name = None
        active_depth = 0
        network_seen = iam_seen = False
        block_lines = []

    for raw in content.splitlines():
        line = raw.split("#", 1)[0].split("//", 1)[0]
        if not line.strip():
            continue

        if active_type is None:
            match = _TF_BLOCK.match(line)
            if not match:
                continue
            active_kind, active_type, active_name = match.groups()
            active_depth = line.count("{") - line.count("}")
            block_lines = [line.strip()]
            if active_depth <= 0:
                flush()
            continue

        block_lines.append(line.strip())

        attribute = _TF_ATTRIBUTE.match(line)
        if attribute:
            key = attribute.group(1).lower()
            network_seen = network_seen or key in _NETWORK_TOKENS
            iam_seen = iam_seen or key in _IAM_TOKENS

        nested = _TF_NESTED_BLOCK.match(line)
        if nested:
            key = nested.group(1).lower()
            network_seen = network_seen or key in _NETWORK_TOKENS
            iam_seen = iam_seen or key in _IAM_TOKENS

        active_depth += line.count("{") - line.count("}")
        if active_depth <= 0:
            flush()

    if active_type is not None:
        raise ValueError("unterminated Terraform block")
    return model


def _structured_delta_model(
    *,
    obj: ChangeObject,
    path: str,
    content: str,
) -> tuple[str, dict[tuple[SemanticSignalKind, str], str]]:
    suffix = PurePosixPath(path.lower()).suffix
    if obj.kind is ChangeObjectKind.API_SPEC and suffix == ".json":
        return "openapi-json-delta", _openapi_json_delta_model(content)
    if obj.kind is ChangeObjectKind.API_SPEC and suffix in {".yaml", ".yml"}:
        return "openapi-yaml-delta-bounded", _openapi_yaml_delta_model(content)
    if obj.kind is ChangeObjectKind.IAC and suffix == ".tf":
        return "terraform-hcl-delta-bounded", _terraform_delta_model(content)
    raise ValueError(f"structured delta parser unsupported for {path!r}")


def _delta_signals_from_models(
    *,
    path: str,
    before: Mapping[tuple[SemanticSignalKind, str], str],
    after: Mapping[tuple[SemanticSignalKind, str], str],
    base_ref: str | None,
    head_ref: str | None,
) -> tuple[SemanticChangeSignal, ...]:
    signals: list[SemanticChangeSignal] = []
    keys = sorted(
        set(before) | set(after),
        key=lambda item: (item[0].value, item[1]),
    )
    for kind, identity in keys:
        old = before.get((kind, identity))
        new = after.get((kind, identity))
        if old == new:
            continue

        if old is None:
            direction = SemanticSignalDirection.ADDED
            refs = tuple(ref for ref in (head_ref,) if ref)
        elif new is None:
            direction = SemanticSignalDirection.REMOVED
            refs = tuple(ref for ref in (base_ref,) if ref)
        else:
            direction = SemanticSignalDirection.MODIFIED
            refs = tuple(ref for ref in (base_ref, head_ref) if ref)

        if kind is SemanticSignalKind.API_SURFACE:
            subject = "OpenAPI operation"
            confidence = 0.82
        elif kind is SemanticSignalKind.NETWORK_BOUNDARY:
            subject = "Terraform network-boundary declaration"
            confidence = 0.78
        elif kind is SemanticSignalKind.IAM_POLICY:
            subject = "Terraform IAM/trust declaration"
            confidence = 0.78
        else:
            subject = "Structured security declaration"
            confidence = 0.72

        signals.append(
            _delta_signal(
                path=path,
                kind=kind,
                direction=direction,
                summary=f"{subject} {direction.value}: {identity}",
                evidence_refs=refs,
                confidence=confidence,
            )
        )
    return tuple(signals)


def enrich_changeset_with_structured_deltas(
    changeset: ChangeSet,
    deltas: Mapping[str, StructuredDocumentDelta],
) -> ChangeSet:
    """Compare base/head documents and add only actual inferred deltas.

    Raw content is never retained. Identical supported documents emit no new
    signals. Parse failures and oversized inputs become explicit uncertainty.
    """

    changeset.validate()
    by_path = {obj.path: obj for obj in changeset.objects}
    replacements: dict[str, ChangeObject] = {}
    additions: list[SemanticChangeSignal] = []
    uncertainties = set(changeset.uncertainties)

    for raw_path, delta in sorted(deltas.items()):
        path = validate_repo_path(raw_path)
        obj = by_path.get(path)
        if obj is None:
            raise ValueError(f"structured delta references unknown change object {path!r}")
        if not isinstance(delta, StructuredDocumentDelta):
            raise ValueError(f"structured delta for {path!r} has invalid type")

        base = delta.base_content
        head = delta.head_content
        if base is None and head is None:
            uncertainties.add(f"structured_delta_missing_both:{path}")
            continue
        for content in (base, head):
            if content is not None and not isinstance(content, str):
                raise ValueError(f"structured delta content for {path!r} must be text")

        base_digest = _document_digest(base)
        head_digest = _document_digest(head)
        base_ref = f"content-sha256:{base_digest}" if base_digest else None
        head_ref = f"content-sha256:{head_digest}" if head_digest else None

        too_large = any(
            content is not None and len(content.encode("utf-8")) > _MAX_STRUCTURED_BYTES
            for content in (base, head)
        )
        metadata = dict(obj.metadata)
        metadata.update(
            {
                "structured_delta_analyzed": "false" if too_large else "true",
            }
        )
        if base_digest:
            metadata["structured_base_sha256"] = base_digest
        if head_digest:
            metadata["structured_head_sha256"] = head_digest

        if too_large:
            metadata["structured_delta_parser"] = "unsupported-size"
            replacements[path] = replace(obj, metadata=tuple(sorted(metadata.items())))
            uncertainties.add(f"structured_delta_too_large:{path}")
            continue

        try:
            if base is None:
                parser, before = (
                    _structured_delta_model(obj=obj, path=path, content=head)
                    if head is not None
                    else ("unknown", {})
                )
                before = {}
            else:
                parser, before = _structured_delta_model(obj=obj, path=path, content=base)

            if head is None:
                if base is None:
                    after = {}
                else:
                    _parser_check, after = parser, {}
            else:
                parser_head, after = _structured_delta_model(
                    obj=obj,
                    path=path,
                    content=head,
                )
                if base is not None and parser_head != parser:
                    raise ValueError("base/head structured parser mismatch")
                parser = parser_head
        except (ValueError, json.JSONDecodeError):
            metadata["structured_delta_analyzed"] = "false"
            metadata["structured_delta_parser"] = "parse-failed"
            replacements[path] = replace(obj, metadata=tuple(sorted(metadata.items())))
            uncertainties.add(f"structured_delta_parse_failed:{path}")
            continue

        metadata["structured_delta_parser"] = parser
        replacements[path] = replace(obj, metadata=tuple(sorted(metadata.items())))
        additions.extend(
            _delta_signals_from_models(
                path=path,
                before=before,
                after=after,
                base_ref=base_ref,
                head_ref=head_ref,
            )
        )

    objects = tuple(replacements.get(obj.path, obj) for obj in changeset.objects)
    by_signal_id = {
        signal.signal_id: signal
        for signal in (*changeset.semantic_signals, *additions)
    }
    enriched = replace(
        changeset,
        objects=objects,
        semantic_signals=tuple(
            sorted(by_signal_id.values(), key=lambda signal: signal.signal_id)
        ),
        uncertainties=tuple(sorted(uncertainties)),
    )
    enriched.validate()
    return enriched
