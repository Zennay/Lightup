"""Structured, network-free document enrichment for Future Security ChangeSets.

Parsers are intentionally conservative. They extract declared OpenAPI operations and
Terraform resource/security-boundary declarations from caller-supplied content,
retain only SHA-256 evidence references plus bounded metadata, and never promote
inferred change signals to verified security effects.
"""

from __future__ import annotations

from dataclasses import replace
from hashlib import sha256
import json
from pathlib import PurePosixPath
import re
from typing import Mapping

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
