"""Deterministic GitHub PR/commit adapters for ChangeSet ingestion.

This module performs no network I/O. Callers supply normalized GitHub compare
file records. Optional unified-diff patches are analyzed transiently: LightUp
stores only a digest plus conservative inferred signals, never the raw patch.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath
import re
from typing import Any, Iterable, Mapping

from .changes import (
    ChangeObject,
    ChangeObjectKind,
    ChangeOperation,
    ChangeSet,
    ChangeSourceKind,
    SemanticChangeSignal,
    SemanticSignalDirection,
    SemanticSignalKind,
    validate_repo_path,
)


_STATUS_MAP = {
    "added": ChangeOperation.ADDED,
    "modified": ChangeOperation.MODIFIED,
    "removed": ChangeOperation.REMOVED,
    "renamed": ChangeOperation.RENAMED,
    "copied": ChangeOperation.COPIED,
    "changed": ChangeOperation.CHANGED,
}

_CODE_SUFFIXES = {
    ".py", ".js", ".jsx", ".ts", ".tsx", ".go", ".rs", ".java", ".kt",
    ".kts", ".rb", ".php", ".cs", ".c", ".h", ".cpp", ".hpp", ".swift",
}
_CONFIG_SUFFIXES = {".json", ".yaml", ".yml", ".toml", ".ini", ".cfg", ".conf"}
_API_NAMES = {
    "openapi.json", "openapi.yaml", "openapi.yml",
    "swagger.json", "swagger.yaml", "swagger.yml",
}
_IAC_SUFFIXES = {".tf", ".tfvars"}
_MAX_PATCH_BYTES = 128 * 1024
_MAX_SIGNALS_PER_OBJECT = 32

_YAML_ROUTE = re.compile(r"^\s*(/[^:\s]+)\s*:\s*$")
_JSON_ROUTE = re.compile(r'^\s*"(/[^"]+)"\s*:\s*[{[]?\s*$')
_GRAPHQL_DECL = re.compile(
    r"^\s*(?:extend\s+)?(?:type|input|interface|enum|union|scalar)\s+"
    r"([A-Za-z_][A-Za-z0-9_]*)\b"
)

_IAM_KEYWORDS = (
    ("principal", "principal/trust"),
    ("permission", "permission"),
    ("policy", "policy"),
    ("action", "action"),
    ("role", "role"),
)
_NETWORK_KEYWORDS = (
    ("ingress", "ingress"),
    ("egress", "egress"),
    ("cidr", "CIDR"),
    ("security_group", "security group"),
    ("securitygroup", "security group"),
    ("network_policy", "network policy"),
    ("networkpolicy", "network policy"),
    ("public_access", "public access"),
    ("publicaccess", "public access"),
)
_CONFIG_KEYWORDS = (
    ("allowed_origin", "CORS/origin control"),
    ("trusted_host", "trusted-host control"),
    ("samesite", "cookie/session control"),
    ("httponly", "cookie/session control"),
    ("cookie_secure", "cookie/session control"),
    ("authentication", "authentication control"),
    ("authorization", "authorization control"),
    ("cors", "CORS/origin control"),
    ("tls", "TLS/transport control"),
    ("ssl", "TLS/transport control"),
    ("debug", "debug/exposure control"),
    ("listen", "network binding"),
    ("bind", "network binding"),
    ("forwarded", "proxy/header trust"),
)


def classify_repository_path(path: str) -> ChangeObjectKind:
    path = validate_repo_path(path)
    lower = path.lower()
    pure = PurePosixPath(lower)
    name = pure.name
    suffix = pure.suffix
    parts = set(pure.parts)

    if lower.startswith(".github/workflows/"):
        return ChangeObjectKind.CI
    if name in _API_NAMES or suffix in {".graphql", ".gql"}:
        return ChangeObjectKind.API_SPEC
    if suffix in _IAC_SUFFIXES or parts.intersection(
        {"terraform", "pulumi", "cloudformation", "kubernetes", "k8s", "helm"}
    ):
        return ChangeObjectKind.IAC
    if parts.intersection({"iam", "rbac"}) or name.startswith(("iam-", "rbac-")):
        return ChangeObjectKind.IAM
    if lower.startswith(("tests/", "test/")) or name.startswith("test_"):
        return ChangeObjectKind.TEST
    if lower.startswith(("docs/", "doc/")) or suffix in {".md", ".rst"}:
        return ChangeObjectKind.DOC
    if (
        suffix in _CONFIG_SUFFIXES
        or name in {"dockerfile", "compose.yml", "compose.yaml"}
        or name.endswith((".service", ".socket", ".timer"))
    ):
        return ChangeObjectKind.CONFIG
    if suffix in _CODE_SUFFIXES:
        return ChangeObjectKind.SOURCE
    return ChangeObjectKind.OTHER


def _nonnegative_int(value: Any, field_name: str, path: str) -> tuple[int, str | None]:
    if value is None:
        return 0, f"missing_{field_name}:{path}"
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{field_name} for {path!r} must be a non-negative integer")
    return value, None


def _signal(
    *,
    path: str,
    kind: SemanticSignalKind,
    direction: SemanticSignalDirection,
    summary: str,
    evidence_ref: str,
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
    )


def _changed_patch_lines(
    patch: str,
) -> Iterable[tuple[SemanticSignalDirection, str]]:
    for raw_line in patch.splitlines():
        if raw_line.startswith(("+++", "---", "@@")):
            continue
        if raw_line.startswith("+"):
            yield SemanticSignalDirection.ADDED, raw_line[1:]
        elif raw_line.startswith("-"):
            yield SemanticSignalDirection.REMOVED, raw_line[1:]


def _semantic_signals(
    *,
    path: str,
    kind: ChangeObjectKind,
    patch: str,
    evidence_ref: str,
) -> tuple[SemanticChangeSignal, ...]:
    signals: dict[tuple[str, str, str], SemanticChangeSignal] = {}

    def add(
        signal_kind: SemanticSignalKind,
        direction: SemanticSignalDirection,
        summary: str,
    ) -> None:
        key = (signal_kind.value, direction.value, summary)
        if key in signals or len(signals) >= _MAX_SIGNALS_PER_OBJECT:
            return
        signals[key] = _signal(
            path=path,
            kind=signal_kind,
            direction=direction,
            summary=summary,
            evidence_ref=evidence_ref,
        )

    for direction, line in _changed_patch_lines(patch):
        stripped = line.strip()
        lower = stripped.lower()
        if not stripped:
            continue

        if kind is ChangeObjectKind.API_SPEC:
            match = _YAML_ROUTE.match(stripped) or _JSON_ROUTE.match(stripped)
            if match:
                route = match.group(1)
                add(
                    SemanticSignalKind.API_SURFACE,
                    direction,
                    f"API route declaration changed: {route}",
                )
                continue
            gql = _GRAPHQL_DECL.match(stripped)
            if gql:
                add(
                    SemanticSignalKind.API_SURFACE,
                    direction,
                    f"API schema declaration changed: {gql.group(1)}",
                )

        if kind in {ChangeObjectKind.IAC, ChangeObjectKind.IAM}:
            for needle, label in _IAM_KEYWORDS:
                if needle in lower:
                    add(
                        SemanticSignalKind.IAM_POLICY,
                        direction,
                        f"IAM/trust declaration changed ({label})",
                    )
            for needle, label in _NETWORK_KEYWORDS:
                if needle in lower:
                    add(
                        SemanticSignalKind.NETWORK_BOUNDARY,
                        direction,
                        f"Infrastructure boundary declaration changed ({label})",
                    )

        if kind is ChangeObjectKind.CONFIG:
            for needle, label in _CONFIG_KEYWORDS:
                if needle in lower:
                    add(
                        SemanticSignalKind.SECURITY_CONFIG,
                        direction,
                        f"Security-sensitive configuration changed ({label})",
                    )

    return tuple(sorted(signals.values(), key=lambda signal: signal.signal_id))


def _patch_context(
    *,
    path: str,
    kind: ChangeObjectKind,
    raw_patch: Any,
) -> tuple[tuple[tuple[str, str], ...], tuple[SemanticChangeSignal, ...], tuple[str, ...]]:
    if raw_patch is None:
        return (), (), (f"patch_content_missing:{path}",)
    if not isinstance(raw_patch, str):
        raise ValueError(f"patch for {path!r} must be text")

    encoded = raw_patch.encode("utf-8")
    digest = sha256(encoded).hexdigest()
    evidence_ref = f"patch-sha256:{digest}"
    metadata = (
        ("patch_bytes", str(len(encoded))),
        ("patch_sha256", digest),
    )

    if len(encoded) > _MAX_PATCH_BYTES:
        return (
            metadata + (("patch_analyzed", "false"),),
            (),
            (f"patch_content_too_large:{path}",),
        )

    signals = _semantic_signals(
        path=path,
        kind=kind,
        patch=raw_patch,
        evidence_ref=evidence_ref,
    )
    return metadata + (("patch_analyzed", "true"),), signals, ()


def _build_objects(
    files: Iterable[Mapping[str, Any]],
) -> tuple[
    tuple[ChangeObject, ...],
    tuple[SemanticChangeSignal, ...],
    tuple[str, ...],
]:
    objects: list[ChangeObject] = []
    semantic_signals: list[SemanticChangeSignal] = []
    uncertainties: set[str] = set()

    for raw in files:
        path = validate_repo_path(str(raw.get("filename") or ""))
        status = str(raw.get("status") or "").lower()
        if status not in _STATUS_MAP:
            raise ValueError(f"unsupported GitHub file status {status!r} for {path!r}")

        additions, additions_gap = _nonnegative_int(raw.get("additions"), "additions", path)
        deletions, deletions_gap = _nonnegative_int(raw.get("deletions"), "deletions", path)
        if additions_gap:
            uncertainties.add(additions_gap)
        if deletions_gap:
            uncertainties.add(deletions_gap)

        previous_path = raw.get("previous_filename")
        if previous_path is not None:
            previous_path = validate_repo_path(str(previous_path))

        operation = _STATUS_MAP[status]
        if operation is ChangeOperation.RENAMED and previous_path is None:
            raise ValueError(f"renamed GitHub file {path!r} lacks previous_filename")

        kind = classify_repository_path(path)
        patch_metadata, patch_signals, patch_uncertainties = _patch_context(
            path=path,
            kind=kind,
            raw_patch=raw.get("patch"),
        )
        semantic_signals.extend(patch_signals)
        uncertainties.update(patch_uncertainties)

        objects.append(
            ChangeObject(
                path=path,
                operation=operation,
                kind=kind,
                additions=additions,
                deletions=deletions,
                previous_path=previous_path,
                metadata=patch_metadata,
            )
        )

    objects.sort(key=lambda obj: (obj.path, obj.operation.value))
    semantic_signals.sort(key=lambda signal: signal.signal_id)
    return tuple(objects), tuple(semantic_signals), tuple(sorted(uncertainties))


def _changeset_id(
    client_id: str,
    source_ref: str,
    base_revision: str,
    head_revision: str,
) -> str:
    material = "\x1f".join(
        (client_id, source_ref, base_revision, head_revision)
    ).encode("utf-8")
    return f"changeset:{sha256(material).hexdigest()[:24]}"


def github_compare_changeset(
    *,
    client_id: str,
    repository: str,
    base_revision: str,
    head_revision: str,
    files: Iterable[Mapping[str, Any]],
    source_kind: ChangeSourceKind,
    source_ref: str,
    too_large: bool = False,
) -> ChangeSet:
    """Normalize GitHub compare metadata plus optional patches into a ChangeSet."""
    objects, semantic_signals, file_uncertainties = _build_objects(files)
    uncertainties = {
        "semantic_security_effects_unresolved",
        *file_uncertainties,
    }
    if any(item.startswith("patch_content_") for item in uncertainties):
        uncertainties.add("patch_content_not_fully_ingested")
    if too_large:
        uncertainties.add("github_compare_too_large")
    if not objects:
        uncertainties.add("no_changed_files_reported")

    changeset = ChangeSet(
        changeset_id=_changeset_id(
            client_id, source_ref, base_revision, head_revision
        ),
        client_id=client_id.strip(),
        source_kind=source_kind,
        source_ref=source_ref.strip(),
        repository=repository.strip(),
        base_revision=base_revision.strip(),
        head_revision=head_revision.strip(),
        objects=objects,
        semantic_signals=semantic_signals,
        uncertainties=tuple(sorted(uncertainties)),
        metadata=(("adapter", "github_compare_patch_context"),),
    )
    changeset.validate()
    return changeset


def github_pull_request_changeset(
    *,
    client_id: str,
    repository: str,
    pr_number: int,
    base_sha: str,
    head_sha: str,
    files: Iterable[Mapping[str, Any]],
    too_large: bool = False,
) -> ChangeSet:
    if pr_number < 1:
        raise ValueError("pr_number must be >= 1")
    source_ref = f"github:{repository}:pull/{pr_number}@{head_sha}"
    return github_compare_changeset(
        client_id=client_id,
        repository=repository,
        base_revision=base_sha,
        head_revision=head_sha,
        files=files,
        source_kind=ChangeSourceKind.GITHUB_PULL_REQUEST,
        source_ref=source_ref,
        too_large=too_large,
    )


def github_commit_changeset(
    *,
    client_id: str,
    repository: str,
    parent_sha: str,
    commit_sha: str,
    files: Iterable[Mapping[str, Any]],
    too_large: bool = False,
) -> ChangeSet:
    source_ref = f"github:{repository}:commit/{commit_sha}"
    return github_compare_changeset(
        client_id=client_id,
        repository=repository,
        base_revision=parent_sha,
        head_revision=commit_sha,
        files=files,
        source_kind=ChangeSourceKind.GITHUB_COMMIT,
        source_ref=source_ref,
        too_large=too_large,
    )
