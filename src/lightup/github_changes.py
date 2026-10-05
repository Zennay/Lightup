"""Deterministic GitHub compare/PR/commit adapters for ChangeSet ingestion.

This module performs no network I/O. Callers supply normalized GitHub compare
file records. That keeps ingestion testable and prevents a proposed code change
from becoming target authorization or execution.
"""

from __future__ import annotations

from hashlib import sha256
from pathlib import PurePosixPath
from typing import Iterable, Mapping, Any

from .changes import (
    ChangeObject,
    ChangeObjectKind,
    ChangeOperation,
    ChangeSet,
    ChangeSourceKind,
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
_API_NAMES = {"openapi.json", "openapi.yaml", "openapi.yml", "swagger.json", "swagger.yaml", "swagger.yml"}
_IAC_SUFFIXES = {".tf", ".tfvars"}


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


def _build_objects(
    files: Iterable[Mapping[str, Any]],
) -> tuple[tuple[ChangeObject, ...], tuple[str, ...]]:
    objects: list[ChangeObject] = []
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

        objects.append(
            ChangeObject(
                path=path,
                operation=operation,
                kind=classify_repository_path(path),
                additions=additions,
                deletions=deletions,
                previous_path=previous_path,
            )
        )

    objects.sort(key=lambda obj: (obj.path, obj.operation.value))
    return tuple(objects), tuple(sorted(uncertainties))


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
    """Normalize GitHub compare-file metadata into an immutable ChangeSet."""
    objects, file_uncertainties = _build_objects(files)
    uncertainties = {
        "patch_content_not_ingested",
        "semantic_security_effects_unresolved",
        *file_uncertainties,
    }
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
        uncertainties=tuple(sorted(uncertainties)),
        metadata=(("adapter", "github_compare_stats"),),
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
