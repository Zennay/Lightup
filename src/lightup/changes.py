"""Immutable change-ingestion primitives for Future Security.

A ChangeSet records what changed and what is still unknown. It is deliberately
not a security verdict: file changes alone do not prove that permissions,
reachability, trust, routes, or attack paths changed.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from hashlib import sha256
import json

from .twin import SecurityTwin


class ChangeSourceKind(str, Enum):
    GITHUB_PULL_REQUEST = "github_pull_request"
    GITHUB_COMMIT = "github_commit"


class ChangeOperation(str, Enum):
    ADDED = "added"
    MODIFIED = "modified"
    REMOVED = "removed"
    RENAMED = "renamed"
    COPIED = "copied"
    CHANGED = "changed"


class ChangeObjectKind(str, Enum):
    SOURCE = "source"
    API_SPEC = "api_spec"
    IAC = "iac"
    IAM = "iam"
    CONFIG = "config"
    CI = "ci"
    TEST = "test"
    DOC = "doc"
    OTHER = "other"


def validate_repo_path(path: str) -> str:
    normalized = path.strip().replace("\\", "/")
    if not normalized or normalized.startswith("/"):
        raise ValueError("change path must be a relative repository path")
    parts = normalized.split("/")
    if any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"unsafe repository path {path!r}")
    return normalized


@dataclass(frozen=True)
class ChangeObject:
    path: str
    operation: ChangeOperation
    kind: ChangeObjectKind
    additions: int = 0
    deletions: int = 0
    previous_path: str | None = None
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def validate(self) -> None:
        validate_repo_path(self.path)
        if self.previous_path is not None:
            validate_repo_path(self.previous_path)
        if self.additions < 0 or self.deletions < 0:
            raise ValueError("change line counts cannot be negative")
        if self.operation is ChangeOperation.RENAMED and not self.previous_path:
            raise ValueError("renamed changes require previous_path")


@dataclass(frozen=True)
class ChangeSet:
    changeset_id: str
    client_id: str
    source_kind: ChangeSourceKind
    source_ref: str
    repository: str
    base_revision: str
    head_revision: str
    objects: tuple[ChangeObject, ...] = ()
    uncertainties: tuple[str, ...] = ()
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    def validate(self) -> None:
        if not self.changeset_id.strip():
            raise ValueError("changeset_id is required")
        if not self.client_id.strip():
            raise ValueError("client_id is required")
        if not self.source_ref.strip():
            raise ValueError("source_ref is required")
        if self.repository.count("/") != 1 or any(
            not part.strip() for part in self.repository.split("/")
        ):
            raise ValueError("repository must be in owner/name form")
        if not self.base_revision.strip() or not self.head_revision.strip():
            raise ValueError("base_revision and head_revision are required")
        if self.base_revision == self.head_revision:
            raise ValueError("base_revision and head_revision must differ")

        paths: set[str] = set()
        for obj in self.objects:
            obj.validate()
            if obj.path in paths:
                raise ValueError(f"duplicate change object path {obj.path!r}")
            paths.add(obj.path)

        if len(set(self.uncertainties)) != len(self.uncertainties):
            raise ValueError("uncertainties must be unique")

    def stable_digest(self) -> str:
        """Return a deterministic digest for evidence/provenance correlation."""
        self.validate()
        payload = {
            "client_id": self.client_id,
            "source_kind": self.source_kind.value,
            "source_ref": self.source_ref,
            "repository": self.repository,
            "base_revision": self.base_revision,
            "head_revision": self.head_revision,
            "objects": [
                {
                    "path": obj.path,
                    "operation": obj.operation.value,
                    "kind": obj.kind.value,
                    "additions": obj.additions,
                    "deletions": obj.deletions,
                    "previous_path": obj.previous_path,
                    "metadata": list(obj.metadata),
                }
                for obj in self.objects
            ],
            "uncertainties": list(self.uncertainties),
            "metadata": list(self.metadata),
        }
        encoded = json.dumps(
            payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True
        ).encode("utf-8")
        return sha256(encoded).hexdigest()


def derive_future_twin(current: SecurityTwin, changeset: ChangeSet) -> SecurityTwin:
    """Attach a ChangeSet to a separate future twin without inventing effects.

    The current graph is copied exactly. Semantic security effects remain
    unresolved until later analysis/materialization produces evidence.
    """
    current.validate()
    changeset.validate()
    if current.client_id != changeset.client_id:
        raise ValueError(
            "changeset client_id does not match the current Security Twin tenant"
        )

    future = current.derive_future(changeset.source_ref)
    metadata = dict(future.metadata)
    metadata.update(
        {
            "changeset_id": changeset.changeset_id,
            "changeset_digest": changeset.stable_digest(),
            "changeset_source_kind": changeset.source_kind.value,
            "changeset_repository": changeset.repository,
            "changeset_object_count": str(len(changeset.objects)),
            "changeset_uncertainty_count": str(len(changeset.uncertainties)),
            "future_semantics": "unresolved",
        }
    )
    future = replace(future, metadata=tuple(sorted(metadata.items())))
    future.validate()
    return future
