"""Security Twin domain primitives.

ST0 deliberately models state only. It does not perform target interaction,
execute tools, or grant authorization. The twin is an immutable, versioned,
evidence-aware representation that later Current/Future Security features can
project into and compare safely.
"""

from __future__ import annotations

from dataclasses import dataclass, field, replace
from enum import Enum
from uuid import uuid4


class FactProvenance(str, Enum):
    OBSERVED = "observed"
    VERIFIED = "verified"
    INFERRED = "inferred"
    DECLARED = "declared"


class TwinSnapshotKind(str, Enum):
    CURRENT = "current"
    FUTURE = "future"


class TwinNodeKind(str, Enum):
    ASSET = "asset"
    SERVICE = "service"
    APPLICATION = "application"
    API = "api"
    IDENTITY = "identity"
    ROLE = "role"
    RESOURCE = "resource"
    DATA = "data"


@dataclass(frozen=True)
class TwinNode:
    node_id: str
    kind: TwinNodeKind
    label: str
    attributes: tuple[tuple[str, str], ...] = ()

    def validate(self) -> None:
        if not self.node_id.strip():
            raise ValueError("node_id is required")
        if not self.label.strip():
            raise ValueError("node label is required")


@dataclass(frozen=True)
class TwinFact:
    fact_id: str
    subject_id: str
    predicate: str
    value: str
    provenance: FactProvenance
    confidence: float
    evidence_refs: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.fact_id.strip():
            raise ValueError("fact_id is required")
        if not self.subject_id.strip():
            raise ValueError("fact subject_id is required")
        if not self.predicate.strip():
            raise ValueError("fact predicate is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("fact confidence must be between 0 and 1")
        if self.provenance is FactProvenance.VERIFIED and not self.evidence_refs:
            raise ValueError("verified facts require evidence_refs")


@dataclass(frozen=True)
class TwinRelationship:
    relationship_id: str
    source_id: str
    target_id: str
    relation: str
    provenance: FactProvenance
    confidence: float
    evidence_refs: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.relationship_id.strip():
            raise ValueError("relationship_id is required")
        if not self.source_id.strip() or not self.target_id.strip():
            raise ValueError("relationship endpoints are required")
        if not self.relation.strip():
            raise ValueError("relationship relation is required")
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError("relationship confidence must be between 0 and 1")
        if self.provenance is FactProvenance.VERIFIED and not self.evidence_refs:
            raise ValueError("verified relationships require evidence_refs")


@dataclass(frozen=True)
class AttackStep:
    source_id: str
    target_id: str
    relation: str
    evidence_refs: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.source_id.strip() or not self.target_id.strip():
            raise ValueError("attack step endpoints are required")
        if not self.relation.strip():
            raise ValueError("attack step relation is required")


@dataclass(frozen=True)
class AttackPath:
    path_id: str
    title: str
    steps: tuple[AttackStep, ...]
    evidence_refs: tuple[str, ...] = ()

    def validate(self) -> None:
        if not self.path_id.strip():
            raise ValueError("path_id is required")
        if not self.title.strip():
            raise ValueError("attack path title is required")
        if not self.steps:
            raise ValueError("attack path requires at least one step")
        for step in self.steps:
            step.validate()
        for previous, current in zip(self.steps, self.steps[1:]):
            if previous.target_id != current.source_id:
                raise ValueError("attack path steps must form a contiguous path")


@dataclass(frozen=True)
class SecurityTwin:
    """Immutable versioned snapshot of one client's security state."""

    twin_id: str
    client_id: str
    version: int
    kind: TwinSnapshotKind
    nodes: tuple[TwinNode, ...] = ()
    facts: tuple[TwinFact, ...] = ()
    relationships: tuple[TwinRelationship, ...] = ()
    attack_paths: tuple[AttackPath, ...] = ()
    source_ref: str | None = None
    parent_twin_id: str | None = None
    parent_version: int | None = None
    metadata: tuple[tuple[str, str], ...] = field(default_factory=tuple)

    @classmethod
    def current(cls, client_id: str) -> "SecurityTwin":
        if not client_id.strip():
            raise ValueError("client_id is required")
        return cls(
            twin_id=str(uuid4()),
            client_id=client_id.strip(),
            version=1,
            kind=TwinSnapshotKind.CURRENT,
        )

    def validate(self) -> None:
        if not self.twin_id.strip():
            raise ValueError("twin_id is required")
        if not self.client_id.strip():
            raise ValueError("client_id is required")
        if self.version < 1:
            raise ValueError("twin version must be >= 1")
        if self.kind is TwinSnapshotKind.FUTURE and not self.source_ref:
            raise ValueError("future twins require a source_ref")

        node_ids: set[str] = set()
        for node in self.nodes:
            node.validate()
            if node.node_id in node_ids:
                raise ValueError(f"duplicate node_id {node.node_id!r}")
            node_ids.add(node.node_id)

        fact_ids: set[str] = set()
        for fact in self.facts:
            fact.validate()
            if fact.fact_id in fact_ids:
                raise ValueError(f"duplicate fact_id {fact.fact_id!r}")
            if fact.subject_id not in node_ids:
                raise ValueError(
                    f"fact {fact.fact_id!r} references unknown node {fact.subject_id!r}"
                )
            fact_ids.add(fact.fact_id)

        relationship_ids: set[str] = set()
        relationship_keys: set[tuple[str, str, str]] = set()
        for relationship in self.relationships:
            relationship.validate()
            if relationship.relationship_id in relationship_ids:
                raise ValueError(
                    f"duplicate relationship_id {relationship.relationship_id!r}"
                )
            if relationship.source_id not in node_ids:
                raise ValueError(
                    f"relationship {relationship.relationship_id!r} has unknown source "
                    f"{relationship.source_id!r}"
                )
            if relationship.target_id not in node_ids:
                raise ValueError(
                    f"relationship {relationship.relationship_id!r} has unknown target "
                    f"{relationship.target_id!r}"
                )
            key = (
                relationship.source_id,
                relationship.target_id,
                relationship.relation,
            )
            if key in relationship_keys:
                raise ValueError(f"duplicate relationship {key!r}")
            relationship_ids.add(relationship.relationship_id)
            relationship_keys.add(key)

        path_ids: set[str] = set()
        for path in self.attack_paths:
            path.validate()
            if path.path_id in path_ids:
                raise ValueError(f"duplicate path_id {path.path_id!r}")
            for step in path.steps:
                if step.source_id not in node_ids or step.target_id not in node_ids:
                    raise ValueError(
                        f"attack path {path.path_id!r} references an unknown node"
                    )
            path_ids.add(path.path_id)

    def next_snapshot(
        self,
        *,
        nodes: tuple[TwinNode, ...] | None = None,
        facts: tuple[TwinFact, ...] | None = None,
        relationships: tuple[TwinRelationship, ...] | None = None,
        attack_paths: tuple[AttackPath, ...] | None = None,
    ) -> "SecurityTwin":
        snapshot = replace(
            self,
            version=self.version + 1,
            nodes=self.nodes if nodes is None else nodes,
            facts=self.facts if facts is None else facts,
            relationships=self.relationships if relationships is None else relationships,
            attack_paths=self.attack_paths if attack_paths is None else attack_paths,
            parent_twin_id=self.twin_id,
            parent_version=self.version,
        )
        snapshot.validate()
        return snapshot

    def derive_future(self, source_ref: str) -> "SecurityTwin":
        """Create an immutable future-state branch without mutating current state."""
        if not source_ref.strip():
            raise ValueError("future twin source_ref is required")
        future = SecurityTwin(
            twin_id=str(uuid4()),
            client_id=self.client_id,
            version=1,
            kind=TwinSnapshotKind.FUTURE,
            nodes=self.nodes,
            facts=self.facts,
            relationships=self.relationships,
            attack_paths=self.attack_paths,
            source_ref=source_ref.strip(),
            parent_twin_id=self.twin_id,
            parent_version=self.version,
            metadata=self.metadata,
        )
        future.validate()
        return future
