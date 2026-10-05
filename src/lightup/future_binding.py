"""Explicit, ambiguity-aware binding of future change signals to twin subjects.

Bindings are candidate relationships only. They never establish that a security
impact exists, never become attack-path steps, and never widen authorization.
Automatic suggestions are limited to exact repository-path metadata matches.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256
from typing import Iterable, Mapping

from .changes import ChangeSet, validate_repo_path
from .twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNode,
    TwinNodeKind,
    TwinRelationship,
    TwinSnapshotKind,
)


class SubjectBindingStatus(str, Enum):
    NO_CANDIDATE = "no_candidate"
    SINGLE_CANDIDATE = "single_candidate"
    AMBIGUOUS = "ambiguous"


@dataclass(frozen=True)
class SubjectBinding:
    signal_id: str
    change_node_id: str
    candidate_node_ids: tuple[str, ...]
    status: SubjectBindingStatus


_ELIGIBLE_SUBJECT_KINDS = {
    TwinNodeKind.ASSET,
    TwinNodeKind.SERVICE,
    TwinNodeKind.APPLICATION,
    TwinNodeKind.API,
    TwinNodeKind.IDENTITY,
    TwinNodeKind.ROLE,
    TwinNodeKind.RESOURCE,
    TwinNodeKind.DATA,
}

_DEFAULT_PATH_ATTRIBUTES = (
    "source_path",
    "repo_path",
    "config_path",
    "iac_path",
    "definition_path",
    "object_path",
)


def _stable_id(prefix: str, *parts: str) -> str:
    material = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}:{sha256(material).hexdigest()[:24]}"


def _assert_changeset_future_pair(future: SecurityTwin, changeset: ChangeSet) -> None:
    future.validate()
    changeset.validate()
    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("subject binding requires a future Security Twin")
    if future.client_id != changeset.client_id:
        raise ValueError("future twin and ChangeSet tenants do not match")
    if future.source_ref != changeset.source_ref:
        raise ValueError("future twin source_ref does not match ChangeSet")
    metadata = dict(future.metadata)
    if metadata.get("changeset_id") != changeset.changeset_id:
        raise ValueError("future twin is not derived from this ChangeSet")


def _change_nodes_by_signal_id(future: SecurityTwin) -> dict[str, TwinNode]:
    result: dict[str, TwinNode] = {}
    for node in future.nodes:
        if node.kind is not TwinNodeKind.CHANGE:
            continue
        signal_id = dict(node.attributes).get("signal_id")
        if not signal_id:
            continue
        if signal_id in result:
            raise ValueError(f"duplicate future change node for signal {signal_id!r}")
        result[signal_id] = node
    return result


def _normalized_candidate_paths(
    node: TwinNode,
    attribute_keys: tuple[str, ...],
) -> set[str]:
    attrs = dict(node.attributes)
    paths: set[str] = set()
    for key in attribute_keys:
        raw = attrs.get(key)
        if raw is None:
            continue
        try:
            paths.add(validate_repo_path(raw))
        except ValueError:
            continue
    return paths


def suggest_subject_candidates(
    future: SecurityTwin,
    changeset: ChangeSet,
    *,
    attribute_keys: tuple[str, ...] = _DEFAULT_PATH_ATTRIBUTES,
) -> dict[str, tuple[str, ...]]:
    """Suggest subjects using exact source-path metadata only.

    No fuzzy names, embeddings, model output, or summary parsing are used.
    Multiple exact matches remain multiple candidates and therefore ambiguous.
    """
    _assert_changeset_future_pair(future, changeset)
    if not attribute_keys or any(not key.strip() for key in attribute_keys):
        raise ValueError("attribute_keys must contain non-empty names")

    eligible: list[tuple[TwinNode, set[str]]] = []
    for node in future.nodes:
        if node.kind not in _ELIGIBLE_SUBJECT_KINDS:
            continue
        paths = _normalized_candidate_paths(node, attribute_keys)
        if paths:
            eligible.append((node, paths))

    suggestions: dict[str, tuple[str, ...]] = {}
    for signal in changeset.semantic_signals:
        object_path = validate_repo_path(signal.object_path)
        candidates = sorted(
            node.node_id
            for node, paths in eligible
            if object_path in paths
        )
        suggestions[signal.signal_id] = tuple(candidates)
    return suggestions


def _normalize_explicit_candidates(
    future: SecurityTwin,
    changeset: ChangeSet,
    candidates: Mapping[str, Iterable[str]],
) -> dict[str, tuple[str, ...]]:
    signal_ids = {signal.signal_id for signal in changeset.semantic_signals}
    unknown_signal_ids = sorted(set(candidates) - signal_ids)
    if unknown_signal_ids:
        raise ValueError(
            f"candidate mapping references unknown signals: {unknown_signal_ids!r}"
        )

    nodes = {node.node_id: node for node in future.nodes}
    normalized: dict[str, tuple[str, ...]] = {}
    for signal in changeset.semantic_signals:
        raw_ids = candidates.get(signal.signal_id, ())
        if isinstance(raw_ids, str):
            raise ValueError("candidate node IDs must be supplied as an iterable, not a string")
        unique_ids = tuple(sorted(set(raw_ids)))
        for node_id in unique_ids:
            node = nodes.get(node_id)
            if node is None:
                raise ValueError(f"candidate references unknown twin node {node_id!r}")
            if node.kind not in _ELIGIBLE_SUBJECT_KINDS:
                raise ValueError(
                    f"node {node_id!r} of kind {node.kind.value!r} "
                    "cannot be a change subject candidate"
                )
        normalized[signal.signal_id] = unique_ids
    return normalized


def bind_future_change_candidates(
    future: SecurityTwin,
    changeset: ChangeSet,
    *,
    candidates: Mapping[str, Iterable[str]] | None = None,
) -> tuple[SecurityTwin, tuple[SubjectBinding, ...]]:
    """Create inferred candidate links while keeping ambiguity explicit."""
    _assert_changeset_future_pair(future, changeset)
    change_nodes = _change_nodes_by_signal_id(future)

    expected_signal_ids = {signal.signal_id for signal in changeset.semantic_signals}
    missing_change_nodes = sorted(expected_signal_ids - set(change_nodes))
    if missing_change_nodes:
        raise ValueError(
            f"future twin lacks change nodes for signals: {missing_change_nodes!r}"
        )

    if candidates is None:
        normalized = suggest_subject_candidates(future, changeset)
        binding_source = "exact_source_metadata"
    else:
        normalized = _normalize_explicit_candidates(future, changeset, candidates)
        binding_source = "explicit_candidates"

    change_node_ids = {node.node_id for node in change_nodes.values()}
    facts = tuple(
        fact
        for fact in future.facts
        if not (
            fact.subject_id in change_node_ids
            and fact.predicate in {"change.binding_status", "change.candidate_count"}
        )
    )
    relationships = tuple(
        relationship
        for relationship in future.relationships
        if not (
            relationship.source_id in change_node_ids
            and relationship.relation == "candidate_affects"
        )
    )

    added_facts: list[TwinFact] = []
    added_relationships: list[TwinRelationship] = []
    bindings: list[SubjectBinding] = []

    signal_by_id = {signal.signal_id: signal for signal in changeset.semantic_signals}
    for signal_id in sorted(expected_signal_ids):
        signal = signal_by_id[signal_id]
        change_node = change_nodes[signal_id]
        candidate_ids = normalized.get(signal_id, ())

        if not candidate_ids:
            status = SubjectBindingStatus.NO_CANDIDATE
        elif len(candidate_ids) == 1:
            status = SubjectBindingStatus.SINGLE_CANDIDATE
        else:
            status = SubjectBindingStatus.AMBIGUOUS

        for predicate, value in (
            ("change.binding_status", status.value),
            ("change.candidate_count", str(len(candidate_ids))),
        ):
            added_facts.append(
                TwinFact(
                    fact_id=_stable_id("fact", change_node.node_id, predicate),
                    subject_id=change_node.node_id,
                    predicate=predicate,
                    value=value,
                    provenance=FactProvenance.INFERRED,
                    confidence=1.0,
                    evidence_refs=signal.evidence_refs,
                )
            )

        relationship_confidence = 0.75 if len(candidate_ids) == 1 else 0.5
        for candidate_id in candidate_ids:
            added_relationships.append(
                TwinRelationship(
                    relationship_id=_stable_id(
                        "relationship",
                        change_node.node_id,
                        candidate_id,
                        "candidate_affects",
                    ),
                    source_id=change_node.node_id,
                    target_id=candidate_id,
                    relation="candidate_affects",
                    provenance=FactProvenance.INFERRED,
                    confidence=relationship_confidence,
                    evidence_refs=signal.evidence_refs,
                )
            )

        bindings.append(
            SubjectBinding(
                signal_id=signal_id,
                change_node_id=change_node.node_id,
                candidate_node_ids=candidate_ids,
                status=status,
            )
        )

    next_twin = future.next_snapshot(
        facts=facts + tuple(added_facts),
        relationships=relationships + tuple(added_relationships),
        attack_paths=future.attack_paths,
    )
    metadata = dict(next_twin.metadata)
    metadata.update(
        {
            "future_subject_binding": binding_source,
            "future_subject_binding_count": str(len(bindings)),
            "future_subject_binding_ambiguous": str(
                sum(binding.status is SubjectBindingStatus.AMBIGUOUS for binding in bindings)
            ),
            "future_subject_binding_missing": str(
                sum(binding.status is SubjectBindingStatus.NO_CANDIDATE for binding in bindings)
            ),
            "future_semantics": "unresolved",
        }
    )
    next_twin = replace(next_twin, metadata=tuple(sorted(metadata.items())))
    next_twin.validate()
    return next_twin, tuple(bindings)
