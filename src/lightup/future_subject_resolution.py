"""Explicit evidence-backed subject resolution for future security changes.

This ST3 contract sits between inferred candidate binding and any later graph
semantics. It can promote one existing candidate association to an explicitly
verified subject decision, but it never creates attack paths, executes tools, or
widens authorization.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from enum import Enum
from hashlib import sha256

from .changes import validate_repo_path
from .state import StateStore
from .twin import (
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNodeKind,
    TwinRelationship,
    TwinSnapshotKind,
)


class SubjectResolutionBasis(str, Enum):
    OPERATOR_REVIEWED = "operator_reviewed"
    INTEGRATION_VERIFIED = "integration_verified"


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

_MAX_RESOLUTION_EVIDENCE_IDS = 16
_MAX_RESOLUTION_IDENTIFIER_LENGTH = 256
_MAX_EVIDENCE_ID_LENGTH = 256
_MAX_LINEAGE_EVIDENCE_REFS = 64
_MAX_EVIDENCE_SOURCE_LENGTH = 256
_EVIDENCE_KIND_BY_BASIS = {
    SubjectResolutionBasis.OPERATOR_REVIEWED: "operator-review",
    SubjectResolutionBasis.INTEGRATION_VERIFIED: "integration-verification",
}
_VALID_RESOLUTION_BASIS_VALUES = {
    basis.value for basis in SubjectResolutionBasis
}
_RESOLUTION_FACT_PREDICATES = (
    "future_subject.decision_id",
    "future_subject.node_id",
    "future_subject.run_id",
    "future_subject.basis",
    "future_subject.rationale_sha256",
    "future_subject.candidate_evidence_sha256",
)


def _validate_bounded_identifier(name: str, value: str, *, max_length: int) -> None:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} is required")
    if value != value.strip():
        raise ValueError(f"{name} must not contain surrounding whitespace")
    if len(value) > max_length:
        raise ValueError(f"{name} exceeds {max_length} characters")
    if any(ord(character) < 32 or ord(character) == 127 for character in value):
        raise ValueError(f"{name} contains control characters")


def _validate_lower_sha256(name: str, value: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{name} must be canonical lowercase SHA-256")


def _validate_verified_subject_state(
    facts: tuple[TwinFact, ...],
    relationships: tuple[TwinRelationship, ...],
) -> None:
    facts_by_change: dict[str, list[TwinFact]] = {}
    relationships_by_change: dict[str, list[TwinRelationship]] = {}

    for fact in facts:
        if fact.predicate not in _RESOLUTION_FACT_PREDICATES:
            raise ValueError(
                "subject resolution found an unknown verified future_subject predicate"
            )
        facts_by_change.setdefault(fact.subject_id, []).append(fact)

    for relationship in relationships:
        relationships_by_change.setdefault(
            relationship.source_id,
            [],
        ).append(relationship)

    if set(facts_by_change) != set(relationships_by_change):
        raise ValueError(
            "subject resolution found partial verified subject state"
        )

    expected_predicates = set(_RESOLUTION_FACT_PREDICATES)
    for change_id in sorted(facts_by_change):
        change_facts = facts_by_change[change_id]
        change_relationships = relationships_by_change[change_id]
        if len(change_relationships) != 1:
            raise ValueError(
                "subject resolution requires exactly one verified subject relationship "
                "per resolved change"
            )

        facts_by_predicate = {fact.predicate: fact for fact in change_facts}
        if (
            len(facts_by_predicate) != len(change_facts)
            or set(facts_by_predicate) != expected_predicates
        ):
            raise ValueError(
                "subject resolution requires one canonical verified fact set "
                "per resolved change"
            )

        relationship = change_relationships[0]
        if (
            facts_by_predicate["future_subject.node_id"].value
            != relationship.target_id
        ):
            raise ValueError(
                "subject resolution verified fact/relationship targets disagree"
            )
        if any(
            fact.evidence_refs != relationship.evidence_refs
            for fact in change_facts
        ):
            raise ValueError(
                "subject resolution verified state evidence lineage is inconsistent"
            )

        decision_id = facts_by_predicate["future_subject.decision_id"].value
        _validate_bounded_identifier(
            "verified subject decision_id",
            decision_id,
            max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
        )
        subject_node_id = facts_by_predicate["future_subject.node_id"].value
        _validate_bounded_identifier(
            "verified subject node_id",
            subject_node_id,
            max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
        )
        run_id = facts_by_predicate["future_subject.run_id"].value
        _validate_bounded_identifier(
            "verified subject run_id",
            run_id,
            max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
        )
        if (
            facts_by_predicate["future_subject.basis"].value
            not in _VALID_RESOLUTION_BASIS_VALUES
        ):
            raise ValueError(
                "subject resolution verified basis value is non-canonical"
            )
        _validate_lower_sha256(
            "verified subject rationale digest",
            facts_by_predicate["future_subject.rationale_sha256"].value,
        )
        _validate_lower_sha256(
            "verified subject candidate evidence digest",
            facts_by_predicate[
                "future_subject.candidate_evidence_sha256"
            ].value,
        )
        for predicate, fact in facts_by_predicate.items():
            if fact.fact_id != _stable_id(
                "subject-resolution",
                decision_id,
                predicate,
            ):
                raise ValueError(
                    "subject resolution verified fact uses a non-canonical stable id"
                )
        if relationship.relationship_id != _stable_id(
            "subject-resolution-rel",
            decision_id,
            change_id,
            relationship.target_id,
        ):
            raise ValueError(
                "subject resolution verified relationship uses a non-canonical stable id"
            )


def _validate_verified_subject_evidence(
    future: SecurityTwin,
    state: StateStore,
    facts: tuple[TwinFact, ...],
    relationships: tuple[TwinRelationship, ...],
) -> None:
    if not relationships:
        return

    facts_by_change: dict[str, dict[str, TwinFact]] = {}
    for fact in facts:
        facts_by_change.setdefault(fact.subject_id, {})[fact.predicate] = fact

    future_metadata = dict(future.metadata)
    changeset_id = future_metadata.get("changeset_id", "")
    expected_metadata_keys = {
        "purpose",
        "decision_id",
        "client_id",
        "future_twin_id",
        "future_twin_version",
        "changeset_id",
        "change_node_id",
        "subject_node_id",
        "candidate_evidence_sha256",
        "resolution_basis",
        "rationale_sha256",
    }

    for relationship in relationships:
        change_facts = facts_by_change[relationship.source_id]
        decision_id = change_facts["future_subject.decision_id"].value
        run_id = change_facts["future_subject.run_id"].value
        basis = SubjectResolutionBasis(
            change_facts["future_subject.basis"].value
        )
        expected_kind = _EVIDENCE_KIND_BY_BASIS[basis]
        expected_values = {
            "purpose": "future_subject_resolution",
            "decision_id": decision_id,
            "client_id": future.client_id,
            "future_twin_id": future.twin_id,
            "changeset_id": changeset_id,
            "change_node_id": relationship.source_id,
            "subject_node_id": relationship.target_id,
            "candidate_evidence_sha256": change_facts[
                "future_subject.candidate_evidence_sha256"
            ].value,
            "resolution_basis": basis.value,
            "rationale_sha256": change_facts[
                "future_subject.rationale_sha256"
            ].value,
        }

        for ref in relationship.evidence_refs:
            evidence_id = ref[len("evidence:"):]
            item = state.get_evidence(evidence_id)
            if item.run_id != run_id:
                raise ValueError(
                    "verified subject evidence belongs to a different run"
                )
            if item.capability_id != "future-subject-resolution":
                raise ValueError(
                    "verified subject evidence capability is non-canonical"
                )
            if item.kind != expected_kind:
                raise ValueError(
                    "verified subject evidence kind is non-canonical"
                )
            _validate_bounded_identifier(
                "verified subject evidence source",
                item.source,
                max_length=_MAX_EVIDENCE_SOURCE_LENGTH,
            )
            if (
                basis is SubjectResolutionBasis.OPERATOR_REVIEWED
                and item.source != "operator"
            ):
                raise ValueError(
                    "verified operator-reviewed subject evidence requires operator source"
                )
            _validate_lower_sha256(
                "verified subject evidence payload digest",
                item.sha256,
            )

            metadata = dict(item.metadata)
            if set(metadata) != expected_metadata_keys:
                raise ValueError(
                    "verified subject evidence metadata keys are non-canonical"
                )
            for key, expected in expected_values.items():
                if metadata.get(key) != expected:
                    raise ValueError(
                        f"verified subject evidence metadata mismatch for {key!r}"
                    )
            evidence_twin_version = _parse_canonical_nonnegative_decimal(
                "verified subject evidence future_twin_version",
                metadata.get("future_twin_version", ""),
            )
            if evidence_twin_version >= future.version:
                raise ValueError(
                    "verified subject evidence references a stale or future twin version"
                )


def _parse_canonical_nonnegative_decimal(name: str, value: str) -> int:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be a canonical non-negative decimal")
    if any(character < "0" or character > "9" for character in value):
        raise ValueError(f"{name} must be a canonical non-negative decimal")
    if len(value) > 1 and value.startswith("0"):
        raise ValueError(f"{name} must not contain leading zeroes")
    return int(value)


def _validate_evidence_refs(name: str, refs: tuple[str, ...]) -> None:
    if not refs:
        raise ValueError(f"{name} requires evidence refs")
    if len(refs) > _MAX_LINEAGE_EVIDENCE_REFS:
        raise ValueError(
            f"{name} accepts at most {_MAX_LINEAGE_EVIDENCE_REFS} evidence refs"
        )
    if len(set(refs)) != len(refs):
        raise ValueError(f"{name} evidence refs must be unique")
    for ref in refs:
        if not isinstance(ref, str) or not ref.startswith("evidence:"):
            raise ValueError(f"{name} evidence refs must use evidence:<id> form")
        _validate_bounded_identifier(
            f"{name} evidence id",
            ref[len("evidence:"):],
            max_length=_MAX_EVIDENCE_ID_LENGTH,
        )


def _validate_lineage_refs(name: str, refs: tuple[str, ...]) -> None:
    if not refs:
        raise ValueError(f"{name} requires lineage refs")
    if len(refs) > _MAX_LINEAGE_EVIDENCE_REFS:
        raise ValueError(
            f"{name} accepts at most {_MAX_LINEAGE_EVIDENCE_REFS} lineage refs"
        )
    if len(set(refs)) != len(refs):
        raise ValueError(f"{name} lineage refs must be unique")
    for ref in refs:
        _validate_bounded_identifier(
            f"{name} lineage ref",
            ref,
            max_length=_MAX_EVIDENCE_ID_LENGTH,
        )


@dataclass(frozen=True)
class FutureSubjectResolution:
    decision_id: str
    client_id: str
    changeset_id: str
    change_node_id: str
    subject_node_id: str
    run_id: str
    basis: SubjectResolutionBasis
    evidence_ids: tuple[str, ...]
    rationale: str = ""

    def validate(self) -> None:
        for name, value in (
            ("decision_id", self.decision_id),
            ("client_id", self.client_id),
            ("changeset_id", self.changeset_id),
            ("change_node_id", self.change_node_id),
            ("subject_node_id", self.subject_node_id),
            ("run_id", self.run_id),
        ):
            _validate_bounded_identifier(
                name,
                value,
                max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
            )
        if not self.change_node_id.startswith("change:"):
            raise ValueError("subject resolution must target a future change node")
        if type(self.evidence_ids) is not tuple:
            raise ValueError("subject resolution evidence_ids must be an exact tuple")
        if not self.evidence_ids:
            raise ValueError("subject resolution requires evidence")
        if len(self.evidence_ids) > _MAX_RESOLUTION_EVIDENCE_IDS:
            raise ValueError(
                f"subject resolution accepts at most {_MAX_RESOLUTION_EVIDENCE_IDS} evidence ids"
            )
        try:
            for item in self.evidence_ids:
                if type(item) is not str:
                    raise ValueError(
                        "subject resolution evidence_id must be an exact string"
                    )
                _validate_bounded_identifier(
                    "subject resolution evidence_id",
                    item,
                    max_length=_MAX_EVIDENCE_ID_LENGTH,
                )
        except ValueError as exc:
            raise ValueError(
                "subject resolution evidence_ids must be canonical bounded strings"
            ) from exc
        if len(set(self.evidence_ids)) != len(self.evidence_ids):
            raise ValueError("subject resolution evidence_ids must be unique")
        if not isinstance(self.basis, SubjectResolutionBasis):
            raise ValueError("subject resolution basis is invalid")
        if len(self.rationale) > 2048:
            raise ValueError("subject resolution rationale exceeds 2048 characters")
        if self.rationale != self.rationale.strip():
            raise ValueError(
                "subject resolution rationale must not contain surrounding whitespace"
            )
        if (
            self.basis is SubjectResolutionBasis.OPERATOR_REVIEWED
            and not self.rationale
        ):
            raise ValueError("operator-reviewed subject resolution requires rationale")


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}:{sha256(payload).hexdigest()[:24]}"


def _resolution_facts(
    resolution: FutureSubjectResolution,
    candidate_evidence_sha256: str,
) -> tuple[TwinFact, ...]:
    evidence_refs = tuple(
        f"evidence:{item}" for item in sorted(resolution.evidence_ids)
    )
    rationale_digest = sha256(resolution.rationale.strip().encode("utf-8")).hexdigest()
    values = dict(
        zip(
            _RESOLUTION_FACT_PREDICATES,
            (
                resolution.decision_id,
                resolution.subject_node_id,
                resolution.run_id,
                resolution.basis.value,
                rationale_digest,
                candidate_evidence_sha256,
            ),
            strict=True,
        )
    )
    return tuple(
        TwinFact(
            fact_id=_stable_id("subject-resolution", resolution.decision_id, predicate),
            subject_id=resolution.change_node_id,
            predicate=predicate,
            value=value,
            provenance=FactProvenance.VERIFIED,
            confidence=1.0,
            evidence_refs=evidence_refs,
        )
        for predicate, value in values.items()
    )


def _resolution_relationship(
    resolution: FutureSubjectResolution,
) -> TwinRelationship:
    evidence_refs = tuple(
        f"evidence:{item}" for item in sorted(resolution.evidence_ids)
    )
    return TwinRelationship(
        relationship_id=_stable_id(
            "subject-resolution-rel",
            resolution.decision_id,
            resolution.change_node_id,
            resolution.subject_node_id,
        ),
        source_id=resolution.change_node_id,
        target_id=resolution.subject_node_id,
        relation="verified_affects_subject",
        provenance=FactProvenance.VERIFIED,
        confidence=1.0,
        evidence_refs=evidence_refs,
    )


def validate_future_subject_snapshot(
    future: SecurityTwin,
    state: StateStore,
    *,
    client_id: str,
    changeset_id: str,
) -> None:
    """Revalidate binding and verified-subject state without creating a decision.

    Reuses the same canonical-state and live evidence checks as the write path.
    Callers exposing this state must authenticate and enforce tenant access
    before calling this lower-level validator.
    """

    _validate_bounded_identifier(
        "client_id", client_id, max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
    )
    _validate_bounded_identifier(
        "changeset_id", changeset_id, max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
    )
    future.validate()

    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("subject resolution requires a future Security Twin")
    if future.client_id != client_id:
        raise ValueError("subject resolution cannot cross tenants")

    input_metadata = dict(future.metadata)
    if len(input_metadata) != len(future.metadata):
        raise ValueError("subject resolution requires canonical future metadata keys")
    if input_metadata.get("future_semantics") != "unresolved":
        raise ValueError("subject resolution requires explicit unresolved future semantics")
    if input_metadata.get("changeset_id") != changeset_id:
        raise ValueError(
            "subject resolution changeset_id does not match future twin metadata"
        )
    recorded_resolution_count = _parse_canonical_nonnegative_decimal(
        "subject resolution metadata count",
        input_metadata.get("future_subject_resolution_count", "0"),
    )
    verified_subject_relationships = tuple(
        item
        for item in future.relationships
        if item.relation == "verified_affects_subject"
    )
    if any(
        item.provenance is not FactProvenance.VERIFIED
        for item in verified_subject_relationships
    ):
        raise ValueError(
            "subject resolution requires verified_affects_subject relationships "
            "to remain verified"
        )
    for item in verified_subject_relationships:
        _validate_evidence_refs("verified subject relationship", item.evidence_refs)
    verified_subject_state_facts = tuple(
        fact
        for fact in future.facts
        if fact.predicate.startswith("future_subject.")
    )
    if any(
        fact.provenance is not FactProvenance.VERIFIED
        for fact in verified_subject_state_facts
    ):
        raise ValueError(
            "subject resolution requires future_subject facts to remain verified"
        )
    for fact in verified_subject_state_facts:
        _validate_evidence_refs("verified subject fact", fact.evidence_refs)
    _validate_verified_subject_state(
        verified_subject_state_facts,
        verified_subject_relationships,
    )
    _validate_verified_subject_evidence(
        future,
        state,
        verified_subject_state_facts,
        verified_subject_relationships,
    )
    verified_resolution_count = len(verified_subject_relationships)
    if recorded_resolution_count != verified_resolution_count:
        raise ValueError(
            "subject resolution metadata count does not match verified subject state"
        )
    resolution_marker = input_metadata.get("future_subject_resolution")
    if recorded_resolution_count == 0:
        if resolution_marker is not None:
            raise ValueError(
                "unresolved subject state cannot claim resolution metadata"
            )
    elif resolution_marker != "evidence_recorded":
        raise ValueError(
            "verified subject state requires canonical resolution metadata"
        )

    binding_source = input_metadata.get("future_subject_binding")
    if binding_source not in {"exact_source_metadata", "explicit_candidates"}:
        raise ValueError(
            "subject resolution requires canonical candidate-binding metadata"
        )

    binding_count_keys = (
        "future_subject_binding_count",
        "future_subject_binding_ambiguous",
        "future_subject_binding_missing",
    )
    binding_counts: dict[str, int] = {}
    for key in binding_count_keys:
        binding_counts[key] = _parse_canonical_nonnegative_decimal(
            f"subject resolution candidate-binding metadata {key!r}",
            input_metadata.get(key, ""),
        )

    binding_status_summary = tuple(
        fact
        for fact in future.facts
        if fact.predicate == "change.binding_status"
    )
    binding_count_summary = tuple(
        fact
        for fact in future.facts
        if fact.predicate == "change.candidate_count"
    )
    if any(
        fact.provenance is not FactProvenance.INFERRED
        for fact in binding_status_summary + binding_count_summary
    ):
        raise ValueError(
            "subject resolution requires candidate-binding facts to remain inferred"
        )
    allowed_binding_states = {"no_candidate", "single_candidate", "ambiguous"}
    if any(fact.value not in allowed_binding_states for fact in binding_status_summary):
        raise ValueError("subject resolution found a non-canonical candidate-binding state")

    nodes = {node.node_id: node for node in future.nodes}
    change_node_ids = {
        node.node_id for node in future.nodes if node.kind is TwinNodeKind.CHANGE
    }
    if any(
        relationship.source_id not in change_node_ids
        or nodes[relationship.target_id].kind not in _ELIGIBLE_SUBJECT_KINDS
        or relationship.confidence != 1.0
        for relationship in verified_subject_relationships
    ):
        raise ValueError(
            "subject resolution found non-canonical verified subject relationship state"
        )
    if any(
        fact.subject_id not in change_node_ids or fact.confidence != 1.0
        for fact in verified_subject_state_facts
    ):
        raise ValueError(
            "subject resolution found non-canonical verified subject fact state"
        )
    status_by_change: dict[str, list[TwinFact]] = {}
    count_by_change: dict[str, list[TwinFact]] = {}
    for fact in binding_status_summary:
        if fact.subject_id not in change_node_ids:
            raise ValueError(
                "subject resolution candidate-binding status targets a non-change node"
            )
        status_by_change.setdefault(fact.subject_id, []).append(fact)
    for fact in binding_count_summary:
        if fact.subject_id not in change_node_ids:
            raise ValueError(
                "subject resolution candidate-binding count targets a non-change node"
            )
        count_by_change.setdefault(fact.subject_id, []).append(fact)

    if set(status_by_change) != set(count_by_change):
        raise ValueError(
            "subject resolution requires matching binding status/count facts for every change"
        )
    if set(status_by_change) != change_node_ids:
        raise ValueError(
            "subject resolution requires binding status/count facts for every future change"
        )

    candidate_binding_relationships = tuple(
        relationship
        for relationship in future.relationships
        if relationship.relation == "candidate_affects"
    )
    if any(
        relationship.provenance is not FactProvenance.INFERRED
        for relationship in candidate_binding_relationships
    ):
        raise ValueError(
            "subject resolution requires candidate_affects relationships to remain inferred"
        )
    if any(
        relationship.source_id not in change_node_ids
        for relationship in candidate_binding_relationships
    ):
        raise ValueError(
            "subject resolution candidate_affects must originate from future change nodes"
        )

    for change_id in sorted(status_by_change):
        status_facts = status_by_change[change_id]
        count_facts = count_by_change[change_id]
        if len(status_facts) != 1 or len(count_facts) != 1:
            raise ValueError(
                "subject resolution requires exactly one binding status/count fact per change"
            )
        status_fact = status_facts[0]
        count_fact = count_facts[0]
        change_signal_facts = tuple(
            fact
            for fact in future.facts
            if fact.subject_id == change_id
            and fact.predicate in {
                "change.signal_kind",
                "change.direction",
                "change.summary",
            }
        )
        change_signal_by_predicate = {
            fact.predicate: fact for fact in change_signal_facts
        }
        expected_change_signal_predicates = {
            "change.signal_kind",
            "change.direction",
            "change.summary",
        }
        if (
            len(change_signal_by_predicate) != len(change_signal_facts)
            or set(change_signal_by_predicate) != expected_change_signal_predicates
        ):
            raise ValueError(
                "subject resolution requires one canonical change-signal fact set per change"
            )
        projected_change = nodes[change_id]
        change_attributes = dict(projected_change.attributes)
        expected_change_attribute_keys = {
            "changeset_id",
            "object_path",
            "signal_id",
        }
        if (
            len(change_attributes) != len(projected_change.attributes)
            or set(change_attributes) != expected_change_attribute_keys
        ):
            raise ValueError(
                "subject resolution requires canonical projected change-node attributes"
            )
        if change_attributes["changeset_id"] != input_metadata["changeset_id"]:
            raise ValueError(
                "subject resolution projected change node belongs to a different changeset"
            )
        _validate_bounded_identifier(
            "projected change signal_id",
            change_attributes["signal_id"],
            max_length=_MAX_RESOLUTION_IDENTIFIER_LENGTH,
        )
        try:
            normalized_object_path = validate_repo_path(
                change_attributes["object_path"]
            )
        except ValueError as exc:
            raise ValueError(
                "subject resolution projected change object_path is non-canonical"
            ) from exc
        if normalized_object_path != change_attributes["object_path"]:
            raise ValueError(
                "subject resolution projected change object_path is non-canonical"
            )
        if change_id != _stable_id(
            "change",
            change_attributes["changeset_id"],
            change_attributes["signal_id"],
        ):
            raise ValueError(
                "subject resolution projected change node uses a non-canonical stable id"
            )
        if (
            projected_change.label
            != change_signal_by_predicate["change.summary"].value
        ):
            raise ValueError(
                "subject resolution projected change label does not match change.summary"
            )
        if any(
            fact.provenance is not FactProvenance.INFERRED
            for fact in change_signal_facts
        ):
            raise ValueError(
                "subject resolution requires change-signal facts to remain inferred"
            )
        if any(
            fact.fact_id
            != _stable_id("fact", change_id, fact.predicate, fact.value)
            for fact in change_signal_facts
        ):
            raise ValueError(
                "subject resolution change-signal fact uses a non-canonical stable id"
            )
        change_signal_confidence = change_signal_facts[0].confidence
        if any(
            fact.confidence != change_signal_confidence
            for fact in change_signal_facts
        ):
            raise ValueError(
                "subject resolution change-signal fact confidence is inconsistent"
            )
        change_signal_evidence = change_signal_facts[0].evidence_refs
        _validate_lineage_refs(
            "change-signal fact",
            change_signal_evidence,
        )
        if any(
            fact.evidence_refs != change_signal_evidence
            for fact in change_signal_facts
        ):
            raise ValueError(
                "subject resolution change-signal evidence lineage is inconsistent"
            )
        for predicate, fact in (
            ("change.binding_status", status_fact),
            ("change.candidate_count", count_fact),
        ):
            if fact.confidence != 1.0:
                raise ValueError(
                    "subject resolution requires canonical candidate-binding fact confidence"
                )
            if fact.fact_id != _stable_id("fact", change_id, predicate):
                raise ValueError(
                    "subject resolution candidate-binding fact uses a non-canonical stable id"
                )
        _validate_lineage_refs(
            "candidate-binding status fact",
            status_fact.evidence_refs,
        )
        _validate_lineage_refs(
            "candidate-binding count fact",
            count_fact.evidence_refs,
        )
        if status_fact.evidence_refs != count_fact.evidence_refs:
            raise ValueError(
                "subject resolution candidate-binding fact evidence lineage is inconsistent"
            )
        if status_fact.evidence_refs != change_signal_evidence:
            raise ValueError(
                "subject resolution candidate binding is detached from change-signal evidence"
            )
        candidate_count = _parse_canonical_nonnegative_decimal(
            "subject resolution candidate count fact",
            count_fact.value,
        )

        candidate_links_for_change = tuple(
            relationship
            for relationship in future.relationships
            if relationship.source_id == change_id
            and relationship.relation == "candidate_affects"
            and relationship.provenance is FactProvenance.INFERRED
        )
        if (
            len(candidate_links_for_change) != candidate_count
            or len({item.target_id for item in candidate_links_for_change})
            != candidate_count
        ):
            raise ValueError(
                "subject resolution candidate count does not match inferred relationships"
            )
        if any(
            nodes[item.target_id].kind not in _ELIGIBLE_SUBJECT_KINDS
            for item in candidate_links_for_change
        ):
            raise ValueError(
                "subject resolution candidate binding targets an ineligible subject kind"
            )
        expected_candidate_confidence = 0.75 if candidate_count == 1 else 0.5
        if any(
            item.confidence != expected_candidate_confidence
            for item in candidate_links_for_change
        ):
            raise ValueError(
                "subject resolution candidate binding uses non-canonical confidence"
            )
        if any(
            item.relationship_id
            != _stable_id(
                "relationship",
                change_id,
                item.target_id,
                "candidate_affects",
            )
            for item in candidate_links_for_change
        ):
            raise ValueError(
                "subject resolution candidate binding uses a non-canonical stable id"
            )
        for item in candidate_links_for_change:
            _validate_lineage_refs(
                "candidate-binding relationship",
                item.evidence_refs,
            )
        if any(
            item.evidence_refs != status_fact.evidence_refs
            for item in candidate_links_for_change
        ):
            raise ValueError(
                "subject resolution candidate relationship evidence lineage is inconsistent"
            )
        if status_fact.value == "no_candidate" and candidate_count != 0:
            raise ValueError("no-candidate binding must have zero candidates")
        if status_fact.value == "single_candidate" and candidate_count != 1:
            raise ValueError("single-candidate binding must have exactly one candidate")
        if status_fact.value == "ambiguous" and candidate_count < 2:
            raise ValueError("ambiguous binding must have at least two candidates")

        verified_links_for_change = tuple(
            relationship
            for relationship in verified_subject_relationships
            if relationship.source_id == change_id
        )
        if verified_links_for_change:
            if status_fact.value != "single_candidate" or candidate_count != 1:
                raise ValueError(
                    "verified subject state requires a current single-candidate binding"
                )
            verified_link = verified_links_for_change[0]
            if candidate_links_for_change[0].target_id != verified_link.target_id:
                raise ValueError(
                    "verified subject state is stale against current candidate binding"
                )
            verified_candidate_digest_facts = tuple(
                fact
                for fact in verified_subject_state_facts
                if fact.subject_id == change_id
                and fact.predicate
                == "future_subject.candidate_evidence_sha256"
            )
            if len(verified_candidate_digest_facts) != 1:
                raise ValueError(
                    "verified subject state requires one candidate evidence digest"
                )
            current_candidate_digest = sha256(
                "\x1f".join(
                    sorted(candidate_links_for_change[0].evidence_refs)
                ).encode("utf-8")
            ).hexdigest()
            if (
                verified_candidate_digest_facts[0].value
                != current_candidate_digest
            ):
                raise ValueError(
                    "verified subject state is stale against current candidate evidence"
                )

    if binding_counts["future_subject_binding_count"] != len(status_by_change):
        raise ValueError(
            "subject resolution candidate-binding count does not match inferred state"
        )
    if binding_counts["future_subject_binding_ambiguous"] != sum(
        facts[0].value == "ambiguous" for facts in status_by_change.values()
    ):
        raise ValueError(
            "subject resolution ambiguous-binding count does not match inferred state"
        )
    if binding_counts["future_subject_binding_missing"] != sum(
        facts[0].value == "no_candidate" for facts in status_by_change.values()
    ):
        raise ValueError(
            "subject resolution missing-binding count does not match inferred state"
        )



def apply_future_subject_resolution(
    future: SecurityTwin,
    resolution: FutureSubjectResolution,
    state: StateStore,
) -> SecurityTwin:
    """Record one explicit verified subject decision without graph promotion."""

    resolution.validate()
    validate_future_subject_snapshot(
        future, state,
        client_id=resolution.client_id, changeset_id=resolution.changeset_id,
    )
    nodes = {node.node_id: node for node in future.nodes}

    change_node = nodes.get(resolution.change_node_id)
    if change_node is None or change_node.kind is not TwinNodeKind.CHANGE:
        raise KeyError(f"unknown future change node {resolution.change_node_id!r}")
    change_attributes = dict(change_node.attributes)
    if len(change_attributes) != len(change_node.attributes):
        raise ValueError("subject resolution requires canonical change-node attributes")
    if change_attributes.get("changeset_id") != resolution.changeset_id:
        raise ValueError("subject resolution changeset_id does not match the change node")

    subject = nodes.get(resolution.subject_node_id)
    if subject is None:
        raise KeyError(f"unknown subject node {resolution.subject_node_id!r}")
    if subject.kind not in _ELIGIBLE_SUBJECT_KINDS:
        raise ValueError(
            f"node kind {subject.kind.value!r} cannot be a resolved change subject"
        )

    candidate_links = tuple(
        relationship
        for relationship in future.relationships
        if relationship.source_id == resolution.change_node_id
        and relationship.relation == "candidate_affects"
        and relationship.provenance is FactProvenance.INFERRED
    )
    if not candidate_links:
        raise ValueError(
            "subject resolution requires an existing inferred candidate_affects link"
        )
    if len(candidate_links) != 1:
        raise ValueError(
            "subject resolution requires exactly one inferred subject candidate"
        )
    if candidate_links[0].target_id != resolution.subject_node_id:
        raise ValueError(
            "subject resolution must select the sole inferred subject candidate"
        )

    binding_status_facts = tuple(
        fact
        for fact in future.facts
        if fact.subject_id == resolution.change_node_id
        and fact.predicate == "change.binding_status"
        and fact.provenance is FactProvenance.INFERRED
    )
    binding_count_facts = tuple(
        fact
        for fact in future.facts
        if fact.subject_id == resolution.change_node_id
        and fact.predicate == "change.candidate_count"
        and fact.provenance is FactProvenance.INFERRED
    )
    if len(binding_status_facts) != 1 or len(binding_count_facts) != 1:
        raise ValueError(
            "subject resolution requires canonical inferred candidate binding facts"
        )
    if (
        binding_status_facts[0].value != "single_candidate"
        or binding_count_facts[0].value != "1"
    ):
        raise ValueError(
            "subject resolution requires a canonical single-candidate binding"
        )
    candidate_evidence_refs = candidate_links[0].evidence_refs
    if (
        not candidate_evidence_refs
        or binding_status_facts[0].evidence_refs != candidate_evidence_refs
        or binding_count_facts[0].evidence_refs != candidate_evidence_refs
    ):
        raise ValueError(
            "subject resolution candidate binding evidence lineage is inconsistent"
        )

    candidate_evidence_sha256 = sha256(
        "\x1f".join(sorted(candidate_evidence_refs)).encode("utf-8")
    ).hexdigest()

    facts = _resolution_facts(resolution, candidate_evidence_sha256)
    relationship = _resolution_relationship(resolution)
    existing_facts = {fact.fact_id: fact for fact in future.facts}
    existing_relationships = {
        item.relationship_id: item for item in future.relationships
    }
    fact_collisions = [fact for fact in facts if fact.fact_id in existing_facts]
    relationship_collision = existing_relationships.get(
        relationship.relationship_id
    )
    exact_collision_replay = False
    if fact_collisions or relationship_collision is not None:
        facts_match = (
            len(fact_collisions) == len(facts)
            and all(existing_facts[fact.fact_id] == fact for fact in facts)
        )
        relationship_matches = relationship_collision == relationship
        if facts_match and relationship_matches:
            exact_collision_replay = True
        else:
            raise ValueError("subject resolution collides with existing twin data")

    if exact_collision_replay:
        replay_metadata = dict(future.metadata)
        if len(replay_metadata) != len(future.metadata):
            raise ValueError(
                "idempotent subject-resolution replay requires canonical metadata keys"
            )
        if (
            future.parent_twin_id != future.twin_id
            or future.parent_version is None
            or future.version != future.parent_version + 1
        ):
            raise ValueError(
                "idempotent subject-resolution replay requires canonical snapshot lineage"
            )
        if replay_metadata.get("future_subject_resolution") != "evidence_recorded":
            raise ValueError(
                "idempotent subject-resolution replay requires canonical resolution metadata"
            )
        replay_count = _parse_canonical_nonnegative_decimal(
            "idempotent subject-resolution replay resolution count",
            replay_metadata.get("future_subject_resolution_count", ""),
        )
        if replay_count < 1:
            raise ValueError(
                "idempotent subject-resolution replay requires a positive resolution count"
            )
        if replay_metadata.get("future_semantics") != "unresolved":
            raise ValueError(
                "idempotent subject-resolution replay requires unresolved future semantics"
            )
        verified_resolution_count = sum(
            1
            for item in future.relationships
            if item.relation == "verified_affects_subject"
            and item.provenance is FactProvenance.VERIFIED
        )
        if replay_count != verified_resolution_count:
            raise ValueError(
                "idempotent subject-resolution replay resolution count is non-canonical"
            )

    evidence = tuple(state.get_evidence(item) for item in resolution.evidence_ids)
    if any(item.run_id != resolution.run_id for item in evidence):
        raise ValueError("subject resolution evidence belongs to a different run")

    rationale_digest = sha256(resolution.rationale.strip().encode("utf-8")).hexdigest()
    evidence_twin_version = (
        future.parent_version
        if exact_collision_replay and future.parent_version is not None
        else future.version
    )
    expected_metadata = {
        "purpose": "future_subject_resolution",
        "decision_id": resolution.decision_id,
        "client_id": resolution.client_id,
        "future_twin_id": future.twin_id,
        "future_twin_version": str(evidence_twin_version),
        "changeset_id": resolution.changeset_id,
        "change_node_id": resolution.change_node_id,
        "subject_node_id": resolution.subject_node_id,
        "candidate_evidence_sha256": candidate_evidence_sha256,
        "resolution_basis": resolution.basis.value,
        "rationale_sha256": rationale_digest,
    }
    expected_kind = _EVIDENCE_KIND_BY_BASIS[resolution.basis]
    for item in evidence:
        if item.capability_id != "future-subject-resolution":
            raise ValueError(
                "subject resolution evidence capability does not match the decision contract"
            )
        if item.kind != expected_kind:
            raise ValueError(
                "subject resolution evidence kind does not match the decision basis"
            )
        try:
            _validate_bounded_identifier(
                "subject resolution evidence source",
                item.source,
                max_length=_MAX_EVIDENCE_SOURCE_LENGTH,
            )
        except ValueError as exc:
            raise ValueError(
                "subject resolution evidence source does not match the decision contract"
            ) from exc
        if (
            resolution.basis is SubjectResolutionBasis.OPERATOR_REVIEWED
            and item.source != "operator"
        ):
            raise ValueError(
                "subject resolution evidence source does not match the decision contract"
            )
        if (
            len(item.sha256) != 64
            or any(character not in "0123456789abcdef" for character in item.sha256)
        ):
            raise ValueError(
                "subject resolution evidence payload digest is non-canonical"
            )
        metadata = dict(item.metadata)
        if set(metadata) != set(expected_metadata):
            raise ValueError(
                "subject resolution evidence metadata keys are non-canonical"
            )
        for key, expected in expected_metadata.items():
            if metadata.get(key) != expected:
                raise ValueError(
                    f"subject resolution evidence metadata mismatch for {key!r}"
                )

    verified_subject_links = tuple(
        item
        for item in future.relationships
        if item.source_id == resolution.change_node_id
        and item.relation == "verified_affects_subject"
        and item.provenance is FactProvenance.VERIFIED
    )
    verified_subject_facts = tuple(
        fact
        for fact in future.facts
        if fact.subject_id == resolution.change_node_id
        and fact.predicate.startswith("future_subject.")
        and fact.provenance is FactProvenance.VERIFIED
    )
    if verified_subject_links or verified_subject_facts:
        canonical_facts = {fact.fact_id: fact for fact in facts}
        existing_subject_facts = {
            fact.fact_id: fact for fact in verified_subject_facts
        }
        exact_existing_resolution = (
            len(verified_subject_links) == 1
            and verified_subject_links[0] == relationship
            and existing_subject_facts == canonical_facts
        )
        if not exact_existing_resolution:
            raise ValueError(
                "future change node already has partial or conflicting verified subject state"
            )

    if exact_collision_replay:
        return future

    metadata = dict(future.metadata)
    prior_count = _parse_canonical_nonnegative_decimal(
        "subject resolution metadata count",
        metadata.get("future_subject_resolution_count", "0"),
    )
    metadata.update(
        {
            "future_subject_resolution": "evidence_recorded",
            "future_subject_resolution_count": str(prior_count + 1),
            "future_semantics": "unresolved",
        }
    )

    snapshot = replace(
        future,
        version=future.version + 1,
        parent_twin_id=future.twin_id,
        parent_version=future.version,
        facts=future.facts + facts,
        relationships=future.relationships + (relationship,),
        metadata=tuple(sorted(metadata.items())),
    )
    snapshot.validate()

    if snapshot.attack_paths != future.attack_paths:
        raise AssertionError("subject resolution must not mutate attack paths")
    return snapshot
