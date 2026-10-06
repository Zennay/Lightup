"""Read-only freshness admission for candidate ST5 evidence.

This module proves only that already-existing candidate evidence is fresh
relative to an unresolved evidence-gap constraint. It does not collect
evidence, select a tool/capability/target, or classify a security transition.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .engagements import AssessmentMode
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    FutureAttackPathTransitionResolution,
)
from .future_security_evidence_collection_request import (
    FutureSecurityEvidenceCollectionRequest,
)
from .future_security_evidence_freshness import (
    FutureSecurityEvidenceFreshnessConstraints,
    validate_future_security_evidence_freshness_constraints,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


ADMISSION_SCHEMA_VERSION = "st5.evidence_freshness_admission.v1"


@dataclass(frozen=True)
class CandidateEvidenceFingerprint:
    evidence_id: str
    run_id: str
    capability_id: str
    kind: str
    sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityEvidenceFreshnessAdmission:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    request_sha256: str
    constraints_sha256: str
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence: tuple[CandidateEvidenceFingerprint, ...]
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    admission_sha256: str
    freshness_check_passed: bool = True
    evidence_suitability_evaluated: bool = False
    classification_selected: bool = False
    transition_resolution_created: bool = False
    collection_authorized: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    remediation_authoring_allowed: bool = False
    future_state_retest_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _require_identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a canonical non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} is not canonical")
    return value


def _require_sha256(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a canonical lowercase SHA-256")
    return value


def _require_canonical_ids(
    values: tuple[str, ...],
    *,
    name: str,
) -> tuple[str, ...]:
    if not isinstance(values, tuple) or not values:
        raise ValueError(f"{name} must be a non-empty immutable tuple")
    parsed = tuple(_require_identifier(value, name=name) for value in values)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{name} must be sorted and unique")
    return parsed


def _admission_digest(
    *,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    source_resolution_id: str,
    change_node_id: str,
    subject_node_id: str,
    candidate_run_id: str,
    candidate_evidence: tuple[CandidateEvidenceFingerprint, ...],
    candidate_capability_ids: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": ADMISSION_SCHEMA_VERSION,
        "client_id": constraints.client_id,
        "current_twin_id": constraints.current_twin_id,
        "current_twin_version": constraints.current_twin_version,
        "twin_id": constraints.twin_id,
        "twin_version": constraints.twin_version,
        "changeset_id": constraints.changeset_id,
        "request_sha256": constraints.request_sha256,
        "constraints_sha256": constraints.constraints_sha256,
        "source_resolution_id": source_resolution_id,
        "change_node_id": change_node_id,
        "subject_node_id": subject_node_id,
        "candidate_run_id": candidate_run_id,
        "candidate_evidence": [
            evidence.as_dict() for evidence in candidate_evidence
        ],
        "candidate_evidence_ids": [
            evidence.evidence_id for evidence in candidate_evidence
        ],
        "candidate_capability_ids": list(candidate_capability_ids),
        "freshness_check_passed": True,
        "evidence_suitability_evaluated": False,
        "classification_selected": False,
        "transition_resolution_created": False,
        "collection_authorized": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
        "remediation_authoring_allowed": False,
        "future_state_retest_allowed": False,
        "deployment_authorized": False,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
    }
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def admit_future_security_evidence_freshness(
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    source_resolution_id: str,
    candidate_evidence_ids: tuple[str, ...],
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessAdmission:
    """Prove candidate evidence is fresh without evaluating its security meaning."""

    validate_future_security_evidence_freshness_constraints(
        constraints,
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        source_contexts,
        state,
    )
    _require_identifier(source_resolution_id, name="source_resolution_id")
    candidate_evidence_ids = _require_canonical_ids(
        candidate_evidence_ids,
        name="candidate_evidence_ids",
    )

    matches = tuple(
        item
        for item in constraints.items
        if item.source_resolution_id == source_resolution_id
    )
    if len(matches) != 1:
        raise ValueError(
            "freshness admission requires exactly one source constraint item"
        )
    item = matches[0]

    source_resolutions = tuple(
        resolution
        for resolution in resolutions
        if resolution.resolution_id == source_resolution_id
    )
    if len(source_resolutions) != 1:
        raise ValueError("freshness admission source resolution is missing or ambiguous")
    source_resolution = source_resolutions[0]

    source_run_contexts = tuple(
        context
        for context in source_contexts
        if context.run_id == source_resolution.run_id
    )
    if len(source_run_contexts) != 1:
        raise ValueError("freshness admission source RunContext is missing or ambiguous")
    source_context = source_run_contexts[0]

    if not isinstance(candidate_context, RunContext):
        raise ValueError("candidate_context must be a RunContext")
    _require_identifier(candidate_context.run_id, name="candidate run_id")
    _require_identifier(candidate_context.client_id, name="candidate client_id")
    _require_identifier(candidate_context.engagement_id, name="candidate engagement_id")
    if (
        not candidate_context.is_lab
        or candidate_context.mode is not AssessmentMode.LAB_AUTONOMOUS
    ):
        raise PermissionError("candidate freshness evidence must come from a lab run")
    if candidate_context.client_id != constraints.client_id:
        raise ValueError("candidate freshness RunContext belongs to another client")
    if candidate_context.engagement_id != source_context.engagement_id:
        raise ValueError("candidate freshness RunContext belongs to another engagement")
    if candidate_context.run_id in item.forbidden_run_ids:
        raise ValueError("candidate freshness run reuses a forbidden prior run")
    if set(candidate_evidence_ids).intersection(item.forbidden_evidence_ids):
        raise ValueError("candidate freshness evidence reuses forbidden prior evidence")

    fingerprints: list[CandidateEvidenceFingerprint] = []
    capabilities: set[str] = set()
    for evidence_id in candidate_evidence_ids:
        record = state.get_evidence(evidence_id)
        _require_identifier(record.evidence_id, name="candidate evidence_id")
        _require_identifier(record.run_id, name="candidate evidence run_id")
        _require_identifier(record.capability_id, name="candidate evidence capability_id")
        _require_identifier(record.kind, name="candidate evidence kind")
        _require_sha256(
            record.sha256,
            name=f"candidate evidence {evidence_id!r} sha256",
        )
        if record.run_id != candidate_context.run_id:
            raise ValueError("candidate freshness evidence belongs to another run")
        capabilities.add(record.capability_id)
        fingerprints.append(
            CandidateEvidenceFingerprint(
                evidence_id=record.evidence_id,
                run_id=record.run_id,
                capability_id=record.capability_id,
                kind=record.kind,
                sha256=record.sha256,
            )
        )

    candidate_evidence = tuple(
        sorted(fingerprints, key=lambda evidence: evidence.evidence_id)
    )
    if tuple(evidence.evidence_id for evidence in candidate_evidence) != candidate_evidence_ids:
        raise ValueError("candidate freshness evidence IDs are not canonical")
    candidate_capability_ids = tuple(sorted(capabilities))
    if not candidate_capability_ids:
        raise ValueError("candidate freshness evidence must expose a capability")

    admission_sha256 = _admission_digest(
        constraints=constraints,
        source_resolution_id=item.source_resolution_id,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        candidate_run_id=candidate_context.run_id,
        candidate_evidence=candidate_evidence,
        candidate_capability_ids=candidate_capability_ids,
    )
    return FutureSecurityEvidenceFreshnessAdmission(
        schema_version=ADMISSION_SCHEMA_VERSION,
        client_id=constraints.client_id,
        current_twin_id=constraints.current_twin_id,
        current_twin_version=constraints.current_twin_version,
        twin_id=constraints.twin_id,
        twin_version=constraints.twin_version,
        changeset_id=constraints.changeset_id,
        request_sha256=constraints.request_sha256,
        constraints_sha256=constraints.constraints_sha256,
        source_resolution_id=item.source_resolution_id,
        change_node_id=item.change_node_id,
        subject_node_id=item.subject_node_id,
        candidate_run_id=candidate_context.run_id,
        candidate_evidence=candidate_evidence,
        candidate_evidence_ids=candidate_evidence_ids,
        candidate_capability_ids=candidate_capability_ids,
        admission_sha256=admission_sha256,
    )


def validate_future_security_evidence_freshness_admission(
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessAdmission:
    """Rebuild a persisted admission against live candidate evidence before use."""

    if not isinstance(admission, FutureSecurityEvidenceFreshnessAdmission):
        raise ValueError("admission must be FutureSecurityEvidenceFreshnessAdmission")
    rebuilt = admit_future_security_evidence_freshness(
        constraints,
        source_resolution_id=admission.source_resolution_id,
        candidate_evidence_ids=admission.candidate_evidence_ids,
        candidate_context=candidate_context,
        request=request,
        plan=plan,
        report=report,
        preview=preview,
        proposal=proposal,
        resolutions=resolutions,
        source_contexts=source_contexts,
        state=state,
    )
    if rebuilt != admission:
        raise ValueError(
            "evidence freshness admission does not match live validated evidence"
        )
    return rebuilt
