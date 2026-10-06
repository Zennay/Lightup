"""Fail-closed handoff into independent ST5 evidence-sufficiency review.

This module does not decide whether candidate evidence is sufficient and does
not select a security classification. It packages the exact live-validated
freshness + metadata-contract lineage for a later independent verifier.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .future_security_evidence_collection_request import (
    FutureSecurityEvidenceCollectionRequest,
)
from .future_security_evidence_freshness import (
    FutureSecurityEvidenceFreshnessConstraints,
)
from .future_security_evidence_freshness_admission import (
    FutureSecurityEvidenceFreshnessAdmission,
)
from .future_security_evidence_metadata_contract_review import (
    FutureSecurityEvidenceMetadataContractReview,
    validate_future_security_evidence_metadata_contract_review,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION = (
    "st5.evidence_sufficiency_review_request.v1"
)
REQUIRED_SUFFICIENCY_REVIEW_CHECKS = (
    "classification_justification",
    "evidence_sufficiency",
)


@dataclass(frozen=True)
class FutureSecurityEvidenceSufficiencyReviewRequest:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    request_sha256: str
    constraints_sha256: str
    admission_sha256: str
    metadata_review_sha256: str
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    candidate_classification_claim: AttackPathTransitionClassification
    required_checks: tuple[str, ...]
    sufficiency_request_sha256: str
    metadata_contract_verified: bool = True
    freshness_check_passed: bool = True
    independent_verifier_required: bool = True
    review_required: bool = True
    evidence_sufficiency_evaluated: bool = False
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
        payload = asdict(self)
        payload["candidate_classification_claim"] = (
            self.candidate_classification_claim.value
        )
        return payload

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _sufficiency_request_digest(
    review: FutureSecurityEvidenceMetadataContractReview,
) -> str:
    payload = {
        "schema_version": SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
        "client_id": review.client_id,
        "current_twin_id": review.current_twin_id,
        "current_twin_version": review.current_twin_version,
        "twin_id": review.twin_id,
        "twin_version": review.twin_version,
        "changeset_id": review.changeset_id,
        "request_sha256": review.request_sha256,
        "constraints_sha256": review.constraints_sha256,
        "admission_sha256": review.admission_sha256,
        "metadata_review_sha256": review.review_sha256,
        "source_resolution_id": review.source_resolution_id,
        "change_node_id": review.change_node_id,
        "subject_node_id": review.subject_node_id,
        "candidate_run_id": review.candidate_run_id,
        "candidate_evidence_ids": list(review.candidate_evidence_ids),
        "candidate_capability_ids": list(review.candidate_capability_ids),
        "candidate_classification_claim": (
            review.candidate_classification_claim.value
        ),
        "required_checks": list(REQUIRED_SUFFICIENCY_REVIEW_CHECKS),
        "metadata_contract_verified": True,
        "freshness_check_passed": True,
        "independent_verifier_required": True,
        "review_required": True,
        "evidence_sufficiency_evaluated": False,
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


def build_future_security_evidence_sufficiency_review_request(
    review: FutureSecurityEvidenceMetadataContractReview,
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
) -> FutureSecurityEvidenceSufficiencyReviewRequest:
    """Package a live-valid candidate review for an independent verifier."""

    validate_future_security_evidence_metadata_contract_review(
        review,
        admission,
        constraints,
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

    sufficiency_request_sha256 = _sufficiency_request_digest(review)
    return FutureSecurityEvidenceSufficiencyReviewRequest(
        schema_version=SUFFICIENCY_REVIEW_REQUEST_SCHEMA_VERSION,
        client_id=review.client_id,
        current_twin_id=review.current_twin_id,
        current_twin_version=review.current_twin_version,
        twin_id=review.twin_id,
        twin_version=review.twin_version,
        changeset_id=review.changeset_id,
        request_sha256=review.request_sha256,
        constraints_sha256=review.constraints_sha256,
        admission_sha256=review.admission_sha256,
        metadata_review_sha256=review.review_sha256,
        source_resolution_id=review.source_resolution_id,
        change_node_id=review.change_node_id,
        subject_node_id=review.subject_node_id,
        candidate_run_id=review.candidate_run_id,
        candidate_evidence_ids=review.candidate_evidence_ids,
        candidate_capability_ids=review.candidate_capability_ids,
        candidate_classification_claim=review.candidate_classification_claim,
        required_checks=REQUIRED_SUFFICIENCY_REVIEW_CHECKS,
        sufficiency_request_sha256=sufficiency_request_sha256,
    )


def validate_future_security_evidence_sufficiency_review_request(
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
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
) -> FutureSecurityEvidenceSufficiencyReviewRequest:
    """Rebuild a persisted sufficiency-review request against live evidence."""

    if not isinstance(
        sufficiency_request,
        FutureSecurityEvidenceSufficiencyReviewRequest,
    ):
        raise ValueError(
            "sufficiency_request must be "
            "FutureSecurityEvidenceSufficiencyReviewRequest"
        )

    rebuilt = build_future_security_evidence_sufficiency_review_request(
        review,
        admission,
        constraints,
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
    if rebuilt != sufficiency_request:
        raise ValueError(
            "evidence sufficiency review request does not match live validated lineage"
        )
    return rebuilt
