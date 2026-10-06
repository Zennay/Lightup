"""Fail-closed handoff into a later ST5 classification review.

This stage consumes a live-validated evidence-sufficiency attestation and only
creates a bounded request when the operator has explicitly attested that the
candidate evidence is sufficient and its classification claim is justified.

The request does not itself select a LightUp security classification, create a
transition resolution, or grant execution/remediation/retest/deployment
authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .domain import AccessContext
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
)
from .future_security_evidence_sufficiency_attestation import (
    EvidenceSufficiencyAttestationDisposition,
    FutureSecurityEvidenceSufficiencyAttestation,
    validate_future_security_evidence_sufficiency_attestation,
)
from .future_security_evidence_sufficiency_review_request import (
    FutureSecurityEvidenceSufficiencyReviewRequest,
)
from .future_security_evidence_sufficiency_verifier_preflight import (
    FutureSecurityEvidenceSufficiencyVerifierPreflight,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION = (
    "st5.classification_review_request.v1"
)


@dataclass(frozen=True)
class FutureSecurityClassificationReviewRequest:
    schema_version: str
    client_id: str
    evidence_collection_request_sha256: str
    freshness_constraints_sha256: str
    admission_sha256: str
    metadata_review_sha256: str
    sufficiency_request_sha256: str
    verifier_preflight_sha256: str
    attestation_sha256: str
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    candidate_classification_claim: AttackPathTransitionClassification
    verifier_user_id: str
    classification_review_request_sha256: str
    evidence_sufficient: bool = True
    classification_claim_justified: bool = True
    sufficiency_decision_created: bool = True
    evidence_sufficiency_evaluated: bool = True
    classification_justification_evaluated: bool = True
    eligible_for_classification_review: bool = True
    classification_review_required: bool = True
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


def _classification_review_request_digest(
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
) -> str:
    payload = {
        "schema_version": CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION,
        "client_id": attestation.client_id,
        "evidence_collection_request_sha256": sufficiency_request.request_sha256,
        "freshness_constraints_sha256": sufficiency_request.constraints_sha256,
        "admission_sha256": attestation.admission_sha256,
        "metadata_review_sha256": attestation.metadata_review_sha256,
        "sufficiency_request_sha256": attestation.sufficiency_request_sha256,
        "verifier_preflight_sha256": attestation.verifier_preflight_sha256,
        "attestation_sha256": attestation.attestation_sha256,
        "source_resolution_id": attestation.source_resolution_id,
        "change_node_id": attestation.change_node_id,
        "subject_node_id": attestation.subject_node_id,
        "candidate_run_id": attestation.candidate_run_id,
        "candidate_evidence_ids": list(attestation.candidate_evidence_ids),
        "candidate_capability_ids": list(attestation.candidate_capability_ids),
        "candidate_classification_claim": (
            attestation.candidate_classification_claim.value
        ),
        "verifier_user_id": attestation.verifier_user_id,
        "evidence_sufficient": True,
        "classification_claim_justified": True,
        "sufficiency_decision_created": True,
        "evidence_sufficiency_evaluated": True,
        "classification_justification_evaluated": True,
        "eligible_for_classification_review": True,
        "classification_review_required": True,
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


def build_future_security_classification_review_request(
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    verifier: AccessContext,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityClassificationReviewRequest:
    """Create review eligibility only from a live-valid positive attestation."""

    validate_future_security_evidence_sufficiency_attestation(
        attestation,
        preflight,
        sufficiency_request,
        review,
        admission,
        constraints,
        verifier=verifier,
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

    if (
        attestation.disposition
        is not EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED
        or not attestation.evidence_sufficient
        or not attestation.classification_claim_justified
        or attestation.needs_more_evidence
        or not attestation.eligible_for_classification_review
    ):
        raise ValueError(
            "classification review requires a sufficient, justified live attestation"
        )

    digest = _classification_review_request_digest(
        attestation,
        sufficiency_request,
    )
    return FutureSecurityClassificationReviewRequest(
        schema_version=CLASSIFICATION_REVIEW_REQUEST_SCHEMA_VERSION,
        client_id=attestation.client_id,
        evidence_collection_request_sha256=sufficiency_request.request_sha256,
        freshness_constraints_sha256=sufficiency_request.constraints_sha256,
        admission_sha256=attestation.admission_sha256,
        metadata_review_sha256=attestation.metadata_review_sha256,
        sufficiency_request_sha256=attestation.sufficiency_request_sha256,
        verifier_preflight_sha256=attestation.verifier_preflight_sha256,
        attestation_sha256=attestation.attestation_sha256,
        source_resolution_id=attestation.source_resolution_id,
        change_node_id=attestation.change_node_id,
        subject_node_id=attestation.subject_node_id,
        candidate_run_id=attestation.candidate_run_id,
        candidate_evidence_ids=attestation.candidate_evidence_ids,
        candidate_capability_ids=attestation.candidate_capability_ids,
        candidate_classification_claim=attestation.candidate_classification_claim,
        verifier_user_id=attestation.verifier_user_id,
        classification_review_request_sha256=digest,
    )


def validate_future_security_classification_review_request(
    classification_request: FutureSecurityClassificationReviewRequest,
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    verifier: AccessContext,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityClassificationReviewRequest:
    """Rebuild a persisted request against the live evidence lineage."""

    if not isinstance(
        classification_request,
        FutureSecurityClassificationReviewRequest,
    ):
        raise ValueError(
            "classification_request must be FutureSecurityClassificationReviewRequest"
        )

    rebuilt = build_future_security_classification_review_request(
        attestation,
        preflight,
        sufficiency_request,
        review,
        admission,
        constraints,
        verifier=verifier,
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
    if rebuilt != classification_request:
        raise ValueError(
            "classification review request does not match live validated lineage"
        )
    return rebuilt
