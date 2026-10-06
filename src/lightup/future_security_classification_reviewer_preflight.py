"""Independent-operator preflight for ST5 classification review.

This stage consumes only a strict, live-valid persisted classification-review
request and binds a second LightUp operator identity to the later review.
It proves reviewer eligibility and independence only: no classification is
selected, no transition resolution is created, and no action authority is
granted.
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
from .future_security_classification_review_request import (
    FutureSecurityClassificationReviewRequest,
)
from .future_security_classification_review_request_consumer import (
    load_and_validate_future_security_classification_review_request,
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
    FutureSecurityEvidenceSufficiencyAttestation,
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


CLASSIFICATION_REVIEWER_PREFLIGHT_SCHEMA_VERSION = (
    "st5.classification_reviewer_preflight.v1"
)


@dataclass(frozen=True)
class FutureSecurityClassificationReviewerPreflight:
    schema_version: str
    client_id: str
    classification_review_request_sha256: str
    evidence_collection_request_sha256: str
    freshness_constraints_sha256: str
    admission_sha256: str
    metadata_review_sha256: str
    sufficiency_request_sha256: str
    sufficiency_verifier_preflight_sha256: str
    attestation_sha256: str
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    candidate_classification_claim: AttackPathTransitionClassification
    sufficiency_verifier_user_id: str
    classification_reviewer_user_id: str
    classification_reviewer_role: str
    independent_reviewer_verified: bool
    eligible_for_classification_review: bool
    preflight_sha256: str
    classification_decision_created: bool = False
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


def _canonical_reviewer_user_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(
            "classification reviewer user_id must be a canonical non-empty string"
        )
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("classification reviewer user_id is not canonical")
    return value


def _preflight_digest(
    request: FutureSecurityClassificationReviewRequest,
    *,
    classification_reviewer_user_id: str,
) -> str:
    payload = {
        "schema_version": CLASSIFICATION_REVIEWER_PREFLIGHT_SCHEMA_VERSION,
        "client_id": request.client_id,
        "classification_review_request_sha256": (
            request.classification_review_request_sha256
        ),
        "evidence_collection_request_sha256": (
            request.evidence_collection_request_sha256
        ),
        "freshness_constraints_sha256": request.freshness_constraints_sha256,
        "admission_sha256": request.admission_sha256,
        "metadata_review_sha256": request.metadata_review_sha256,
        "sufficiency_request_sha256": request.sufficiency_request_sha256,
        "sufficiency_verifier_preflight_sha256": request.verifier_preflight_sha256,
        "attestation_sha256": request.attestation_sha256,
        "source_resolution_id": request.source_resolution_id,
        "change_node_id": request.change_node_id,
        "subject_node_id": request.subject_node_id,
        "candidate_run_id": request.candidate_run_id,
        "candidate_evidence_ids": list(request.candidate_evidence_ids),
        "candidate_capability_ids": list(request.candidate_capability_ids),
        "candidate_classification_claim": (
            request.candidate_classification_claim.value
        ),
        "sufficiency_verifier_user_id": request.verifier_user_id,
        "classification_reviewer_user_id": classification_reviewer_user_id,
        "classification_reviewer_role": "operator",
        "independent_reviewer_verified": True,
        "eligible_for_classification_review": True,
        "classification_decision_created": False,
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


def preflight_future_security_classification_reviewer(
    persisted_classification_request: object,
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    sufficiency_verifier: AccessContext,
    classification_reviewer: AccessContext,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityClassificationReviewerPreflight:
    """Bind a distinct operator to the later classification-review decision."""

    classification_request = (
        load_and_validate_future_security_classification_review_request(
            persisted_classification_request,
            attestation,
            preflight,
            sufficiency_request,
            review,
            admission,
            constraints,
            verifier=sufficiency_verifier,
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
    )

    if not isinstance(classification_reviewer, AccessContext):
        raise ValueError("classification reviewer must be an AccessContext")
    classification_reviewer.require_operator("classification review")
    reviewer_user_id = _canonical_reviewer_user_id(
        classification_reviewer.user_id
    )
    if reviewer_user_id == classification_request.verifier_user_id:
        raise ValueError(
            "classification reviewer must be independent from sufficiency verifier"
        )

    digest = _preflight_digest(
        classification_request,
        classification_reviewer_user_id=reviewer_user_id,
    )
    return FutureSecurityClassificationReviewerPreflight(
        schema_version=CLASSIFICATION_REVIEWER_PREFLIGHT_SCHEMA_VERSION,
        client_id=classification_request.client_id,
        classification_review_request_sha256=(
            classification_request.classification_review_request_sha256
        ),
        evidence_collection_request_sha256=(
            classification_request.evidence_collection_request_sha256
        ),
        freshness_constraints_sha256=(
            classification_request.freshness_constraints_sha256
        ),
        admission_sha256=classification_request.admission_sha256,
        metadata_review_sha256=classification_request.metadata_review_sha256,
        sufficiency_request_sha256=(
            classification_request.sufficiency_request_sha256
        ),
        sufficiency_verifier_preflight_sha256=(
            classification_request.verifier_preflight_sha256
        ),
        attestation_sha256=classification_request.attestation_sha256,
        source_resolution_id=classification_request.source_resolution_id,
        change_node_id=classification_request.change_node_id,
        subject_node_id=classification_request.subject_node_id,
        candidate_run_id=classification_request.candidate_run_id,
        candidate_evidence_ids=classification_request.candidate_evidence_ids,
        candidate_capability_ids=classification_request.candidate_capability_ids,
        candidate_classification_claim=(
            classification_request.candidate_classification_claim
        ),
        sufficiency_verifier_user_id=classification_request.verifier_user_id,
        classification_reviewer_user_id=reviewer_user_id,
        classification_reviewer_role="operator",
        independent_reviewer_verified=True,
        eligible_for_classification_review=True,
        preflight_sha256=digest,
    )


def validate_future_security_classification_reviewer_preflight(
    reviewer_preflight: FutureSecurityClassificationReviewerPreflight,
    persisted_classification_request: object,
    attestation: FutureSecurityEvidenceSufficiencyAttestation,
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    sufficiency_verifier: AccessContext,
    classification_reviewer: AccessContext,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityClassificationReviewerPreflight:
    """Rebuild classification-reviewer eligibility from the live strict request."""

    if not isinstance(
        reviewer_preflight,
        FutureSecurityClassificationReviewerPreflight,
    ):
        raise ValueError(
            "reviewer_preflight must be FutureSecurityClassificationReviewerPreflight"
        )
    rebuilt = preflight_future_security_classification_reviewer(
        persisted_classification_request,
        attestation,
        preflight,
        sufficiency_request,
        review,
        admission,
        constraints,
        sufficiency_verifier=sufficiency_verifier,
        classification_reviewer=classification_reviewer,
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
    if rebuilt != reviewer_preflight:
        raise ValueError(
            "classification reviewer preflight does not match live validated lineage"
        )
    return rebuilt
