"""Operator-only preflight for independent ST5 evidence-sufficiency review.

This stage binds a live-valid sufficiency-review request to an existing LightUp
authorization context. It proves role eligibility only: no evidence-sufficiency
decision, classification selection, transition resolution, or execution
authority is created.
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
from .future_security_evidence_sufficiency_review_request import (
    FutureSecurityEvidenceSufficiencyReviewRequest,
    validate_future_security_evidence_sufficiency_review_request,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION = (
    "st5.evidence_sufficiency_verifier_preflight.v1"
)


@dataclass(frozen=True)
class FutureSecurityEvidenceSufficiencyVerifierPreflight:
    schema_version: str
    client_id: str
    sufficiency_request_sha256: str
    metadata_review_sha256: str
    admission_sha256: str
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    candidate_classification_claim: AttackPathTransitionClassification
    verifier_user_id: str
    verifier_role: str
    eligible_for_sufficiency_review: bool
    preflight_sha256: str
    sufficiency_decision_created: bool = False
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


def _canonical_verifier_user_id(value: object) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError("verifier user_id must be a canonical non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError("verifier user_id is not canonical")
    return value


def _preflight_digest(
    request: FutureSecurityEvidenceSufficiencyReviewRequest,
    *,
    verifier_user_id: str,
) -> str:
    payload = {
        "schema_version": SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION,
        "client_id": request.client_id,
        "sufficiency_request_sha256": request.sufficiency_request_sha256,
        "metadata_review_sha256": request.metadata_review_sha256,
        "admission_sha256": request.admission_sha256,
        "source_resolution_id": request.source_resolution_id,
        "change_node_id": request.change_node_id,
        "subject_node_id": request.subject_node_id,
        "candidate_run_id": request.candidate_run_id,
        "candidate_evidence_ids": list(request.candidate_evidence_ids),
        "candidate_capability_ids": list(request.candidate_capability_ids),
        "candidate_classification_claim": request.candidate_classification_claim.value,
        "verifier_user_id": verifier_user_id,
        "verifier_role": "operator",
        "eligible_for_sufficiency_review": True,
        "sufficiency_decision_created": False,
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


def preflight_future_security_evidence_sufficiency_verifier(
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
) -> FutureSecurityEvidenceSufficiencyVerifierPreflight:
    """Prove only that an operator context may perform the later review."""

    validate_future_security_evidence_sufficiency_review_request(
        sufficiency_request,
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
    if not isinstance(verifier, AccessContext):
        raise ValueError("verifier must be an AccessContext")
    verifier.require_operator("evidence sufficiency review")
    verifier_user_id = _canonical_verifier_user_id(verifier.user_id)

    digest = _preflight_digest(
        sufficiency_request,
        verifier_user_id=verifier_user_id,
    )
    return FutureSecurityEvidenceSufficiencyVerifierPreflight(
        schema_version=SUFFICIENCY_VERIFIER_PREFLIGHT_SCHEMA_VERSION,
        client_id=sufficiency_request.client_id,
        sufficiency_request_sha256=sufficiency_request.sufficiency_request_sha256,
        metadata_review_sha256=sufficiency_request.metadata_review_sha256,
        admission_sha256=sufficiency_request.admission_sha256,
        source_resolution_id=sufficiency_request.source_resolution_id,
        change_node_id=sufficiency_request.change_node_id,
        subject_node_id=sufficiency_request.subject_node_id,
        candidate_run_id=sufficiency_request.candidate_run_id,
        candidate_evidence_ids=sufficiency_request.candidate_evidence_ids,
        candidate_capability_ids=sufficiency_request.candidate_capability_ids,
        candidate_classification_claim=(
            sufficiency_request.candidate_classification_claim
        ),
        verifier_user_id=verifier_user_id,
        verifier_role="operator",
        eligible_for_sufficiency_review=True,
        preflight_sha256=digest,
    )


def validate_future_security_evidence_sufficiency_verifier_preflight(
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
) -> FutureSecurityEvidenceSufficiencyVerifierPreflight:
    """Rebuild a persisted verifier preflight against live request lineage."""

    if not isinstance(
        preflight,
        FutureSecurityEvidenceSufficiencyVerifierPreflight,
    ):
        raise ValueError(
            "preflight must be FutureSecurityEvidenceSufficiencyVerifierPreflight"
        )
    rebuilt = preflight_future_security_evidence_sufficiency_verifier(
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
    if rebuilt != preflight:
        raise ValueError(
            "evidence sufficiency verifier preflight does not match live validated lineage"
        )
    return rebuilt
