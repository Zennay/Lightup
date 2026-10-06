"""Operator evidence-sufficiency attestation for ST5.

This stage records an explicit operator judgment for evidence sufficiency and
classification-claim justification. It never selects the LightUp security
classification, creates a transition resolution, or grants execution authority.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
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
)
from .future_security_evidence_sufficiency_verifier_preflight import (
    FutureSecurityEvidenceSufficiencyVerifierPreflight,
    validate_future_security_evidence_sufficiency_verifier_preflight,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


SUFFICIENCY_ATTESTATION_SCHEMA_VERSION = "st5.evidence_sufficiency_attestation.v1"


class EvidenceSufficiencyAttestationDisposition(str, Enum):
    INSUFFICIENT_FOR_CLASSIFICATION = "insufficient_for_classification"
    SUFFICIENT_CLAIM_UNJUSTIFIED = "sufficient_claim_unjustified"
    SUFFICIENT_CLAIM_JUSTIFIED = "sufficient_claim_justified"


@dataclass(frozen=True)
class FutureSecurityEvidenceSufficiencyAttestation:
    schema_version: str
    client_id: str
    sufficiency_request_sha256: str
    verifier_preflight_sha256: str
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
    disposition: EvidenceSufficiencyAttestationDisposition
    evidence_sufficient: bool
    classification_claim_justified: bool
    needs_more_evidence: bool
    eligible_for_classification_review: bool
    attestation_sha256: str
    sufficiency_decision_created: bool = True
    evidence_sufficiency_evaluated: bool = True
    classification_justification_evaluated: bool = True
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
        payload["disposition"] = self.disposition.value
        return payload

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _derived_disposition_flags(
    disposition: EvidenceSufficiencyAttestationDisposition,
) -> tuple[bool, bool, bool, bool]:
    if disposition is EvidenceSufficiencyAttestationDisposition.INSUFFICIENT_FOR_CLASSIFICATION:
        return False, False, True, False
    if disposition is EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_UNJUSTIFIED:
        return True, False, False, False
    if disposition is EvidenceSufficiencyAttestationDisposition.SUFFICIENT_CLAIM_JUSTIFIED:
        return True, True, False, True
    raise ValueError("unsupported evidence sufficiency attestation disposition")


def _attestation_digest(
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    *,
    disposition: EvidenceSufficiencyAttestationDisposition,
    evidence_sufficient: bool,
    classification_claim_justified: bool,
    needs_more_evidence: bool,
    eligible_for_classification_review: bool,
) -> str:
    payload = {
        "schema_version": SUFFICIENCY_ATTESTATION_SCHEMA_VERSION,
        "client_id": preflight.client_id,
        "sufficiency_request_sha256": preflight.sufficiency_request_sha256,
        "verifier_preflight_sha256": preflight.preflight_sha256,
        "metadata_review_sha256": preflight.metadata_review_sha256,
        "admission_sha256": preflight.admission_sha256,
        "source_resolution_id": preflight.source_resolution_id,
        "change_node_id": preflight.change_node_id,
        "subject_node_id": preflight.subject_node_id,
        "candidate_run_id": preflight.candidate_run_id,
        "candidate_evidence_ids": list(preflight.candidate_evidence_ids),
        "candidate_capability_ids": list(preflight.candidate_capability_ids),
        "candidate_classification_claim": preflight.candidate_classification_claim.value,
        "verifier_user_id": preflight.verifier_user_id,
        "disposition": disposition.value,
        "evidence_sufficient": evidence_sufficient,
        "classification_claim_justified": classification_claim_justified,
        "needs_more_evidence": needs_more_evidence,
        "eligible_for_classification_review": eligible_for_classification_review,
        "sufficiency_decision_created": True,
        "evidence_sufficiency_evaluated": True,
        "classification_justification_evaluated": True,
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


def attest_future_security_evidence_sufficiency(
    preflight: FutureSecurityEvidenceSufficiencyVerifierPreflight,
    sufficiency_request: FutureSecurityEvidenceSufficiencyReviewRequest,
    review: FutureSecurityEvidenceMetadataContractReview,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    *,
    verifier: AccessContext,
    disposition: EvidenceSufficiencyAttestationDisposition,
    candidate_context: RunContext,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceSufficiencyAttestation:
    """Record the operator's review outcome without selecting classification."""

    validate_future_security_evidence_sufficiency_verifier_preflight(
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
    if not isinstance(disposition, EvidenceSufficiencyAttestationDisposition):
        raise ValueError(
            "disposition must be EvidenceSufficiencyAttestationDisposition"
        )
    if verifier.user_id != preflight.verifier_user_id:
        raise ValueError("attestation verifier must match verifier preflight")

    (
        evidence_sufficient,
        classification_claim_justified,
        needs_more_evidence,
        eligible_for_classification_review,
    ) = _derived_disposition_flags(disposition)

    digest = _attestation_digest(
        preflight,
        disposition=disposition,
        evidence_sufficient=evidence_sufficient,
        classification_claim_justified=classification_claim_justified,
        needs_more_evidence=needs_more_evidence,
        eligible_for_classification_review=eligible_for_classification_review,
    )
    return FutureSecurityEvidenceSufficiencyAttestation(
        schema_version=SUFFICIENCY_ATTESTATION_SCHEMA_VERSION,
        client_id=preflight.client_id,
        sufficiency_request_sha256=preflight.sufficiency_request_sha256,
        verifier_preflight_sha256=preflight.preflight_sha256,
        metadata_review_sha256=preflight.metadata_review_sha256,
        admission_sha256=preflight.admission_sha256,
        source_resolution_id=preflight.source_resolution_id,
        change_node_id=preflight.change_node_id,
        subject_node_id=preflight.subject_node_id,
        candidate_run_id=preflight.candidate_run_id,
        candidate_evidence_ids=preflight.candidate_evidence_ids,
        candidate_capability_ids=preflight.candidate_capability_ids,
        candidate_classification_claim=preflight.candidate_classification_claim,
        verifier_user_id=preflight.verifier_user_id,
        disposition=disposition,
        evidence_sufficient=evidence_sufficient,
        classification_claim_justified=classification_claim_justified,
        needs_more_evidence=needs_more_evidence,
        eligible_for_classification_review=eligible_for_classification_review,
        attestation_sha256=digest,
    )


def validate_future_security_evidence_sufficiency_attestation(
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
) -> FutureSecurityEvidenceSufficiencyAttestation:
    """Rebuild a persisted attestation against live verifier + evidence lineage."""

    if not isinstance(attestation, FutureSecurityEvidenceSufficiencyAttestation):
        raise ValueError(
            "attestation must be FutureSecurityEvidenceSufficiencyAttestation"
        )
    rebuilt = attest_future_security_evidence_sufficiency(
        preflight,
        sufficiency_request,
        review,
        admission,
        constraints,
        verifier=verifier,
        disposition=attestation.disposition,
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
    if rebuilt != attestation:
        raise ValueError(
            "evidence sufficiency attestation does not match live validated lineage"
        )
    return rebuilt
