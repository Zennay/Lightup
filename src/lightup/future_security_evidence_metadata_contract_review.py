"""Read-only ST5 review of admitted candidate evidence metadata contracts.

This stage proves only that already-fresh candidate evidence carries one
internally consistent instance of the existing ST4 transition-verification
metadata contract.  The classification value is treated as an evidence claim:
LightUp does not select or accept a security classification here.
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
    future_attack_path_transition_evidence_contract,
)
from .future_security_evidence_collection_request import (
    FutureSecurityEvidenceCollectionRequest,
)
from .future_security_evidence_freshness import (
    FutureSecurityEvidenceFreshnessConstraints,
)
from .future_security_evidence_freshness_admission import (
    FutureSecurityEvidenceFreshnessAdmission,
    validate_future_security_evidence_freshness_admission,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


REVIEW_SCHEMA_VERSION = "st5.evidence_metadata_contract_review.v1"
_TRANSITION_EVIDENCE_KIND = "future-transition-verification"


@dataclass(frozen=True)
class FutureSecurityEvidenceMetadataContractReview:
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
    source_resolution_id: str
    change_node_id: str
    subject_node_id: str
    candidate_run_id: str
    candidate_evidence_ids: tuple[str, ...]
    candidate_capability_ids: tuple[str, ...]
    candidate_classification_claim: AttackPathTransitionClassification
    metadata_contract_verified: bool
    review_sha256: str
    freshness_check_passed: bool = True
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


def _review_digest(
    *,
    admission: FutureSecurityEvidenceFreshnessAdmission,
    claim: AttackPathTransitionClassification,
) -> str:
    payload = {
        "schema_version": REVIEW_SCHEMA_VERSION,
        "client_id": admission.client_id,
        "current_twin_id": admission.current_twin_id,
        "current_twin_version": admission.current_twin_version,
        "twin_id": admission.twin_id,
        "twin_version": admission.twin_version,
        "changeset_id": admission.changeset_id,
        "request_sha256": admission.request_sha256,
        "constraints_sha256": admission.constraints_sha256,
        "admission_sha256": admission.admission_sha256,
        "source_resolution_id": admission.source_resolution_id,
        "change_node_id": admission.change_node_id,
        "subject_node_id": admission.subject_node_id,
        "candidate_run_id": admission.candidate_run_id,
        "candidate_evidence_ids": list(admission.candidate_evidence_ids),
        "candidate_capability_ids": list(admission.candidate_capability_ids),
        "candidate_classification_claim": claim.value,
        "metadata_contract_verified": True,
        "freshness_check_passed": True,
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


def review_future_security_evidence_metadata_contract(
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
) -> FutureSecurityEvidenceMetadataContractReview:
    """Verify candidate evidence metadata without selecting a security outcome."""

    validate_future_security_evidence_freshness_admission(
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

    records = tuple(
        state.get_evidence(evidence_id)
        for evidence_id in admission.candidate_evidence_ids
    )
    if not records:
        raise ValueError("metadata contract review requires candidate evidence")

    live_ids = tuple(sorted(record.evidence_id for record in records))
    if live_ids != admission.candidate_evidence_ids:
        raise ValueError("candidate evidence identity drifted from live admission")

    live_capabilities = tuple(
        sorted({record.capability_id for record in records})
    )
    if live_capabilities != admission.candidate_capability_ids:
        raise ValueError("candidate evidence capabilities drifted from live admission")

    claims: list[AttackPathTransitionClassification] = []
    metadata_by_evidence: list[tuple[str, dict]] = []
    for record in records:
        if record.run_id != admission.candidate_run_id:
            raise ValueError("candidate evidence run drifted from live admission")
        if record.kind != _TRANSITION_EVIDENCE_KIND:
            raise ValueError(
                "candidate evidence kind is not transition-verification evidence"
            )
        metadata = dict(record.metadata)
        raw_claim = metadata.get("classification")
        if not isinstance(raw_claim, str):
            raise ValueError(
                "candidate evidence classification claim must be a canonical string"
            )
        try:
            claim = AttackPathTransitionClassification(raw_claim)
        except ValueError as exc:
            raise ValueError(
                "candidate evidence classification claim is unsupported"
            ) from exc
        claims.append(claim)
        metadata_by_evidence.append((record.evidence_id, metadata))

    unique_claims = set(claims)
    if len(unique_claims) != 1:
        raise ValueError(
            "candidate evidence must carry one consistent classification claim"
        )
    claim = claims[0]

    expected_metadata = future_attack_path_transition_evidence_contract(
        proposal,
        change_node_id=admission.change_node_id,
        classification=claim,
        context=candidate_context,
    )
    for evidence_id, metadata in metadata_by_evidence:
        for key, value in expected_metadata.items():
            if metadata.get(key) != value:
                raise ValueError(
                    "candidate evidence metadata contract mismatch "
                    f"for {evidence_id!r} key {key!r}"
                )

    review_sha256 = _review_digest(admission=admission, claim=claim)
    return FutureSecurityEvidenceMetadataContractReview(
        schema_version=REVIEW_SCHEMA_VERSION,
        client_id=admission.client_id,
        current_twin_id=admission.current_twin_id,
        current_twin_version=admission.current_twin_version,
        twin_id=admission.twin_id,
        twin_version=admission.twin_version,
        changeset_id=admission.changeset_id,
        request_sha256=admission.request_sha256,
        constraints_sha256=admission.constraints_sha256,
        admission_sha256=admission.admission_sha256,
        source_resolution_id=admission.source_resolution_id,
        change_node_id=admission.change_node_id,
        subject_node_id=admission.subject_node_id,
        candidate_run_id=admission.candidate_run_id,
        candidate_evidence_ids=admission.candidate_evidence_ids,
        candidate_capability_ids=admission.candidate_capability_ids,
        candidate_classification_claim=claim,
        metadata_contract_verified=True,
        review_sha256=review_sha256,
    )


def validate_future_security_evidence_metadata_contract_review(
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
) -> FutureSecurityEvidenceMetadataContractReview:
    """Rebuild a persisted metadata review against live candidate evidence."""

    if not isinstance(review, FutureSecurityEvidenceMetadataContractReview):
        raise ValueError(
            "review must be FutureSecurityEvidenceMetadataContractReview"
        )
    rebuilt = review_future_security_evidence_metadata_contract(
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
    if rebuilt != review:
        raise ValueError(
            "evidence metadata contract review does not match live validated evidence"
        )
    return rebuilt
