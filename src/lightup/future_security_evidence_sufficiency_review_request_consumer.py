"""Fail-closed consumer for persisted ST5 evidence sufficiency-review requests."""

from __future__ import annotations

import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_security_evidence_collection_request import FutureSecurityEvidenceCollectionRequest
from .future_security_evidence_freshness import FutureSecurityEvidenceFreshnessConstraints
from .future_security_evidence_freshness_admission import FutureSecurityEvidenceFreshnessAdmission
from .future_security_evidence_metadata_contract_review import (
    FutureSecurityEvidenceMetadataContractReview,
)
from .future_security_evidence_sufficiency_review_request import (
    FutureSecurityEvidenceSufficiencyReviewRequest,
    validate_future_security_evidence_sufficiency_review_request,
)
from .future_security_evidence_sufficiency_review_request_handoff import (
    future_security_evidence_sufficiency_review_request_from_dict,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


def _object_without_duplicate_keys(pairs: list[tuple[str, object]]) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(
                "evidence sufficiency review request JSON contains duplicate object keys"
            )
        payload[key] = value
    return payload


def _persisted_payload(value: object) -> dict:
    if isinstance(value, str):
        try:
            payload = json.loads(
                value,
                object_pairs_hook=_object_without_duplicate_keys,
            )
        except json.JSONDecodeError as exc:
            raise ValueError(
                "evidence sufficiency review request persisted JSON is invalid"
            ) from exc
    elif isinstance(value, dict):
        payload = value
    else:
        raise ValueError(
            "evidence sufficiency review request persisted value must be JSON text or object"
        )
    if not isinstance(payload, dict):
        raise ValueError(
            "evidence sufficiency review request persisted payload must be an object"
        )
    return payload


def load_and_validate_future_security_evidence_sufficiency_review_request(
    persisted: object,
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
    """Strictly parse a persisted request and immediately require live validity."""

    parsed = future_security_evidence_sufficiency_review_request_from_dict(
        _persisted_payload(persisted)
    )
    return validate_future_security_evidence_sufficiency_review_request(
        parsed,
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
