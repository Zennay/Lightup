"""Fail-closed consumer for persisted ST5 evidence-freshness admissions.

Persisted admission parsing and live evidence validation are intentionally
composed here so callers cannot receive a parsed admission after candidate or
upstream lineage has drifted.
"""

from __future__ import annotations

import json

from .ai.orchestration import RunContext
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
)
from .future_security_evidence_freshness_admission import (
    FutureSecurityEvidenceFreshnessAdmission,
    validate_future_security_evidence_freshness_admission,
)
from .future_security_evidence_freshness_admission_handoff import (
    future_security_evidence_freshness_admission_from_dict,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


def _object_without_duplicate_keys(
    pairs: list[tuple[str, object]],
) -> dict[str, object]:
    payload: dict[str, object] = {}
    for key, value in pairs:
        if key in payload:
            raise ValueError(
                "evidence freshness admission JSON contains duplicate object keys"
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
                "evidence freshness admission persisted JSON is invalid"
            ) from exc
    elif isinstance(value, dict):
        payload = value
    else:
        raise ValueError(
            "evidence freshness admission persisted value must be JSON text or object"
        )

    if not isinstance(payload, dict):
        raise ValueError(
            "evidence freshness admission persisted payload must be an object"
        )
    return payload


def load_and_validate_future_security_evidence_freshness_admission(
    persisted: object,
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
    """Strictly parse persisted admission and immediately require live validity."""

    parsed = future_security_evidence_freshness_admission_from_dict(
        _persisted_payload(persisted)
    )
    return validate_future_security_evidence_freshness_admission(
        parsed,
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
