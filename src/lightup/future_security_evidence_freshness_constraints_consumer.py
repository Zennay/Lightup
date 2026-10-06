"""Fail-closed consumer for persisted ST5 evidence-freshness constraints.

Serialization integrity alone is not live evidence validity. This module
composes the strict constraints parser with immediate live lineage and
StateStore validation.
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
    future_security_evidence_freshness_constraints_from_dict,
    validate_future_security_evidence_freshness_constraints,
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
                "evidence freshness constraints JSON contains duplicate object keys"
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
                "evidence freshness constraints persisted JSON is invalid"
            ) from exc
    elif isinstance(value, dict):
        payload = value
    else:
        raise ValueError(
            "evidence freshness constraints persisted value must be JSON text or object"
        )

    if not isinstance(payload, dict):
        raise ValueError(
            "evidence freshness constraints persisted payload must be an object"
        )
    return payload


def load_and_validate_future_security_evidence_freshness_constraints(
    persisted: object,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessConstraints:
    """Strictly parse persisted constraints and immediately require live validity."""

    parsed = future_security_evidence_freshness_constraints_from_dict(
        _persisted_payload(persisted)
    )
    return validate_future_security_evidence_freshness_constraints(
        parsed,
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
