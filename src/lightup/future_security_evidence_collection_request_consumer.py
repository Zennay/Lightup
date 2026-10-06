"""Fail-closed consumer for persisted ST5 evidence collection requests.

Strict serialization parsing is composed with immediate live-lineage validation
so persisted evidence-gap requests cannot be consumed after their source state
has drifted.
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
    future_security_evidence_collection_request_from_dict,
    validate_future_security_evidence_collection_request,
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
                "evidence collection request JSON contains duplicate object keys"
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
                "evidence collection request persisted JSON is invalid"
            ) from exc
    elif isinstance(value, dict):
        payload = value
    else:
        raise ValueError(
            "evidence collection request persisted value must be JSON text or object"
        )

    if not isinstance(payload, dict):
        raise ValueError(
            "evidence collection request persisted payload must be an object"
        )
    return payload


def load_and_validate_future_security_evidence_collection_request(
    persisted: object,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceCollectionRequest:
    """Strictly parse persisted request JSON and immediately require live validity."""

    parsed = future_security_evidence_collection_request_from_dict(
        _persisted_payload(persisted)
    )
    return validate_future_security_evidence_collection_request(
        parsed,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
