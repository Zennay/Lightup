"""Strict persisted handoff for revised ST5 remediation implementation plans.

A revised implementation plan remains unaccepted planning text. This boundary
validates its exact schema, canonical digest, bounded model provenance and
action-denying state, then revalidates the complete live revision-request,
independent-review and prior-plan lineage before allowing later reuse. It never
re-invokes a model.
"""

from __future__ import annotations

import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import FutureRemediationAuthoringRequest
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_implementation_plan import RemediationImplementationPlanItem
from .future_remediation_implementation_plan_handoff import (
    load_and_validate_future_remediation_implementation_plan,
)
from .future_remediation_implementation_plan_review_handoff import (
    load_and_validate_future_remediation_implementation_plan_review,
)
from .future_remediation_implementation_plan_revision_proposal import (
    REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
    FutureRemediationImplementationPlanRevisionProposal,
    _revision_plan_digest,
)
from .future_remediation_implementation_plan_revision_request_handoff import (
    load_and_validate_future_remediation_implementation_plan_revision_request,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVISED_PLAN_KEYS = {
    "schema_version",
    "revision_request_sha256",
    "prior_review_sha256",
    "prior_plan_sha256",
    "implementation_request_sha256",
    "provider_id",
    "model_id",
    "summary",
    "plan_items",
    "assumptions",
    "unresolved_questions",
    "revised_plan_sha256",
    "revised_implementation_plan_created",
    "implementation_plan_accepted",
    "code_change_authorized",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
    "future_semantics",
    "security_verdict",
}
_ITEM_KEYS = {
    "plan_item_id",
    "change_area",
    "intent",
    "verification_intent",
    "rollback_intent",
}
_ALLOWED_CHANGE_AREAS = {
    "application",
    "configuration",
    "identity_access",
    "infrastructure",
    "process",
    "unknown",
}
_MAX_PLAN_ITEMS = 20
_MAX_LIST_ITEMS = 20
_MAX_SUMMARY_CHARS = 4_000
_MAX_PLAN_TEXT_CHARS = 1_200
_MAX_LIST_TEXT_CHARS = 800
_MAX_PROVENANCE_CHARS = 256


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        type(value) is not str
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _canonical_bounded_text(
    value: object,
    *,
    field: str,
    max_chars: int,
) -> str:
    if type(value) is not str or not value:
        raise ValueError(f"{field} must be an exact non-empty string")
    if value != value.strip():
        raise ValueError(f"{field} must be canonical trimmed text")
    if "\x00" in value:
        raise ValueError(f"{field} contains NUL")
    if len(value) > max_chars:
        raise ValueError(f"{field} exceeds bounded size")
    return value


def _bounded_sequence(
    value: object,
    *,
    field: str,
) -> tuple[str, ...]:
    if not isinstance(value, (list, tuple)):
        raise ValueError(f"{field} must be a list or tuple")
    if len(value) > _MAX_LIST_ITEMS:
        raise ValueError(f"{field} exceeds bounded item count")
    return tuple(
        _canonical_bounded_text(
            item,
            field=f"{field}[{index}]",
            max_chars=_MAX_LIST_TEXT_CHARS,
        )
        for index, item in enumerate(value)
    )


def future_remediation_implementation_plan_revision_proposal_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlanRevisionProposal:
    """Parse one exact persisted revised implementation plan."""

    if type(payload) is not dict:
        raise ValueError(
            "revised remediation implementation plan payload must be an object"
        )
    if set(payload) != _REVISED_PLAN_KEYS:
        raise ValueError(
            "revised remediation implementation plan payload schema mismatch"
        )
    if (
        payload["schema_version"]
        != REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION
    ):
        raise ValueError(
            "revised remediation implementation plan schema version mismatch"
        )

    revision_request_sha256 = _canonical_sha256(
        payload["revision_request_sha256"],
        field="revised implementation plan revision_request_sha256",
    )
    prior_review_sha256 = _canonical_sha256(
        payload["prior_review_sha256"],
        field="revised implementation plan prior_review_sha256",
    )
    prior_plan_sha256 = _canonical_sha256(
        payload["prior_plan_sha256"],
        field="revised implementation plan prior_plan_sha256",
    )
    implementation_request_sha256 = _canonical_sha256(
        payload["implementation_request_sha256"],
        field="revised implementation plan implementation_request_sha256",
    )
    revised_plan_sha256 = _canonical_sha256(
        payload["revised_plan_sha256"],
        field="revised implementation plan revised_plan_sha256",
    )
    provider_id = _canonical_bounded_text(
        payload["provider_id"],
        field="revised implementation plan provider_id",
        max_chars=_MAX_PROVENANCE_CHARS,
    )
    model_id = _canonical_bounded_text(
        payload["model_id"],
        field="revised implementation plan model_id",
        max_chars=_MAX_PROVENANCE_CHARS,
    )
    summary = _canonical_bounded_text(
        payload["summary"],
        field="revised implementation plan summary",
        max_chars=_MAX_SUMMARY_CHARS,
    )

    raw_items = payload["plan_items"]
    if not isinstance(raw_items, (list, tuple)):
        raise ValueError(
            "revised remediation implementation plan plan_items must be a list or tuple"
        )
    if not raw_items:
        raise ValueError(
            "revised remediation implementation plan requires at least one plan item"
        )
    if len(raw_items) > _MAX_PLAN_ITEMS:
        raise ValueError(
            "revised remediation implementation plan plan_items exceed bounded item count"
        )

    items: list[RemediationImplementationPlanItem] = []
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if type(raw_item) is not dict or set(raw_item) != _ITEM_KEYS:
            raise ValueError(
                "revised remediation implementation plan item schema mismatch"
            )
        plan_item_id = _canonical_bounded_text(
            raw_item["plan_item_id"],
            field=f"revised implementation plan item[{index}].plan_item_id",
            max_chars=128,
        )
        if plan_item_id in seen_ids:
            raise ValueError(
                "revised remediation implementation plan item IDs must be unique"
            )
        seen_ids.add(plan_item_id)
        change_area = raw_item["change_area"]
        if type(change_area) is not str or change_area not in _ALLOWED_CHANGE_AREAS:
            raise ValueError(
                "revised remediation implementation plan change_area is invalid"
            )
        items.append(
            RemediationImplementationPlanItem(
                plan_item_id=plan_item_id,
                change_area=change_area,
                intent=_canonical_bounded_text(
                    raw_item["intent"],
                    field=f"revised implementation plan item[{index}].intent",
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
                verification_intent=_canonical_bounded_text(
                    raw_item["verification_intent"],
                    field=(
                        f"revised implementation plan item[{index}]"
                        ".verification_intent"
                    ),
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
                rollback_intent=_canonical_bounded_text(
                    raw_item["rollback_intent"],
                    field=(
                        f"revised implementation plan item[{index}]"
                        ".rollback_intent"
                    ),
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
            )
        )

    assumptions = _bounded_sequence(
        payload["assumptions"],
        field="revised implementation plan assumptions",
    )
    unresolved_questions = _bounded_sequence(
        payload["unresolved_questions"],
        field="revised implementation plan unresolved_questions",
    )

    if payload["revised_implementation_plan_created"] is not True:
        raise ValueError(
            "revised_implementation_plan_created must remain true"
        )
    if payload["implementation_plan_accepted"] is not False:
        raise ValueError("implementation_plan_accepted must remain false")
    for field in (
        "code_change_authorized",
        "tool_call_created",
        "execution_allowed",
        "target_interaction_allowed",
        "future_state_retest_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(
                f"revised implementation plan authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "revised implementation plan future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "revised implementation plan security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationImplementationPlanRevisionProposal(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_REVISION_PROPOSAL_SCHEMA_VERSION,
        revision_request_sha256=revision_request_sha256,
        prior_review_sha256=prior_review_sha256,
        prior_plan_sha256=prior_plan_sha256,
        implementation_request_sha256=implementation_request_sha256,
        provider_id=provider_id,
        model_id=model_id,
        summary=summary,
        plan_items=tuple(items),
        assumptions=assumptions,
        unresolved_questions=unresolved_questions,
        revised_plan_sha256=revised_plan_sha256,
    )
    expected_digest = _revision_plan_digest(
        revision_request_sha256=parsed.revision_request_sha256,
        prior_review_sha256=parsed.prior_review_sha256,
        prior_plan_sha256=parsed.prior_plan_sha256,
        implementation_request_sha256=parsed.implementation_request_sha256,
        provider_id=parsed.provider_id,
        model_id=parsed.model_id,
        summary=parsed.summary,
        plan_items=parsed.plan_items,
        assumptions=parsed.assumptions,
        unresolved_questions=parsed.unresolved_questions,
    )
    if expected_digest != parsed.revised_plan_sha256:
        raise ValueError("revised remediation implementation plan digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_revision_proposal_from_json(
    raw: str,
) -> FutureRemediationImplementationPlanRevisionProposal:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if type(raw) is not str or not raw.strip():
        raise ValueError(
            "revised remediation implementation plan JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError(
            "revised remediation implementation plan JSON is invalid"
        ) from exc
    return future_remediation_implementation_plan_revision_proposal_from_dict(payload)


def load_and_validate_future_remediation_implementation_plan_revision_proposal(
    persisted_revised_plan: object,
    persisted_revision_request: object,
    persisted_plan_review: object,
    persisted_plan_review_request: object,
    persisted_plan: object,
    persisted_planning_request: object,
    persisted_remediation_review: object,
    persisted_remediation_review_request: object,
    persisted_proposal: object,
    request: FutureRemediationAuthoringRequest,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    transition_proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationImplementationPlanRevisionProposal:
    """Parse a revised plan and require its complete referenced lineage to stay live."""

    if type(persisted_revised_plan) is str:
        parsed = future_remediation_implementation_plan_revision_proposal_from_json(
            persisted_revised_plan
        )
    elif type(persisted_revised_plan) is dict:
        parsed = future_remediation_implementation_plan_revision_proposal_from_dict(
            persisted_revised_plan
        )
    else:
        raise ValueError(
            "revised remediation implementation plan persisted value "
            "must be JSON text or object"
        )

    revision_request = (
        load_and_validate_future_remediation_implementation_plan_revision_request(
            persisted_revision_request,
            persisted_plan_review,
            persisted_plan_review_request,
            persisted_plan,
            persisted_planning_request,
            persisted_remediation_review,
            persisted_remediation_review_request,
            persisted_proposal,
            request,
            bundle,
            plan,
            report,
            preview,
            transition_proposal,
            resolutions,
            contexts,
            state,
        )
    )
    review = load_and_validate_future_remediation_implementation_plan_review(
        persisted_plan_review,
        persisted_plan_review_request,
        persisted_plan,
        persisted_planning_request,
        persisted_remediation_review,
        persisted_remediation_review_request,
        persisted_proposal,
        request,
        bundle,
        plan,
        report,
        preview,
        transition_proposal,
        resolutions,
        contexts,
        state,
    )
    prior_plan = load_and_validate_future_remediation_implementation_plan(
        persisted_plan,
        persisted_planning_request,
        persisted_remediation_review,
        persisted_remediation_review_request,
        persisted_proposal,
        request,
        bundle,
        plan,
        report,
        preview,
        transition_proposal,
        resolutions,
        contexts,
        state,
    )

    if parsed.revision_request_sha256 != revision_request.revision_request_sha256:
        raise ValueError("revised implementation plan revision-request lineage mismatch")
    if parsed.prior_review_sha256 != review.review_sha256:
        raise ValueError("revised implementation plan review lineage mismatch")
    if parsed.prior_plan_sha256 != prior_plan.plan_sha256:
        raise ValueError("revised implementation plan prior-plan lineage mismatch")
    if (
        parsed.implementation_request_sha256
        != prior_plan.implementation_request_sha256
    ):
        raise ValueError(
            "revised implementation plan implementation-request lineage mismatch"
        )
    return parsed
