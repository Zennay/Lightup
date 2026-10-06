"""Strict persisted handoff for ST5 remediation implementation plans.

Persisted implementation planning remains non-executable. This boundary
validates the exact structured plan schema, canonical digest, model provenance
and action-denying flags, then composes with the still-live accepted review and
implementation-planning request chain before allowing reuse.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import FutureRemediationAuthoringRequest
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_implementation_plan import (
    REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION,
    FutureRemediationImplementationPlan,
    RemediationImplementationPlanItem,
)
from .future_remediation_implementation_plan_request_handoff import (
    load_and_validate_future_remediation_implementation_plan_request,
)
from .future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)
from .future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_PLAN_KEYS = {
    "schema_version",
    "implementation_request_sha256",
    "review_sha256",
    "proposal_sha256",
    "content_sha256",
    "provider_id",
    "model_id",
    "summary",
    "plan_items",
    "assumptions",
    "unresolved_questions",
    "plan_sha256",
    "implementation_plan_created",
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


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _bounded_text(value: object, *, field: str, max_chars: int) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    value = value.strip()
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
        _bounded_text(
            item,
            field=f"{field}[{index}]",
            max_chars=_MAX_LIST_TEXT_CHARS,
        )
        for index, item in enumerate(value)
    )


def _plan_digest(plan: FutureRemediationImplementationPlan) -> str:
    payload = {
        "schema_version": REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION,
        "implementation_request_sha256": plan.implementation_request_sha256,
        "review_sha256": plan.review_sha256,
        "proposal_sha256": plan.proposal_sha256,
        "content_sha256": plan.content_sha256,
        "provider_id": plan.provider_id,
        "model_id": plan.model_id,
        "summary": plan.summary,
        "plan_items": [item.as_dict() for item in plan.plan_items],
        "assumptions": list(plan.assumptions),
        "unresolved_questions": list(plan.unresolved_questions),
        "implementation_plan_created": True,
        "code_change_authorized": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
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


def future_remediation_implementation_plan_from_dict(
    payload: dict,
) -> FutureRemediationImplementationPlan:
    """Parse one exact persisted remediation implementation plan."""

    if not isinstance(payload, dict):
        raise ValueError("remediation implementation plan payload must be an object")
    if set(payload) != _PLAN_KEYS:
        raise ValueError("remediation implementation plan payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION:
        raise ValueError("remediation implementation plan schema version mismatch")

    implementation_request_sha256 = _canonical_sha256(
        payload["implementation_request_sha256"],
        field="remediation implementation plan implementation_request_sha256",
    )
    review_sha256 = _canonical_sha256(
        payload["review_sha256"],
        field="remediation implementation plan review_sha256",
    )
    proposal_sha256 = _canonical_sha256(
        payload["proposal_sha256"],
        field="remediation implementation plan proposal_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation implementation plan content_sha256",
    )
    plan_sha256 = _canonical_sha256(
        payload["plan_sha256"],
        field="remediation implementation plan plan_sha256",
    )
    provider_id = _bounded_text(
        payload["provider_id"],
        field="remediation implementation plan provider_id",
        max_chars=256,
    )
    model_id = _bounded_text(
        payload["model_id"],
        field="remediation implementation plan model_id",
        max_chars=256,
    )
    summary = _bounded_text(
        payload["summary"],
        field="remediation implementation plan summary",
        max_chars=_MAX_SUMMARY_CHARS,
    )

    raw_items = payload["plan_items"]
    if not isinstance(raw_items, (list, tuple)):
        raise ValueError("remediation implementation plan plan_items must be a list or tuple")
    if not raw_items:
        raise ValueError("remediation implementation plan requires at least one plan item")
    if len(raw_items) > _MAX_PLAN_ITEMS:
        raise ValueError("remediation implementation plan plan_items exceed bounded item count")

    items: list[RemediationImplementationPlanItem] = []
    seen_ids: set[str] = set()
    for index, raw_item in enumerate(raw_items):
        if not isinstance(raw_item, dict) or set(raw_item) != _ITEM_KEYS:
            raise ValueError("remediation implementation plan item schema mismatch")
        plan_item_id = _bounded_text(
            raw_item["plan_item_id"],
            field=f"remediation implementation plan item[{index}].plan_item_id",
            max_chars=128,
        )
        if plan_item_id in seen_ids:
            raise ValueError("remediation implementation plan item IDs must be unique")
        seen_ids.add(plan_item_id)
        change_area = raw_item["change_area"]
        if change_area not in _ALLOWED_CHANGE_AREAS:
            raise ValueError("remediation implementation plan change_area is invalid")
        items.append(
            RemediationImplementationPlanItem(
                plan_item_id=plan_item_id,
                change_area=change_area,
                intent=_bounded_text(
                    raw_item["intent"],
                    field=f"remediation implementation plan item[{index}].intent",
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
                verification_intent=_bounded_text(
                    raw_item["verification_intent"],
                    field=(
                        f"remediation implementation plan item[{index}]"
                        ".verification_intent"
                    ),
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
                rollback_intent=_bounded_text(
                    raw_item["rollback_intent"],
                    field=(
                        f"remediation implementation plan item[{index}]"
                        ".rollback_intent"
                    ),
                    max_chars=_MAX_PLAN_TEXT_CHARS,
                ),
            )
        )

    assumptions = _bounded_sequence(
        payload["assumptions"],
        field="remediation implementation plan assumptions",
    )
    unresolved_questions = _bounded_sequence(
        payload["unresolved_questions"],
        field="remediation implementation plan unresolved_questions",
    )

    if payload["implementation_plan_created"] is not True:
        raise ValueError(
            "remediation implementation plan implementation_plan_created must remain true"
        )
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
                f"remediation implementation plan authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation implementation plan future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation implementation plan security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationImplementationPlan(
        schema_version=REMEDIATION_IMPLEMENTATION_PLAN_SCHEMA_VERSION,
        implementation_request_sha256=implementation_request_sha256,
        review_sha256=review_sha256,
        proposal_sha256=proposal_sha256,
        content_sha256=content_sha256,
        provider_id=provider_id,
        model_id=model_id,
        summary=summary,
        plan_items=tuple(items),
        assumptions=assumptions,
        unresolved_questions=unresolved_questions,
        plan_sha256=plan_sha256,
    )
    if _plan_digest(parsed) != parsed.plan_sha256:
        raise ValueError("remediation implementation plan digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_implementation_plan_from_json(
    raw: str,
) -> FutureRemediationImplementationPlan:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("remediation implementation plan JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation implementation plan JSON is invalid") from exc
    return future_remediation_implementation_plan_from_dict(payload)


def load_and_validate_future_remediation_implementation_plan(
    persisted_plan: object,
    persisted_planning_request: object,
    persisted_review: object,
    persisted_review_request: object,
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
) -> FutureRemediationImplementationPlan:
    """Strictly parse a plan and require its full planning lineage to remain live."""

    if isinstance(persisted_plan, str):
        parsed = future_remediation_implementation_plan_from_json(persisted_plan)
    elif isinstance(persisted_plan, dict):
        parsed = future_remediation_implementation_plan_from_dict(persisted_plan)
    else:
        raise ValueError(
            "remediation implementation plan persisted value must be JSON text or object"
        )

    planning_request = (
        load_and_validate_future_remediation_implementation_plan_request(
            persisted_planning_request,
            persisted_review,
            persisted_review_request,
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
    review = load_and_validate_future_remediation_text_review(
        persisted_review,
        persisted_review_request,
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
    proposal = load_and_validate_future_remediation_text_proposal(
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

    if parsed.implementation_request_sha256 != (
        planning_request.implementation_request_sha256
    ):
        raise ValueError("remediation implementation plan request lineage mismatch")
    if parsed.review_sha256 != review.review_sha256:
        raise ValueError("remediation implementation plan review lineage mismatch")
    if parsed.proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("remediation implementation plan proposal lineage mismatch")
    if parsed.content_sha256 != proposal.content_sha256:
        raise ValueError("remediation implementation plan content lineage mismatch")
    return parsed
