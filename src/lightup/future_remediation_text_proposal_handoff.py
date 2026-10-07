"""Strict persisted handoff for ST5 remediation text proposals.

Persisted model text is not execution authority. This boundary accepts only the
exact proposal schema, verifies canonical digests and fail-closed authority
flags, then composes with the live remediation-authoring request validator.
"""

from __future__ import annotations

from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import FutureAttackPathSecurityDeltaReport
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import FutureAttackPathTransitionResolution
from .future_remediation_authoring_request import (
    FutureRemediationAuthoringRequest,
    validate_future_remediation_authoring_request,
)
from .future_remediation_evidence_bundle import FutureRemediationEvidenceBundle
from .future_remediation_text_proposal import (
    REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION,
    FutureRemediationTextProposal,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_PROPOSAL_KEYS = {
    "schema_version",
    "request_sha256",
    "bundle_sha256",
    "item_count",
    "provider_id",
    "model_id",
    "content",
    "content_sha256",
    "proposal_sha256",
    "remediation_proposal_created",
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
_MAX_MODEL_OUTPUT_CHARS = 16_000


def _canonical_sha256(value: object, *, field: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(character not in "0123456789abcdef" for character in value)
    ):
        raise ValueError(f"{field} must be a canonical lowercase SHA-256 digest")
    return value


def _non_empty_string(value: object, *, field: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValueError(f"{field} must be a non-empty string")
    return value


def _non_negative_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        raise ValueError(f"{field} must be a non-negative integer")
    return value


def _content_digest(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def _proposal_digest(proposal: FutureRemediationTextProposal) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION,
        "request_sha256": proposal.request_sha256,
        "bundle_sha256": proposal.bundle_sha256,
        "item_count": proposal.item_count,
        "provider_id": proposal.provider_id,
        "model_id": proposal.model_id,
        "content": proposal.content,
        "content_sha256": proposal.content_sha256,
        "remediation_proposal_created": True,
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


def future_remediation_text_proposal_from_dict(
    payload: dict,
) -> FutureRemediationTextProposal:
    """Parse one exact persisted remediation-text proposal."""

    if not isinstance(payload, dict):
        raise ValueError("remediation text proposal payload must be an object")
    if set(payload) != _PROPOSAL_KEYS:
        raise ValueError("remediation text proposal payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION:
        raise ValueError("remediation text proposal schema version mismatch")

    request_sha256 = _canonical_sha256(
        payload["request_sha256"],
        field="remediation text proposal request_sha256",
    )
    bundle_sha256 = _canonical_sha256(
        payload["bundle_sha256"],
        field="remediation text proposal bundle_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation text proposal content_sha256",
    )
    proposal_sha256 = _canonical_sha256(
        payload["proposal_sha256"],
        field="remediation text proposal proposal_sha256",
    )
    item_count = _non_negative_int(
        payload["item_count"],
        field="remediation text proposal item_count",
    )
    if item_count == 0:
        raise ValueError("remediation text proposal item_count must be positive")

    provider_id = _non_empty_string(
        payload["provider_id"],
        field="remediation text proposal provider_id",
    )
    model_id = _non_empty_string(
        payload["model_id"],
        field="remediation text proposal model_id",
    )
    content = _non_empty_string(
        payload["content"],
        field="remediation text proposal content",
    )
    if "\x00" in content:
        raise ValueError("remediation text proposal content contains NUL")
    if len(content) > _MAX_MODEL_OUTPUT_CHARS:
        raise ValueError("remediation text proposal content exceeds the bounded output size")

    if payload["remediation_proposal_created"] is not True:
        raise ValueError(
            "remediation text proposal remediation_proposal_created must remain true"
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
                f"remediation text proposal authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation text proposal future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation text proposal security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationTextProposal(
        schema_version=REMEDIATION_TEXT_PROPOSAL_SCHEMA_VERSION,
        request_sha256=request_sha256,
        bundle_sha256=bundle_sha256,
        item_count=item_count,
        provider_id=provider_id,
        model_id=model_id,
        content=content,
        content_sha256=content_sha256,
        proposal_sha256=proposal_sha256,
    )
    if _content_digest(parsed.content) != parsed.content_sha256:
        raise ValueError("remediation text proposal content digest mismatch")
    if _proposal_digest(parsed) != parsed.proposal_sha256:
        raise ValueError("remediation text proposal digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_text_proposal_from_json(
    raw: str,
) -> FutureRemediationTextProposal:
    """Parse strict JSON without last-value-wins duplicate-key behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError("remediation text proposal JSON must be a non-empty string")
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation text proposal JSON is invalid") from exc
    return future_remediation_text_proposal_from_dict(payload)


def validate_future_remediation_text_proposal(
    proposal: FutureRemediationTextProposal,
    request: FutureRemediationAuthoringRequest,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    transition_proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationTextProposal:
    """Require exact proposal integrity plus a still-live authoring lineage."""

    if not isinstance(proposal, FutureRemediationTextProposal):
        raise ValueError("proposal must be a FutureRemediationTextProposal")
    live_request = validate_future_remediation_authoring_request(
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
    if proposal.request_sha256 != live_request.request_sha256:
        raise ValueError("remediation text proposal request lineage mismatch")
    if proposal.bundle_sha256 != live_request.bundle_sha256:
        raise ValueError("remediation text proposal bundle lineage mismatch")
    if proposal.item_count != live_request.item_count:
        raise ValueError("remediation text proposal item count mismatch")
    if _content_digest(proposal.content) != proposal.content_sha256:
        raise ValueError("remediation text proposal content digest mismatch")
    if _proposal_digest(proposal) != proposal.proposal_sha256:
        raise ValueError("remediation text proposal digest mismatch")
    return proposal


def load_and_validate_future_remediation_text_proposal(
    persisted: object,
    request: FutureRemediationAuthoringRequest,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    transition_proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationTextProposal:
    """Strictly parse persisted model text and immediately require live lineage."""

    if isinstance(persisted, str):
        parsed = future_remediation_text_proposal_from_json(persisted)
    elif isinstance(persisted, dict):
        parsed = future_remediation_text_proposal_from_dict(persisted)
    else:
        raise ValueError(
            "remediation text proposal persisted value must be JSON text or object"
        )
    return validate_future_remediation_text_proposal(
        parsed,
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
