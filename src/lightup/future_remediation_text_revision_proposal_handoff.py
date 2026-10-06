"""Strict persisted handoff for revised ST5 remediation text.

Persisted revised prose remains unaccepted planning material. This boundary
validates exact schema, model provenance, canonical content/proposal digests and
fixed fail-closed authority flags, then composes with the strict live revision
request, review and prior-proposal chain before allowing reuse.
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
from .future_remediation_text_proposal_handoff import (
    load_and_validate_future_remediation_text_proposal,
)
from .future_remediation_text_revision_proposal import (
    REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION,
    FutureRemediationTextRevisionProposal,
)
from .future_remediation_text_revision_request_handoff import (
    load_and_validate_future_remediation_text_revision_request,
)
from .future_remediation_text_review_handoff import (
    load_and_validate_future_remediation_text_review,
)
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


_REVISION_PROPOSAL_KEYS = {
    "schema_version",
    "revision_request_sha256",
    "prior_review_sha256",
    "prior_proposal_sha256",
    "prior_content_sha256",
    "provider_id",
    "model_id",
    "content",
    "content_sha256",
    "revision_proposal_sha256",
    "remediation_revision_proposal_created",
    "remediation_accepted",
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


def _content_digest(content: str) -> str:
    return sha256(content.encode("utf-8")).hexdigest()


def _revision_proposal_digest(
    proposal: FutureRemediationTextRevisionProposal,
) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION,
        "revision_request_sha256": proposal.revision_request_sha256,
        "prior_review_sha256": proposal.prior_review_sha256,
        "prior_proposal_sha256": proposal.prior_proposal_sha256,
        "prior_content_sha256": proposal.prior_content_sha256,
        "provider_id": proposal.provider_id,
        "model_id": proposal.model_id,
        "content": proposal.content,
        "content_sha256": proposal.content_sha256,
        "remediation_revision_proposal_created": True,
        "remediation_accepted": False,
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


def future_remediation_text_revision_proposal_from_dict(
    payload: dict,
) -> FutureRemediationTextRevisionProposal:
    """Parse one exact persisted revised remediation-text proposal."""

    if not isinstance(payload, dict):
        raise ValueError("remediation text revision proposal payload must be an object")
    if set(payload) != _REVISION_PROPOSAL_KEYS:
        raise ValueError("remediation text revision proposal payload schema mismatch")
    if payload["schema_version"] != REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION:
        raise ValueError("remediation text revision proposal schema version mismatch")

    revision_request_sha256 = _canonical_sha256(
        payload["revision_request_sha256"],
        field="remediation text revision proposal revision_request_sha256",
    )
    prior_review_sha256 = _canonical_sha256(
        payload["prior_review_sha256"],
        field="remediation text revision proposal prior_review_sha256",
    )
    prior_proposal_sha256 = _canonical_sha256(
        payload["prior_proposal_sha256"],
        field="remediation text revision proposal prior_proposal_sha256",
    )
    prior_content_sha256 = _canonical_sha256(
        payload["prior_content_sha256"],
        field="remediation text revision proposal prior_content_sha256",
    )
    content_sha256 = _canonical_sha256(
        payload["content_sha256"],
        field="remediation text revision proposal content_sha256",
    )
    revision_proposal_sha256 = _canonical_sha256(
        payload["revision_proposal_sha256"],
        field="remediation text revision proposal revision_proposal_sha256",
    )
    provider_id = _non_empty_string(
        payload["provider_id"],
        field="remediation text revision proposal provider_id",
    )
    model_id = _non_empty_string(
        payload["model_id"],
        field="remediation text revision proposal model_id",
    )
    content = _non_empty_string(
        payload["content"],
        field="remediation text revision proposal content",
    ).strip()
    if "\x00" in content:
        raise ValueError("remediation text revision proposal content contains NUL")
    if len(content) > _MAX_MODEL_OUTPUT_CHARS:
        raise ValueError(
            "remediation text revision proposal content exceeds the bounded output size"
        )
    if _content_digest(content) != content_sha256:
        raise ValueError("remediation text revision proposal content digest mismatch")

    if payload["remediation_revision_proposal_created"] is not True:
        raise ValueError(
            "remediation text revision proposal created flag must remain true"
        )
    if payload["remediation_accepted"] is not False:
        raise ValueError(
            "remediation text revision proposal remediation_accepted must remain false"
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
                f"remediation text revision proposal authority flag {field} must remain false"
            )
    if payload["future_semantics"] != "unresolved":
        raise ValueError(
            "remediation text revision proposal future_semantics must remain unresolved"
        )
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError(
            "remediation text revision proposal security_verdict must remain not_evaluated"
        )

    parsed = FutureRemediationTextRevisionProposal(
        schema_version=REMEDIATION_TEXT_REVISION_PROPOSAL_SCHEMA_VERSION,
        revision_request_sha256=revision_request_sha256,
        prior_review_sha256=prior_review_sha256,
        prior_proposal_sha256=prior_proposal_sha256,
        prior_content_sha256=prior_content_sha256,
        provider_id=provider_id,
        model_id=model_id,
        content=content,
        content_sha256=content_sha256,
        revision_proposal_sha256=revision_proposal_sha256,
    )
    if _revision_proposal_digest(parsed) != parsed.revision_proposal_sha256:
        raise ValueError("remediation text revision proposal digest mismatch")
    return parsed


def _reject_duplicate_json_keys(pairs: list[tuple[str, object]]) -> dict:
    result: dict = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate JSON key {key!r}")
        result[key] = value
    return result


def future_remediation_text_revision_proposal_from_json(
    raw: str,
) -> FutureRemediationTextRevisionProposal:
    """Parse strict JSON without duplicate-key last-value-wins behavior."""

    if not isinstance(raw, str) or not raw.strip():
        raise ValueError(
            "remediation text revision proposal JSON must be a non-empty string"
        )
    try:
        payload = json.loads(raw, object_pairs_hook=_reject_duplicate_json_keys)
    except json.JSONDecodeError as exc:
        raise ValueError("remediation text revision proposal JSON is invalid") from exc
    return future_remediation_text_revision_proposal_from_dict(payload)


def load_and_validate_future_remediation_text_revision_proposal(
    persisted_revision_proposal: object,
    persisted_revision_request: object,
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
) -> FutureRemediationTextRevisionProposal:
    """Parse revised prose and require the complete referenced lineage live."""

    if isinstance(persisted_revision_proposal, str):
        parsed = future_remediation_text_revision_proposal_from_json(
            persisted_revision_proposal
        )
    elif isinstance(persisted_revision_proposal, dict):
        parsed = future_remediation_text_revision_proposal_from_dict(
            persisted_revision_proposal
        )
    else:
        raise ValueError(
            "remediation text revision proposal persisted value must be JSON text or object"
        )

    revision_request = load_and_validate_future_remediation_text_revision_request(
        persisted_revision_request,
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

    if parsed.revision_request_sha256 != revision_request.revision_request_sha256:
        raise ValueError("remediation text revision proposal request lineage mismatch")
    if parsed.prior_review_sha256 != review.review_sha256:
        raise ValueError("remediation text revision proposal review lineage mismatch")
    if parsed.prior_proposal_sha256 != proposal.proposal_sha256:
        raise ValueError("remediation text revision proposal prior proposal lineage mismatch")
    if parsed.prior_content_sha256 != proposal.content_sha256:
        raise ValueError("remediation text revision proposal prior content lineage mismatch")
    return parsed
