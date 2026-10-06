"""Bounded ST5 remediation-text review request.

This module turns a strict, live-valid persisted remediation text proposal into
immutable metadata requesting independent review. It does not perform the
review, accept the remediation, generate code/config, call tools, interact with
targets, execute remediation or retests, authorize deployment, or mutate attack
paths.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
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
from .future_security_remediation_retest_plan import FutureSecurityRemediationRetestPlan
from .state import StateStore


REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION = "st5.remediation_text_review_request.v1"
REQUIRED_REVIEW_CHECKS = (
    "evidence_alignment",
    "unsupported_claims",
    "least_privilege",
    "future_retest_separation",
)


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


def _positive_int(value: object, *, field: str) -> int:
    if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
        raise ValueError(f"{field} must be a positive integer")
    return value


@dataclass(frozen=True)
class FutureRemediationTextReviewRequest:
    schema_version: str
    request_sha256: str
    bundle_sha256: str
    proposal_sha256: str
    content_sha256: str
    provider_id: str
    model_id: str
    item_count: int
    required_checks: tuple[str, ...]
    review_request_sha256: str
    review_requested: bool = True
    remediation_accepted: bool = False
    code_change_authorized: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    future_state_retest_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def __post_init__(self) -> None:
        if self.schema_version != REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION:
            raise ValueError("remediation text review request schema version mismatch")
        for field in (
            "request_sha256",
            "bundle_sha256",
            "proposal_sha256",
            "content_sha256",
            "review_request_sha256",
        ):
            _canonical_sha256(
                getattr(self, field),
                field=f"remediation text review request {field}",
            )
        _non_empty_string(
            self.provider_id,
            field="remediation text review request provider_id",
        )
        _non_empty_string(
            self.model_id,
            field="remediation text review request model_id",
        )
        _positive_int(
            self.item_count,
            field="remediation text review request item_count",
        )
        if not isinstance(self.required_checks, tuple):
            raise ValueError(
                "remediation text review request required_checks must be a tuple"
            )
        if self.required_checks != REQUIRED_REVIEW_CHECKS:
            raise ValueError(
                "remediation text review request required_checks mismatch"
            )
        if self.review_requested is not True:
            raise ValueError("review_requested must remain true")
        if self.remediation_accepted is not False:
            raise ValueError("remediation_accepted must remain false")
        for field in (
            "code_change_authorized",
            "tool_call_created",
            "execution_allowed",
            "target_interaction_allowed",
            "future_state_retest_allowed",
            "deployment_authorized",
            "attack_path_mutation_allowed",
        ):
            if getattr(self, field) is not False:
                raise ValueError(f"authority flag {field} must remain false")
        if self.future_semantics != "unresolved":
            raise ValueError("future_semantics must remain unresolved")
        if self.security_verdict != "not_evaluated":
            raise ValueError("security_verdict must remain not_evaluated")
        expected_review_request_sha256 = _review_request_digest(
            request_sha256=self.request_sha256,
            bundle_sha256=self.bundle_sha256,
            proposal_sha256=self.proposal_sha256,
            content_sha256=self.content_sha256,
            provider_id=self.provider_id,
            model_id=self.model_id,
            item_count=self.item_count,
        )
        if self.review_request_sha256 != expected_review_request_sha256:
            raise ValueError("remediation text review request digest mismatch")

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _review_request_digest(
    *,
    request_sha256: str,
    bundle_sha256: str,
    proposal_sha256: str,
    content_sha256: str,
    provider_id: str,
    model_id: str,
    item_count: int,
) -> str:
    payload = {
        "schema_version": REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION,
        "request_sha256": request_sha256,
        "bundle_sha256": bundle_sha256,
        "proposal_sha256": proposal_sha256,
        "content_sha256": content_sha256,
        "provider_id": provider_id,
        "model_id": model_id,
        "item_count": item_count,
        "required_checks": list(REQUIRED_REVIEW_CHECKS),
        "review_requested": True,
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


def build_future_remediation_text_review_request(
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
) -> FutureRemediationTextReviewRequest:
    """Request independent review only after strict live proposal validation."""

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
    if not proposal.remediation_proposal_created:
        raise PermissionError("remediation text review requires an existing proposal")
    if proposal.execution_allowed or proposal.target_interaction_allowed:
        raise ValueError("remediation text review source proposal must remain non-executable")
    if proposal.future_semantics != "unresolved":
        raise ValueError("remediation text review source proposal must remain unresolved")
    if proposal.security_verdict != "not_evaluated":
        raise ValueError("remediation text review source proposal must not precompute a verdict")

    review_request_sha256 = _review_request_digest(
        request_sha256=proposal.request_sha256,
        bundle_sha256=proposal.bundle_sha256,
        proposal_sha256=proposal.proposal_sha256,
        content_sha256=proposal.content_sha256,
        provider_id=proposal.provider_id,
        model_id=proposal.model_id,
        item_count=proposal.item_count,
    )
    return FutureRemediationTextReviewRequest(
        schema_version=REMEDIATION_TEXT_REVIEW_REQUEST_SCHEMA_VERSION,
        request_sha256=proposal.request_sha256,
        bundle_sha256=proposal.bundle_sha256,
        proposal_sha256=proposal.proposal_sha256,
        content_sha256=proposal.content_sha256,
        provider_id=proposal.provider_id,
        model_id=proposal.model_id,
        item_count=proposal.item_count,
        required_checks=REQUIRED_REVIEW_CHECKS,
        review_request_sha256=review_request_sha256,
    )
