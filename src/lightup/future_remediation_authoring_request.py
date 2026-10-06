"""Bounded ST5 remediation text-authoring request.

This module turns a live-valid, authoring-ready remediation evidence bundle into
immutable planning metadata for a later remediation-advisor stage. It does not
invoke a model, generate code/config, call tools, interact with targets, execute
remediation or retests, or authorize deployment.
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
)
from .future_remediation_evidence_bundle import (
    FutureRemediationEvidenceBundle,
    require_future_remediation_evidence_bundle_for_authoring,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


AUTHORING_REQUEST_SCHEMA_VERSION = "st5.remediation_authoring_request.v1"


@dataclass(frozen=True)
class RemediationAuthoringEvidenceRef:
    evidence_id: str
    run_id: str
    capability_id: str
    kind: str
    sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureRemediationAuthoringRequestItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    evidence: tuple[RemediationAuthoringEvidenceRef, ...]
    evidence_manifest_sha256: str
    requested_output: str = "remediation_text_proposal"
    remediation_required: bool = True
    future_state_retest_required: bool = True

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureRemediationAuthoringRequest:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    report_sha256: str
    plan_sha256: str
    bundle_sha256: str
    items: tuple[FutureRemediationAuthoringRequestItem, ...]
    item_count: int
    request_sha256: str
    authoring_requested: bool = True
    remediation_proposal_created: bool = False
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
        if self.authoring_requested is not True:
            raise ValueError("authoring_requested must remain true")
        if self.remediation_proposal_created is not False:
            raise ValueError("remediation_proposal_created must remain false")
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

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _request_digest(
    *,
    bundle: FutureRemediationEvidenceBundle,
    items: tuple[FutureRemediationAuthoringRequestItem, ...],
) -> str:
    payload = {
        "schema_version": AUTHORING_REQUEST_SCHEMA_VERSION,
        "client_id": bundle.client_id,
        "current_twin_id": bundle.current_twin_id,
        "current_twin_version": bundle.current_twin_version,
        "twin_id": bundle.twin_id,
        "twin_version": bundle.twin_version,
        "changeset_id": bundle.changeset_id,
        "report_sha256": bundle.report_sha256,
        "plan_sha256": bundle.plan_sha256,
        "bundle_sha256": bundle.bundle_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "effect_ids": list(item.effect_ids),
                "capability_ids": list(item.capability_ids),
                "evidence": [record.as_dict() for record in item.evidence],
                "evidence_manifest_sha256": item.evidence_manifest_sha256,
                "requested_output": "remediation_text_proposal",
                "remediation_required": True,
                "future_state_retest_required": True,
            }
            for item in items
        ],
        "item_count": len(items),
        "authoring_requested": True,
        "remediation_proposal_created": False,
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


def build_future_remediation_authoring_request(
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationAuthoringRequest:
    """Create a bounded text-authoring request from exact live evidence lineage."""

    live_bundle = require_future_remediation_evidence_bundle_for_authoring(
        bundle,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if not live_bundle.items:
        raise ValueError("remediation authoring request requires remediation items")

    request_items: list[FutureRemediationAuthoringRequestItem] = []
    for item in live_bundle.items:
        if item.classification not in {
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        }:
            raise ValueError(
                "remediation authoring request item has unsupported classification"
            )
        if not item.remediation_required or not item.future_state_retest_required:
            raise ValueError(
                "remediation authoring request requires remediation plus future retest"
            )
        if not item.evidence:
            raise ValueError(
                "remediation authoring request requires bounded evidence references"
            )

        request_items.append(
            FutureRemediationAuthoringRequestItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                capability_ids=item.capability_ids,
                evidence=tuple(
                    RemediationAuthoringEvidenceRef(
                        evidence_id=record.evidence_id,
                        run_id=record.run_id,
                        capability_id=record.capability_id,
                        kind=record.kind,
                        sha256=record.sha256,
                    )
                    for record in item.evidence
                ),
                evidence_manifest_sha256=item.evidence_manifest_sha256,
            )
        )

    items = tuple(
        sorted(
            request_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.resolution_id,
            ),
        )
    )
    request_sha256 = _request_digest(bundle=live_bundle, items=items)
    return FutureRemediationAuthoringRequest(
        schema_version=AUTHORING_REQUEST_SCHEMA_VERSION,
        client_id=live_bundle.client_id,
        current_twin_id=live_bundle.current_twin_id,
        current_twin_version=live_bundle.current_twin_version,
        twin_id=live_bundle.twin_id,
        twin_version=live_bundle.twin_version,
        changeset_id=live_bundle.changeset_id,
        report_sha256=live_bundle.report_sha256,
        plan_sha256=live_bundle.plan_sha256,
        bundle_sha256=live_bundle.bundle_sha256,
        items=items,
        item_count=len(items),
        request_sha256=request_sha256,
    )


def validate_future_remediation_authoring_request(
    request: FutureRemediationAuthoringRequest,
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationAuthoringRequest:
    """Rebuild a request from live lineage before any later authoring use."""

    if not isinstance(request, FutureRemediationAuthoringRequest):
        raise ValueError(
            "request must be a FutureRemediationAuthoringRequest"
        )
    rebuilt = build_future_remediation_authoring_request(
        bundle,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != request:
        raise ValueError(
            "remediation authoring request does not match its live validated lineage"
        )
    return rebuilt
