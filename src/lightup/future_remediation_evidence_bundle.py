"""Evidence-bound ST5 remediation authoring input.

This module converts an already live-revalidated remediation/retest plan into a
canonical manifest that a remediation author may inspect.  It deliberately
does not generate code/config changes, execute tools, interact with targets, or
authorize deployment.
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
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
    build_future_security_remediation_retest_plan,
)
from .state import StateStore


BUNDLE_SCHEMA_VERSION = "st5.remediation_evidence_bundle.v1"


@dataclass(frozen=True)
class RemediationEvidenceRef:
    evidence_id: str
    run_id: str
    capability_id: str
    kind: str
    sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureRemediationEvidenceItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    current_attack_path_ids: tuple[str, ...]
    effect_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    evidence: tuple[RemediationEvidenceRef, ...]
    evidence_manifest_sha256: str
    remediation_required: bool = True
    future_state_retest_required: bool = True

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureRemediationEvidenceBundle:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    report_sha256: str
    plan_sha256: str
    items: tuple[FutureRemediationEvidenceItem, ...]
    remediation_item_count: int
    blocking_evidence_gap_count: int
    remediation_authoring_ready: bool
    bundle_sha256: str
    execution_allowed: bool = False
    code_change_authorized: bool = False
    target_interaction_allowed: bool = False
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _validate_sha256(value: str, *, name: str) -> None:
    if (
        len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a canonical lowercase SHA-256 digest")


def _manifest_digest(evidence: tuple[RemediationEvidenceRef, ...]) -> str:
    payload = [
        {
            "evidence_id": record.evidence_id,
            "run_id": record.run_id,
            "capability_id": record.capability_id,
            "kind": record.kind,
            "sha256": record.sha256,
        }
        for record in evidence
    ]
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _bundle_digest(
    *,
    plan: FutureSecurityRemediationRetestPlan,
    items: tuple[FutureRemediationEvidenceItem, ...],
    remediation_authoring_ready: bool,
) -> str:
    payload = {
        "schema_version": BUNDLE_SCHEMA_VERSION,
        "client_id": plan.client_id,
        "current_twin_id": plan.current_twin_id,
        "current_twin_version": plan.current_twin_version,
        "twin_id": plan.twin_id,
        "twin_version": plan.twin_version,
        "changeset_id": plan.changeset_id,
        "report_sha256": plan.report_sha256,
        "plan_sha256": plan.plan_sha256,
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
                "remediation_required": True,
                "future_state_retest_required": True,
            }
            for item in items
        ],
        "remediation_item_count": len(items),
        "blocking_evidence_gap_count": plan.evidence_gap_count,
        "remediation_authoring_ready": remediation_authoring_ready,
        "execution_allowed": False,
        "code_change_authorized": False,
        "target_interaction_allowed": False,
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


def build_future_remediation_evidence_bundle(
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationEvidenceBundle:
    """Build a read-only evidence manifest for remediation authoring."""

    live_plan = build_future_security_remediation_retest_plan(
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if plan != live_plan:
        raise ValueError(
            "remediation evidence bundle requires the exact live remediation plan"
        )
    if plan.execution_allowed:
        raise ValueError("remediation evidence source plan must not allow execution")
    if plan.attack_path_mutation_allowed:
        raise ValueError("remediation evidence source plan must not mutate attack paths")
    if plan.future_semantics != "unresolved":
        raise ValueError("remediation evidence source plan must remain unresolved")
    if plan.security_verdict != "not_evaluated":
        raise ValueError("remediation evidence source plan must not precompute a verdict")

    context_run_ids = {context.run_id for context in contexts}
    bundle_items: list[FutureRemediationEvidenceItem] = []

    for item in plan.items:
        if not item.remediation_required:
            continue
        if item.classification not in {
            AttackPathTransitionClassification.INTRODUCED,
            AttackPathTransitionClassification.WORSENED,
        }:
            raise ValueError("remediation-required item has an invalid classification")
        if not item.future_state_retest_required:
            raise ValueError("remediation-required item must require a future retest")
        if item.evidence_required:
            raise ValueError("remediation-required item cannot carry an evidence gap")
        if not item.evidence_ids:
            raise ValueError("remediation-required item must retain evidence")
        if not item.capability_ids:
            raise ValueError("remediation-required item must retain capabilities")

        evidence_records: list[RemediationEvidenceRef] = []
        for evidence_id in sorted(item.evidence_ids):
            record = state.get_evidence(evidence_id)
            _validate_sha256(record.sha256, name=f"evidence {evidence_id!r} sha256")
            if record.run_id not in context_run_ids:
                raise ValueError("remediation evidence belongs to an unexpected run")
            if record.capability_id not in item.capability_ids:
                raise ValueError("remediation evidence capability is outside item lineage")
            evidence_records.append(
                RemediationEvidenceRef(
                    evidence_id=record.evidence_id,
                    run_id=record.run_id,
                    capability_id=record.capability_id,
                    kind=record.kind,
                    sha256=record.sha256,
                )
            )

        evidence = tuple(evidence_records)
        bundle_items.append(
            FutureRemediationEvidenceItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                current_attack_path_ids=item.current_attack_path_ids,
                effect_ids=item.effect_ids,
                capability_ids=item.capability_ids,
                evidence=evidence,
                evidence_manifest_sha256=_manifest_digest(evidence),
            )
        )

    items = tuple(
        sorted(
            bundle_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.resolution_id,
            ),
        )
    )
    remediation_authoring_ready = bool(items) and not plan.contains_insufficient_evidence
    bundle_sha256 = _bundle_digest(
        plan=plan,
        items=items,
        remediation_authoring_ready=remediation_authoring_ready,
    )

    return FutureRemediationEvidenceBundle(
        schema_version=BUNDLE_SCHEMA_VERSION,
        client_id=plan.client_id,
        current_twin_id=plan.current_twin_id,
        current_twin_version=plan.current_twin_version,
        twin_id=plan.twin_id,
        twin_version=plan.twin_version,
        changeset_id=plan.changeset_id,
        report_sha256=plan.report_sha256,
        plan_sha256=plan.plan_sha256,
        items=items,
        remediation_item_count=len(items),
        blocking_evidence_gap_count=plan.evidence_gap_count,
        remediation_authoring_ready=remediation_authoring_ready,
        bundle_sha256=bundle_sha256,
    )


def validate_future_remediation_evidence_bundle(
    bundle: FutureRemediationEvidenceBundle,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureRemediationEvidenceBundle:
    """Rebuild a persisted bundle from live lineage before remediation use."""

    if not isinstance(bundle, FutureRemediationEvidenceBundle):
        raise ValueError(
            "bundle must be a FutureRemediationEvidenceBundle"
        )

    rebuilt = build_future_remediation_evidence_bundle(
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != bundle:
        raise ValueError(
            "remediation evidence bundle does not match its live validated lineage"
        )
    return rebuilt
