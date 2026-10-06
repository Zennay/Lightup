"""Planning-only freshness constraints for unresolved ST5 evidence gaps.

The contract binds an evidence-collection request to the exact live evidence
and run identities that already proved insufficient.  Those identities become
explicitly ineligible for satisfying the next collection attempt.  No
capability, tool, target, argument, credential, or outcome is selected here.
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
    FutureAttackPathTransitionResolution,
)
from .future_security_evidence_collection_request import (
    FutureSecurityEvidenceCollectionRequest,
    validate_future_security_evidence_collection_request,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


FRESHNESS_SCHEMA_VERSION = "st5.evidence_freshness_constraints.v1"


@dataclass(frozen=True)
class PriorEvidenceFingerprint:
    evidence_id: str
    run_id: str
    capability_id: str
    kind: str
    sha256: str

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityEvidenceFreshnessItem:
    change_node_id: str
    subject_node_id: str
    source_resolution_id: str
    source_resolution_sha256: str
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    prior_capability_ids: tuple[str, ...]
    prior_evidence: tuple[PriorEvidenceFingerprint, ...]
    forbidden_evidence_ids: tuple[str, ...]
    forbidden_run_ids: tuple[str, ...]
    fresh_evidence_required: bool = True
    fresh_run_required: bool = True
    capability_selected: bool = False
    outcome_classification_selected: bool = False

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityEvidenceFreshnessConstraints:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    request_sha256: str
    items: tuple[FutureSecurityEvidenceFreshnessItem, ...]
    freshness_item_count: int
    constraints_sha256: str
    collection_authorized: bool = False
    capability_selected: bool = False
    tool_call_created: bool = False
    execution_allowed: bool = False
    target_interaction_allowed: bool = False
    remediation_authoring_allowed: bool = False
    future_state_retest_allowed: bool = False
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


def _require_sha256(value: str, *, name: str) -> None:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a canonical lowercase SHA-256")


def _constraints_digest(
    *,
    request: FutureSecurityEvidenceCollectionRequest,
    items: tuple[FutureSecurityEvidenceFreshnessItem, ...],
) -> str:
    payload = {
        "schema_version": FRESHNESS_SCHEMA_VERSION,
        "client_id": request.client_id,
        "current_twin_id": request.current_twin_id,
        "current_twin_version": request.current_twin_version,
        "twin_id": request.twin_id,
        "twin_version": request.twin_version,
        "changeset_id": request.changeset_id,
        "request_sha256": request.request_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "source_resolution_id": item.source_resolution_id,
                "source_resolution_sha256": item.source_resolution_sha256,
                "effect_ids": list(item.effect_ids),
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "prior_capability_ids": list(item.prior_capability_ids),
                "prior_evidence": [
                    evidence.as_dict() for evidence in item.prior_evidence
                ],
                "forbidden_evidence_ids": list(item.forbidden_evidence_ids),
                "forbidden_run_ids": list(item.forbidden_run_ids),
                "fresh_evidence_required": True,
                "fresh_run_required": True,
                "capability_selected": False,
                "outcome_classification_selected": False,
            }
            for item in items
        ],
        "freshness_item_count": len(items),
        "collection_authorized": False,
        "capability_selected": False,
        "tool_call_created": False,
        "execution_allowed": False,
        "target_interaction_allowed": False,
        "remediation_authoring_allowed": False,
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


def build_future_security_evidence_freshness_constraints(
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessConstraints:
    """Bind unresolved gaps to the exact evidence/run identities they must not reuse."""

    validated = validate_future_security_evidence_collection_request(
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if validated is not request and validated != request:
        raise ValueError("freshness constraints require the exact live request")

    resolutions_by_id = {resolution.resolution_id: resolution for resolution in resolutions}
    if len(resolutions_by_id) != len(resolutions):
        raise ValueError("freshness constraints require unique source resolutions")

    items: list[FutureSecurityEvidenceFreshnessItem] = []
    for request_item in request.items:
        source_resolution = resolutions_by_id.get(request_item.resolution_id)
        if source_resolution is None:
            raise ValueError("freshness constraints source resolution is missing")
        if source_resolution.resolution_sha256 != request_item.resolution_sha256:
            raise ValueError("freshness constraints source resolution digest mismatch")
        if source_resolution.evidence_ids != request_item.prior_evidence_ids:
            raise ValueError("freshness constraints prior evidence lineage mismatch")
        if source_resolution.capability_ids != request_item.prior_capability_ids:
            raise ValueError("freshness constraints prior capability lineage mismatch")

        prior_records: list[PriorEvidenceFingerprint] = []
        live_capabilities: set[str] = set()
        live_runs: set[str] = set()
        for evidence_id in request_item.prior_evidence_ids:
            record = state.get_evidence(evidence_id)
            _require_sha256(
                record.sha256,
                name=f"evidence {evidence_id!r} sha256",
            )
            if record.run_id != source_resolution.run_id:
                raise ValueError("prior evidence run drifted from source resolution")
            if record.capability_id not in request_item.prior_capability_ids:
                raise ValueError("prior evidence capability drifted from request lineage")
            live_capabilities.add(record.capability_id)
            live_runs.add(record.run_id)
            prior_records.append(
                PriorEvidenceFingerprint(
                    evidence_id=record.evidence_id,
                    run_id=record.run_id,
                    capability_id=record.capability_id,
                    kind=record.kind,
                    sha256=record.sha256,
                )
            )

        if live_capabilities != set(request_item.prior_capability_ids):
            raise ValueError(
                "live prior evidence capabilities do not exactly match request lineage"
            )

        prior_evidence = tuple(
            sorted(prior_records, key=lambda evidence: evidence.evidence_id)
        )
        forbidden_evidence_ids = tuple(
            evidence.evidence_id for evidence in prior_evidence
        )
        forbidden_run_ids = tuple(sorted(live_runs))
        if not forbidden_evidence_ids or not forbidden_run_ids:
            raise ValueError("freshness constraints require prior evidence and run lineage")

        items.append(
            FutureSecurityEvidenceFreshnessItem(
                change_node_id=request_item.change_node_id,
                subject_node_id=request_item.subject_node_id,
                source_resolution_id=request_item.resolution_id,
                source_resolution_sha256=request_item.resolution_sha256,
                effect_ids=request_item.effect_ids,
                current_attack_path_ids=request_item.current_attack_path_ids,
                prior_capability_ids=request_item.prior_capability_ids,
                prior_evidence=prior_evidence,
                forbidden_evidence_ids=forbidden_evidence_ids,
                forbidden_run_ids=forbidden_run_ids,
            )
        )

    canonical_items = tuple(
        sorted(
            items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.source_resolution_id,
            ),
        )
    )
    if len(canonical_items) != request.evidence_gap_count:
        raise ValueError("freshness constraint count does not match evidence gaps")

    constraints_sha256 = _constraints_digest(
        request=request,
        items=canonical_items,
    )
    return FutureSecurityEvidenceFreshnessConstraints(
        schema_version=FRESHNESS_SCHEMA_VERSION,
        client_id=request.client_id,
        current_twin_id=request.current_twin_id,
        current_twin_version=request.current_twin_version,
        twin_id=request.twin_id,
        twin_version=request.twin_version,
        changeset_id=request.changeset_id,
        request_sha256=request.request_sha256,
        items=canonical_items,
        freshness_item_count=len(canonical_items),
        constraints_sha256=constraints_sha256,
    )


def validate_future_security_evidence_freshness_constraints(
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessConstraints:
    """Rebuild persisted freshness constraints against live evidence before use."""

    if not isinstance(constraints, FutureSecurityEvidenceFreshnessConstraints):
        raise ValueError(
            "constraints must be FutureSecurityEvidenceFreshnessConstraints"
        )
    rebuilt = build_future_security_evidence_freshness_constraints(
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if rebuilt != constraints:
        raise ValueError(
            "evidence freshness constraints do not match live validated lineage"
        )
    return rebuilt
