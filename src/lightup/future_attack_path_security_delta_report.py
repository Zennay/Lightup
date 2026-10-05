"""Evidence-linked read-only ST4 security delta reporting.

The report is a product-facing projection of an already validated immutable
attack-path graph-diff preview. It deliberately remains below deployment policy:
no attack paths are mutated and no pass/warn/review/block verdict is emitted.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_preview import (
    AttackPathGraphDiffAction,
    FutureAttackPathGraphDiffPreview,
    validate_future_attack_path_graph_diff_preview,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .state import StateStore


REPORT_SCHEMA_VERSION = "st4.security_delta.v1"


@dataclass(frozen=True)
class FutureAttackPathSecurityDeltaReportItem:
    change_node_id: str
    subject_node_id: str
    resolution_id: str
    resolution_sha256: str
    classification: AttackPathTransitionClassification
    action: AttackPathGraphDiffAction
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureAttackPathSecurityDeltaReport:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    proposal_sha256: str
    impact_analysis_sha256: str
    preview_sha256: str
    items: tuple[FutureAttackPathSecurityDeltaReportItem, ...]
    report_complete: bool
    contains_insufficient_evidence: bool
    report_sha256: str
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        return asdict(self)

    def to_json(self) -> str:
        """Serialize without raw customer code/config or patch material."""
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _report_digest(
    *,
    preview: FutureAttackPathGraphDiffPreview,
    items: tuple[FutureAttackPathSecurityDeltaReportItem, ...],
    contains_insufficient_evidence: bool,
) -> str:
    payload = {
        "schema_version": REPORT_SCHEMA_VERSION,
        "client_id": preview.client_id,
        "current_twin_id": preview.current_twin_id,
        "current_twin_version": preview.current_twin_version,
        "twin_id": preview.twin_id,
        "twin_version": preview.twin_version,
        "changeset_id": preview.changeset_id,
        "proposal_sha256": preview.proposal_sha256,
        "impact_analysis_sha256": preview.impact_analysis_sha256,
        "preview_sha256": preview.preview_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "resolution_id": item.resolution_id,
                "resolution_sha256": item.resolution_sha256,
                "classification": item.classification.value,
                "action": item.action.value,
                "effect_ids": list(item.effect_ids),
                "current_attack_path_ids": list(item.current_attack_path_ids),
                "evidence_ids": list(item.evidence_ids),
                "capability_ids": list(item.capability_ids),
            }
            for item in items
        ],
        "report_complete": True,
        "contains_insufficient_evidence": contains_insufficient_evidence,
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


def build_future_attack_path_security_delta_report(
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureAttackPathSecurityDeltaReport:
    """Build a deterministic evidence-linked report from a live-valid preview."""
    live_preview = validate_future_attack_path_graph_diff_preview(
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )

    if not live_preview.preview_complete:
        raise ValueError("security delta report requires a complete graph diff preview")

    report_items: list[FutureAttackPathSecurityDeltaReportItem] = []
    seen_changes: set[str] = set()
    seen_resolutions: set[str] = set()
    claimed_current_paths: dict[str, str] = {}

    for item in live_preview.items:
        if item.change_node_id in seen_changes:
            raise ValueError("security delta report contains duplicate changes")
        if item.resolution_id in seen_resolutions:
            raise ValueError("security delta report contains duplicate resolutions")
        seen_changes.add(item.change_node_id)
        seen_resolutions.add(item.resolution_id)

        for path_id in item.current_attack_path_ids:
            prior_change = claimed_current_paths.get(path_id)
            if prior_change is not None and prior_change != item.change_node_id:
                raise ValueError(
                    "security delta report has colliding current attack path claims"
                )
            claimed_current_paths[path_id] = item.change_node_id

        report_items.append(
            FutureAttackPathSecurityDeltaReportItem(
                change_node_id=item.change_node_id,
                subject_node_id=item.subject_node_id,
                resolution_id=item.resolution_id,
                resolution_sha256=item.resolution_sha256,
                classification=item.classification,
                action=item.action,
                effect_ids=item.effect_ids,
                current_attack_path_ids=item.current_attack_path_ids,
                evidence_ids=item.evidence_ids,
                capability_ids=item.capability_ids,
            )
        )

    items = tuple(report_items)
    contains_insufficient = any(
        item.classification
        is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE
        for item in items
    )
    if contains_insufficient != live_preview.contains_insufficient_evidence:
        raise ValueError(
            "security delta report insufficient-evidence state is inconsistent"
        )

    digest = _report_digest(
        preview=live_preview,
        items=items,
        contains_insufficient_evidence=contains_insufficient,
    )

    return FutureAttackPathSecurityDeltaReport(
        schema_version=REPORT_SCHEMA_VERSION,
        client_id=live_preview.client_id,
        current_twin_id=live_preview.current_twin_id,
        current_twin_version=live_preview.current_twin_version,
        twin_id=live_preview.twin_id,
        twin_version=live_preview.twin_version,
        changeset_id=live_preview.changeset_id,
        proposal_sha256=live_preview.proposal_sha256,
        impact_analysis_sha256=live_preview.impact_analysis_sha256,
        preview_sha256=live_preview.preview_sha256,
        items=items,
        report_complete=True,
        contains_insufficient_evidence=contains_insufficient,
        report_sha256=digest,
    )
