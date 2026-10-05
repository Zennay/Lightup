"""Fail-closed ST4 attack-graph delta readiness analysis.

This layer consumes a validated ST3 future attack-path impact report plus the
exact Current/Future Security Twins. It does not classify verified path deltas.
Until path-specific future evidence exists, every item remains unknown.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json

from .domain import AccessContext, TenantIsolationError
from .future_attack_path_analysis import (
    FutureAttackPathImpactItem,
    FutureAttackPathImpactReport,
    validate_future_attack_path_impact_report,
)
from .twin import SecurityTwin, TwinSnapshotKind


@dataclass(frozen=True)
class AttackGraphDeltaReadinessItem:
    change_node_id: str
    subject_node_id: str
    graph_resolution_id: str
    subject_decision_id: str
    materialization_resolution_id: str
    effect_ids: tuple[str, ...]
    current_attack_path_ids: tuple[str, ...]
    impact_hint: str
    candidate_direction_hint: str
    verified_delta_classification: str
    verification_state: str
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class AttackGraphDeltaReadinessReport:
    client_id: str
    current_twin_id: str
    current_twin_version: int
    current_twin_sha256: str
    future_twin_id: str
    future_twin_version: int
    future_twin_sha256: str
    changeset_id: str
    impact_analysis_sha256: str
    items: tuple[AttackGraphDeltaReadinessItem, ...]
    readiness_assessed: bool
    report_sha256: str
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"
    attack_path_mutation_allowed: bool = False

    def as_dict(self) -> dict:
        """Return a detached JSON-serializable representation."""
        return asdict(self)


def _candidate_direction_hint(impact: str) -> str:
    mapping = {
        "potential_regression": "potential_worsening",
        "potential_improvement": "potential_improvement",
        "mixed": "mixed",
        "unchanged": "unchanged",
    }
    try:
        return mapping[impact]
    except KeyError as exc:
        raise ValueError(f"unsupported ST3 impact hint {impact!r}") from exc


def _current_paths_touching_subject(
    current: SecurityTwin,
    subject_node_id: str,
) -> tuple[str, ...]:
    return tuple(
        sorted(
            path.path_id
            for path in current.attack_paths
            if any(
                step.source_id == subject_node_id
                or step.target_id == subject_node_id
                for step in path.steps
            )
        )
    )


def _report_digest(
    *,
    client_id: str,
    current_twin_id: str,
    current_twin_version: int,
    current_twin_sha256: str,
    future_twin_id: str,
    future_twin_version: int,
    future_twin_sha256: str,
    changeset_id: str,
    impact_analysis_sha256: str,
    items: tuple[AttackGraphDeltaReadinessItem, ...],
) -> str:
    payload = {
        "client_id": client_id,
        "current_twin_id": current_twin_id,
        "current_twin_version": current_twin_version,
        "current_twin_sha256": current_twin_sha256,
        "future_twin_id": future_twin_id,
        "future_twin_version": future_twin_version,
        "future_twin_sha256": future_twin_sha256,
        "changeset_id": changeset_id,
        "impact_analysis_sha256": impact_analysis_sha256,
        "items": [asdict(item) for item in items],
        "readiness_assessed": True,
        "future_semantics": "unresolved",
        "security_verdict": "not_evaluated",
        "attack_path_mutation_allowed": False,
    }
    encoded = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def validate_attack_graph_delta_readiness_report(
    report: AttackGraphDeltaReadinessReport,
) -> None:
    """Validate the immutable ST4 readiness handoff and its fixed boundaries."""
    if not report.readiness_assessed:
        raise ValueError("attack graph delta readiness report is incomplete")
    if report.future_semantics != "unresolved":
        raise ValueError("attack graph delta readiness must preserve unresolved semantics")
    if report.security_verdict != "not_evaluated":
        raise ValueError("attack graph delta readiness cannot claim a security verdict")
    if report.attack_path_mutation_allowed:
        raise ValueError("attack graph delta readiness cannot allow attack-path mutation")
    if not report.items:
        raise ValueError("attack graph delta readiness requires at least one item")

    for item in report.items:
        if item.verified_delta_classification != "unknown":
            raise ValueError("ST4 readiness cannot claim a verified path delta")
        if item.verification_state != "insufficient_future_path_evidence":
            raise ValueError("ST4 readiness requires insufficient-evidence state")
        expected_hint = _candidate_direction_hint(item.impact_hint)
        if item.candidate_direction_hint != expected_hint:
            raise ValueError("ST4 readiness candidate direction hint is not canonical")
        if not item.effect_ids:
            raise ValueError("ST4 readiness requires effect lineage")

    expected = _report_digest(
        client_id=report.client_id,
        current_twin_id=report.current_twin_id,
        current_twin_version=report.current_twin_version,
        current_twin_sha256=report.current_twin_sha256,
        future_twin_id=report.future_twin_id,
        future_twin_version=report.future_twin_version,
        future_twin_sha256=report.future_twin_sha256,
        changeset_id=report.changeset_id,
        impact_analysis_sha256=report.impact_analysis_sha256,
        items=report.items,
    )
    if report.report_sha256 != expected:
        raise ValueError("attack graph delta readiness report digest mismatch")


def build_attack_graph_delta_readiness(
    impact_report: FutureAttackPathImpactReport,
    *,
    current: SecurityTwin,
    future: SecurityTwin,
    context: AccessContext,
    client_id: str | None = None,
) -> AttackGraphDeltaReadinessReport:
    """Build a read-only ST4 readiness report without inferring path deltas."""
    selected_client = context.resolve_client(
        client_id, "build attack graph delta readiness"
    )
    if (
        impact_report.client_id != selected_client
        or current.client_id != selected_client
        or future.client_id != selected_client
    ):
        raise TenantIsolationError(
            "attack graph delta readiness current/future/report cannot cross tenants"
        )

    validate_future_attack_path_impact_report(impact_report)
    current.validate()
    future.validate()

    if current.kind is not TwinSnapshotKind.CURRENT:
        raise ValueError("attack graph delta readiness requires a Current Twin")
    if future.kind is not TwinSnapshotKind.FUTURE:
        raise ValueError("attack graph delta readiness requires a Future Twin")

    if (
        impact_report.current_twin_id != current.twin_id
        or impact_report.current_twin_version != current.version
    ):
        raise ValueError("ST3 report does not match the supplied Current Twin")
    if (
        impact_report.twin_id != future.twin_id
        or impact_report.twin_version != future.version
    ):
        raise ValueError("ST3 report does not match the supplied Future Twin")

    current_digest = current.stable_digest()
    future_digest = future.stable_digest()
    metadata = dict(future.metadata)
    if (
        metadata.get("future_base_twin_id") != current.twin_id
        or metadata.get("future_base_twin_version") != str(current.version)
        or metadata.get("future_base_twin_sha256") != current_digest
    ):
        raise ValueError("Future Twin baseline lineage does not match Current Twin")
    if metadata.get("changeset_id") != impact_report.changeset_id:
        raise ValueError("Future Twin ChangeSet does not match ST3 impact report")
    if metadata.get("future_semantics") != "unresolved":
        raise ValueError("ST4 readiness requires unresolved Future Twin semantics")
    if future.attack_paths != current.attack_paths:
        raise ValueError("ST4 readiness requires attack paths unchanged from Current Twin")

    current_nodes = {node.node_id: node for node in current.nodes}
    future_nodes = {node.node_id: node for node in future.nodes}
    future_change_ids = {node.node_id for node in future.nodes}

    items: list[AttackGraphDeltaReadinessItem] = []
    for impact in impact_report.items:
        current_subject = current_nodes.get(impact.subject_node_id)
        future_subject = future_nodes.get(impact.subject_node_id)
        if current_subject is None or future_subject != current_subject:
            raise ValueError("ST4 readiness subject identity drifted from Current Twin")
        if impact.change_node_id not in future_change_ids:
            raise ValueError("ST4 readiness change node is absent from Future Twin")

        exact_paths = _current_paths_touching_subject(current, impact.subject_node_id)
        if exact_paths != impact.current_attack_path_ids:
            raise ValueError("ST3 current-path membership does not match Current Twin")

        items.append(
            AttackGraphDeltaReadinessItem(
                change_node_id=impact.change_node_id,
                subject_node_id=impact.subject_node_id,
                graph_resolution_id=impact.graph_resolution_id,
                subject_decision_id=impact.subject_decision_id,
                materialization_resolution_id=impact.materialization_resolution_id,
                effect_ids=impact.effect_ids,
                current_attack_path_ids=impact.current_attack_path_ids,
                impact_hint=impact.impact,
                candidate_direction_hint=_candidate_direction_hint(impact.impact),
                verified_delta_classification="unknown",
                verification_state="insufficient_future_path_evidence",
                evidence_refs=impact.evidence_refs,
            )
        )

    report_items = tuple(
        sorted(items, key=lambda item: (item.change_node_id, item.subject_node_id))
    )
    report_sha256 = _report_digest(
        client_id=selected_client,
        current_twin_id=current.twin_id,
        current_twin_version=current.version,
        current_twin_sha256=current_digest,
        future_twin_id=future.twin_id,
        future_twin_version=future.version,
        future_twin_sha256=future_digest,
        changeset_id=impact_report.changeset_id,
        impact_analysis_sha256=impact_report.analysis_sha256,
        items=report_items,
    )
    report = AttackGraphDeltaReadinessReport(
        client_id=selected_client,
        current_twin_id=current.twin_id,
        current_twin_version=current.version,
        current_twin_sha256=current_digest,
        future_twin_id=future.twin_id,
        future_twin_version=future.version,
        future_twin_sha256=future_digest,
        changeset_id=impact_report.changeset_id,
        impact_analysis_sha256=impact_report.analysis_sha256,
        items=report_items,
        readiness_assessed=True,
        report_sha256=report_sha256,
    )
    validate_attack_graph_delta_readiness_report(report)
    return report
