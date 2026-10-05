"""Project durable domain evidence into a tenant-isolated current Security Twin.

ST1 is intentionally read-only. It does not perform target interaction, execute
capabilities, or expand authorization. The projection consumes only records
already stored in the LightUp domain store.

A domain finding is considered eligible for the verified projection only when
it carries at least one evidence reference. Evidence-less findings remain in
the domain store but are omitted from the verified twin graph.
"""

from __future__ import annotations

from dataclasses import dataclass, replace
from hashlib import sha256

from .domain import AccessContext, DomainStore
from .models import RetestStatus
from .twin import (
    AttackPath,
    AttackStep,
    FactProvenance,
    SecurityTwin,
    TwinFact,
    TwinNode,
    TwinNodeKind,
    TwinRelationship,
)


def _stable_id(prefix: str, *parts: str) -> str:
    payload = "\x1f".join(parts).encode("utf-8")
    return f"{prefix}:{sha256(payload).hexdigest()[:20]}"


@dataclass(frozen=True)
class AttackPathExplanation:
    path_id: str
    title: str
    steps: tuple[str, ...]
    evidence_refs: tuple[str, ...]


def project_current_twin(
    store: DomainStore,
    ctx: AccessContext,
    client_id: str | None = None,
) -> SecurityTwin:
    """Build an immutable current-state twin from one tenant's durable records."""
    scoped_client_id = ctx.resolve_client(client_id, "project_current_twin")
    store.get_client(ctx, scoped_client_id)

    nodes: dict[str, TwinNode] = {}
    facts: list[TwinFact] = []
    relationships: list[TwinRelationship] = []
    attack_paths: list[AttackPath] = []
    contextual_edges: set[tuple[str, str]] = set()

    for engagement in store.list_engagements(ctx, scoped_client_id):
        engagement_node_id = f"engagement:{engagement.engagement_id}"
        nodes[engagement_node_id] = TwinNode(
            engagement_node_id,
            TwinNodeKind.ENGAGEMENT,
            engagement.name,
            (
                ("engagement_id", engagement.engagement_id),
                ("status", engagement.status.value),
            ),
        )

        for capability_id, status in sorted(
            store.get_coverage(ctx, engagement.engagement_id).items()
        ):
            facts.append(
                TwinFact(
                    _stable_id("coverage", engagement.engagement_id, capability_id),
                    engagement_node_id,
                    f"coverage:{capability_id}",
                    status,
                    FactProvenance.OBSERVED,
                    1.0,
                )
            )

        findings = sorted(
            store.list_findings(ctx, engagement_id=engagement.engagement_id),
            key=lambda finding: finding.finding_id,
        )
        for finding in findings:
            evidence_refs = tuple(
                sorted({ref.strip() for ref in finding.evidence_ids if ref.strip()})
            )
            if not evidence_refs:
                continue

            asset_node_id = _stable_id("asset", scoped_client_id, finding.asset)
            nodes.setdefault(
                asset_node_id,
                TwinNode(
                    asset_node_id,
                    TwinNodeKind.ASSET,
                    finding.asset,
                    (("asset", finding.asset),),
                ),
            )

            finding_node_id = f"finding:{finding.finding_id}"
            nodes[finding_node_id] = TwinNode(
                finding_node_id,
                TwinNodeKind.FINDING,
                finding.title,
                (
                    ("finding_id", finding.finding_id),
                    ("severity", finding.severity.value),
                    ("retest_status", finding.retest_status.value),
                    ("engagement_id", finding.engagement_id),
                ),
            )

            facts.extend(
                (
                    TwinFact(
                        f"fact:{finding.finding_id}:severity",
                        finding_node_id,
                        "severity",
                        finding.severity.value,
                        FactProvenance.VERIFIED,
                        1.0,
                        evidence_refs,
                    ),
                    TwinFact(
                        f"fact:{finding.finding_id}:retest_status",
                        finding_node_id,
                        "retest_status",
                        finding.retest_status.value,
                        FactProvenance.OBSERVED,
                        1.0,
                    ),
                )
            )

            edge_key = (engagement_node_id, asset_node_id)
            if edge_key not in contextual_edges:
                contextual_edges.add(edge_key)
                relationships.append(
                    TwinRelationship(
                        _stable_id(
                            "relationship",
                            engagement.engagement_id,
                            asset_node_id,
                            "assessed_asset",
                        ),
                        engagement_node_id,
                        asset_node_id,
                        "assessed_asset",
                        FactProvenance.OBSERVED,
                        1.0,
                    )
                )

            relationships.append(
                TwinRelationship(
                    f"relationship:{finding.finding_id}:verified",
                    asset_node_id,
                    finding_node_id,
                    "has_verified_finding",
                    FactProvenance.VERIFIED,
                    1.0,
                    evidence_refs,
                )
            )

            if finding.retest_status is not RetestStatus.FIXED:
                attack_paths.append(
                    AttackPath(
                        f"path:{finding.finding_id}",
                        f"{finding.asset}: {finding.title}",
                        (
                            AttackStep(
                                asset_node_id,
                                finding_node_id,
                                "has_verified_finding",
                                evidence_refs,
                            ),
                        ),
                        evidence_refs,
                    )
                )

    base = SecurityTwin.current(scoped_client_id)
    twin = replace(
        base,
        nodes=tuple(nodes[key] for key in sorted(nodes)),
        facts=tuple(sorted(facts, key=lambda fact: fact.fact_id)),
        relationships=tuple(
            sorted(relationships, key=lambda relationship: relationship.relationship_id)
        ),
        attack_paths=tuple(sorted(attack_paths, key=lambda path: path.path_id)),
        metadata=(("projection", "domain-store"), ("projection_stage", "ST1")),
    )
    twin.validate()
    return twin


def explain_attack_path(twin: SecurityTwin, path_id: str) -> AttackPathExplanation:
    """Return a human-readable, evidence-linked explanation for one path."""
    twin.validate()
    path = next(
        (candidate for candidate in twin.attack_paths if candidate.path_id == path_id),
        None,
    )
    if path is None:
        raise KeyError(f"unknown attack path {path_id!r}")

    node_by_id = {node.node_id: node for node in twin.nodes}
    evidence_refs = set(path.evidence_refs)
    rendered_steps: list[str] = []
    for step in path.steps:
        evidence_refs.update(step.evidence_refs)
        rendered_steps.append(
            f"{node_by_id[step.source_id].label} --{step.relation}--> "
            f"{node_by_id[step.target_id].label}"
        )

    return AttackPathExplanation(
        path.path_id,
        path.title,
        tuple(rendered_steps),
        tuple(sorted(evidence_refs)),
    )


def query_attack_paths(
    twin: SecurityTwin,
    *,
    node_id: str | None = None,
    evidence_ref: str | None = None,
) -> tuple[AttackPathExplanation, ...]:
    """Query explainable paths without inventing inferred graph transitions."""
    twin.validate()
    explanations: list[AttackPathExplanation] = []
    for path in twin.attack_paths:
        if node_id is not None and not any(
            step.source_id == node_id or step.target_id == node_id
            for step in path.steps
        ):
            continue
        explanation = explain_attack_path(twin, path.path_id)
        if evidence_ref is not None and evidence_ref not in explanation.evidence_refs:
            continue
        explanations.append(explanation)
    return tuple(explanations)
