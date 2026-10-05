"""Tenant-scoped, read-only review of future subject decisions.

A verified subject association establishes identity only. This report cannot
grant execution, claim production safety, or evaluate future attack paths.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass

from .domain import AccessContext, TenantIsolationError
from .future_subject_resolution import validate_future_subject_snapshot
from .state import StateStore
from .twin import SecurityTwin, TwinNodeKind


@dataclass(frozen=True)
class FutureSubjectReviewItem:
    change_node_id: str
    signal_id: str
    object_path: str
    summary: str
    binding_status: str
    candidate_subject_ids: tuple[str, ...]
    review_status: str
    next_action: str
    verified_subject_id: str | None
    decision_id: str | None
    review_basis: str | None
    evidence_refs: tuple[str, ...]


@dataclass(frozen=True)
class FutureSubjectReview:
    client_id: str
    twin_id: str
    twin_version: int
    changeset_id: str
    items: tuple[FutureSubjectReviewItem, ...]
    unresolved_change_count: int
    subject_review_complete: bool
    future_semantics: str = "unresolved"
    security_verdict: str = "not_evaluated"

    def as_dict(self) -> dict:
        """A detached JSON-serializable value; contains references, not payloads."""
        return asdict(self)


def review_future_subjects(
    future: SecurityTwin,
    state: StateStore,
    context: AccessContext,
    *,
    client_id: str | None = None,
) -> FutureSubjectReview:
    """Describe only canonical state backed by still-present ledger evidence.

    Operators must explicitly select a client. Client users can read only their
    own twin. Authorization is checked before snapshot or evidence inspection.
    A malformed or stale snapshot raises rather than yielding a partial report.
    """
    selected_client = context.resolve_client(client_id, "review future subjects")
    if selected_client != future.client_id:
        raise TenantIsolationError("future subject review cannot cross tenants")

    changeset_id = dict(future.metadata).get("changeset_id", "")
    validate_future_subject_snapshot(
        future, state, client_id=selected_client, changeset_id=changeset_id,
    )
    facts_by_change: dict[str, dict[str, str]] = {}
    candidates: dict[str, list[str]] = {}
    verified = {}
    for fact in future.facts:
        if fact.predicate == "change.binding_status" or fact.predicate.startswith("future_subject."):
            facts_by_change.setdefault(fact.subject_id, {})[fact.predicate] = fact.value
    for relationship in future.relationships:
        if relationship.relation == "candidate_affects":
            candidates.setdefault(relationship.source_id, []).append(relationship.target_id)
        elif relationship.relation == "verified_affects_subject":
            verified[relationship.source_id] = relationship

    items = []
    next_actions = {
        "no_candidate": "supply_candidate_mapping",
        "ambiguous": "disambiguate_candidate_mapping",
        "single_candidate": "record_explicit_subject_review",
    }
    for node in sorted(future.nodes, key=lambda item: item.node_id):
        if node.kind is not TwinNodeKind.CHANGE:
            continue
        attributes = dict(node.attributes)
        facts = facts_by_change[node.node_id]
        binding_status = facts["change.binding_status"]
        decision = verified.get(node.node_id)
        items.append(FutureSubjectReviewItem(
            change_node_id=node.node_id,
            signal_id=attributes["signal_id"],
            object_path=attributes["object_path"],
            summary=node.label,
            binding_status=binding_status,
            candidate_subject_ids=tuple(sorted(candidates.get(node.node_id, ()))),
            review_status="verified" if decision else "pending",
            next_action="await_effect_graph_resolution" if decision else next_actions[binding_status],
            verified_subject_id=decision.target_id if decision else None,
            decision_id=facts.get("future_subject.decision_id"),
            review_basis=facts.get("future_subject.basis"),
            evidence_refs=tuple(sorted(decision.evidence_refs)) if decision else (),
        ))

    unresolved = sum(item.review_status != "verified" for item in items)
    return FutureSubjectReview(
        client_id=selected_client, twin_id=future.twin_id, twin_version=future.version,
        changeset_id=changeset_id, items=tuple(items),
        unresolved_change_count=unresolved,
        subject_review_complete=bool(items) and unresolved == 0,
    )
