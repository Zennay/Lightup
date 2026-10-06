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


_CONSTRAINT_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "request_sha256",
    "items",
    "freshness_item_count",
    "constraints_sha256",
    "collection_authorized",
    "capability_selected",
    "tool_call_created",
    "execution_allowed",
    "target_interaction_allowed",
    "remediation_authoring_allowed",
    "future_state_retest_allowed",
    "deployment_authorized",
    "attack_path_mutation_allowed",
    "future_semantics",
    "security_verdict",
}

_FRESHNESS_ITEM_KEYS = {
    "change_node_id",
    "subject_node_id",
    "source_resolution_id",
    "source_resolution_sha256",
    "effect_ids",
    "current_attack_path_ids",
    "prior_capability_ids",
    "prior_evidence",
    "forbidden_evidence_ids",
    "forbidden_run_ids",
    "fresh_evidence_required",
    "fresh_run_required",
    "capability_selected",
    "outcome_classification_selected",
}

_PRIOR_EVIDENCE_KEYS = {
    "evidence_id",
    "run_id",
    "capability_id",
    "kind",
    "sha256",
}


def _strict_identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a canonical non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} is not canonical")
    return value


def _strict_string_list(
    value: object,
    *,
    name: str,
    allow_empty: bool,
) -> tuple[str, ...]:
    if not isinstance(value, list):
        raise ValueError(f"{name} must be a string list")
    if not value and not allow_empty:
        raise ValueError(f"{name} must be a non-empty string list")
    parsed = tuple(_strict_identifier(item, name=name) for item in value)
    if parsed != tuple(sorted(set(parsed))):
        raise ValueError(f"{name} must be sorted and unique")
    return parsed


def _constraints_digest_from_constraints(
    constraints: FutureSecurityEvidenceFreshnessConstraints,
) -> str:
    payload = {
        "schema_version": FRESHNESS_SCHEMA_VERSION,
        "client_id": constraints.client_id,
        "current_twin_id": constraints.current_twin_id,
        "current_twin_version": constraints.current_twin_version,
        "twin_id": constraints.twin_id,
        "twin_version": constraints.twin_version,
        "changeset_id": constraints.changeset_id,
        "request_sha256": constraints.request_sha256,
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
            for item in constraints.items
        ],
        "freshness_item_count": len(constraints.items),
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


def future_security_evidence_freshness_constraints_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceFreshnessConstraints:
    """Parse an exact serialized freshness contract and verify its digest."""

    if not isinstance(payload, dict):
        raise ValueError("evidence freshness payload must be an object")
    if set(payload) != _CONSTRAINT_KEYS:
        raise ValueError("evidence freshness payload schema mismatch")
    if payload["schema_version"] != FRESHNESS_SCHEMA_VERSION:
        raise ValueError("evidence freshness schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
    ):
        _strict_identifier(payload[field], name=f"evidence freshness {field}")
    _require_sha256(payload["request_sha256"], name="request_sha256")
    _require_sha256(payload["constraints_sha256"], name="constraints_sha256")

    for field in ("current_twin_version", "twin_version", "freshness_item_count"):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(
                f"evidence freshness {field} must be a non-negative integer"
            )

    for field in (
        "collection_authorized",
        "capability_selected",
        "tool_call_created",
        "execution_allowed",
        "target_interaction_allowed",
        "remediation_authoring_allowed",
        "future_state_retest_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(f"evidence freshness safety flag {field} must remain false")
    if payload["future_semantics"] != "unresolved":
        raise ValueError("evidence freshness future semantics must remain unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError("evidence freshness must not claim a security verdict")

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("evidence freshness items must be a non-empty list")

    items: list[FutureSecurityEvidenceFreshnessItem] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _FRESHNESS_ITEM_KEYS:
            raise ValueError("evidence freshness item schema mismatch")

        change_node_id = _strict_identifier(
            raw_item["change_node_id"],
            name="evidence freshness change_node_id",
        )
        subject_node_id = _strict_identifier(
            raw_item["subject_node_id"],
            name="evidence freshness subject_node_id",
        )
        source_resolution_id = _strict_identifier(
            raw_item["source_resolution_id"],
            name="evidence freshness source_resolution_id",
        )
        _require_sha256(
            raw_item["source_resolution_sha256"],
            name="source_resolution_sha256",
        )

        effect_ids = _strict_string_list(
            raw_item["effect_ids"],
            name="evidence freshness effect_ids",
            allow_empty=False,
        )
        current_attack_path_ids = _strict_string_list(
            raw_item["current_attack_path_ids"],
            name="evidence freshness current_attack_path_ids",
            allow_empty=True,
        )
        prior_capability_ids = _strict_string_list(
            raw_item["prior_capability_ids"],
            name="evidence freshness prior_capability_ids",
            allow_empty=False,
        )
        forbidden_evidence_ids = _strict_string_list(
            raw_item["forbidden_evidence_ids"],
            name="evidence freshness forbidden_evidence_ids",
            allow_empty=False,
        )
        forbidden_run_ids = _strict_string_list(
            raw_item["forbidden_run_ids"],
            name="evidence freshness forbidden_run_ids",
            allow_empty=False,
        )

        if raw_item["fresh_evidence_required"] is not True:
            raise ValueError("evidence freshness item must require fresh evidence")
        if raw_item["fresh_run_required"] is not True:
            raise ValueError("evidence freshness item must require a fresh run")
        if raw_item["capability_selected"] is not False:
            raise ValueError("evidence freshness item cannot select a capability")
        if raw_item["outcome_classification_selected"] is not False:
            raise ValueError(
                "evidence freshness item cannot select an outcome classification"
            )

        raw_prior = raw_item["prior_evidence"]
        if not isinstance(raw_prior, list) or not raw_prior:
            raise ValueError("evidence freshness prior_evidence must be a non-empty list")

        prior: list[PriorEvidenceFingerprint] = []
        for raw_evidence in raw_prior:
            if (
                not isinstance(raw_evidence, dict)
                or set(raw_evidence) != _PRIOR_EVIDENCE_KEYS
            ):
                raise ValueError("evidence freshness prior evidence schema mismatch")
            evidence_id = _strict_identifier(
                raw_evidence["evidence_id"],
                name="evidence freshness evidence_id",
            )
            run_id = _strict_identifier(
                raw_evidence["run_id"],
                name="evidence freshness run_id",
            )
            capability_id = _strict_identifier(
                raw_evidence["capability_id"],
                name="evidence freshness capability_id",
            )
            kind = _strict_identifier(
                raw_evidence["kind"],
                name="evidence freshness evidence kind",
            )
            _require_sha256(raw_evidence["sha256"], name="prior evidence sha256")
            prior.append(
                PriorEvidenceFingerprint(
                    evidence_id=evidence_id,
                    run_id=run_id,
                    capability_id=capability_id,
                    kind=kind,
                    sha256=raw_evidence["sha256"],
                )
            )

        prior_evidence = tuple(prior)
        canonical_prior = tuple(
            sorted(prior_evidence, key=lambda evidence: evidence.evidence_id)
        )
        if prior_evidence != canonical_prior:
            raise ValueError("evidence freshness prior evidence must be canonically ordered")
        evidence_ids = tuple(evidence.evidence_id for evidence in prior_evidence)
        if len(set(evidence_ids)) != len(evidence_ids):
            raise ValueError("evidence freshness prior evidence IDs must be unique")
        if forbidden_evidence_ids != evidence_ids:
            raise ValueError(
                "evidence freshness forbidden evidence IDs must match prior evidence"
            )
        prior_run_ids = tuple(sorted({evidence.run_id for evidence in prior_evidence}))
        if forbidden_run_ids != prior_run_ids:
            raise ValueError(
                "evidence freshness forbidden run IDs must match prior evidence"
            )
        prior_capabilities = tuple(
            sorted({evidence.capability_id for evidence in prior_evidence})
        )
        if prior_capability_ids != prior_capabilities:
            raise ValueError(
                "evidence freshness prior capabilities must match prior evidence"
            )

        items.append(
            FutureSecurityEvidenceFreshnessItem(
                change_node_id=change_node_id,
                subject_node_id=subject_node_id,
                source_resolution_id=source_resolution_id,
                source_resolution_sha256=raw_item["source_resolution_sha256"],
                effect_ids=effect_ids,
                current_attack_path_ids=current_attack_path_ids,
                prior_capability_ids=prior_capability_ids,
                prior_evidence=prior_evidence,
                forbidden_evidence_ids=forbidden_evidence_ids,
                forbidden_run_ids=forbidden_run_ids,
            )
        )

    parsed_items = tuple(items)
    identities = tuple(
        (item.change_node_id, item.subject_node_id, item.source_resolution_id)
        for item in parsed_items
    )
    if len(set(identities)) != len(identities):
        raise ValueError("evidence freshness item identities must be unique")
    canonical_items = tuple(
        sorted(
            parsed_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.source_resolution_id,
            ),
        )
    )
    if parsed_items != canonical_items:
        raise ValueError("evidence freshness items must be canonically ordered")
    if payload["freshness_item_count"] != len(parsed_items):
        raise ValueError("evidence freshness item count mismatch")

    constraints = FutureSecurityEvidenceFreshnessConstraints(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        request_sha256=payload["request_sha256"],
        items=parsed_items,
        freshness_item_count=payload["freshness_item_count"],
        constraints_sha256=payload["constraints_sha256"],
        collection_authorized=False,
        capability_selected=False,
        tool_call_created=False,
        execution_allowed=False,
        target_interaction_allowed=False,
        remediation_authoring_allowed=False,
        future_state_retest_allowed=False,
        deployment_authorized=False,
        attack_path_mutation_allowed=False,
        future_semantics=payload["future_semantics"],
        security_verdict=payload["security_verdict"],
    )
    expected = _constraints_digest_from_constraints(constraints)
    if constraints.constraints_sha256 != expected:
        raise ValueError("evidence freshness constraints digest mismatch")
    return constraints
