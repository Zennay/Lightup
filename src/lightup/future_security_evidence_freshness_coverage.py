"""Coverage aggregation for live-valid fresh-evidence admissions.

This module reports which unresolved ST5 evidence gaps have a live-valid fresh
candidate admission. Coverage is not evidence sufficiency, gap closure, a
security classification, or execution authority.
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
)
from .future_security_evidence_freshness import (
    FutureSecurityEvidenceFreshnessConstraints,
    validate_future_security_evidence_freshness_constraints,
)
from .future_security_evidence_freshness_admission import (
    FutureSecurityEvidenceFreshnessAdmission,
    validate_future_security_evidence_freshness_admission,
)
from .future_security_remediation_retest_plan import (
    FutureSecurityRemediationRetestPlan,
)
from .state import StateStore


COVERAGE_SCHEMA_VERSION = "st5.evidence_freshness_coverage.v1"


@dataclass(frozen=True)
class FutureSecurityEvidenceFreshnessCoverageItem:
    change_node_id: str
    subject_node_id: str
    source_resolution_id: str
    fresh_candidate_present: bool
    admission_sha256: str | None
    candidate_run_id: str | None
    candidate_evidence_ids: tuple[str, ...]

    def as_dict(self) -> dict:
        return asdict(self)


@dataclass(frozen=True)
class FutureSecurityEvidenceFreshnessCoverage:
    schema_version: str
    client_id: str
    current_twin_id: str
    current_twin_version: int
    twin_id: str
    twin_version: int
    changeset_id: str
    request_sha256: str
    constraints_sha256: str
    items: tuple[FutureSecurityEvidenceFreshnessCoverageItem, ...]
    total_gap_count: int
    covered_gap_count: int
    missing_gap_count: int
    all_gaps_have_fresh_candidates: bool
    coverage_sha256: str
    evidence_sufficiency_evaluated: bool = False
    gap_closed: bool = False
    classification_selected: bool = False
    transition_resolution_created: bool = False
    collection_authorized: bool = False
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


def _coverage_digest(
    *,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    items: tuple[FutureSecurityEvidenceFreshnessCoverageItem, ...],
) -> str:
    covered = sum(1 for item in items if item.fresh_candidate_present)
    total = len(items)
    payload = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "client_id": constraints.client_id,
        "current_twin_id": constraints.current_twin_id,
        "current_twin_version": constraints.current_twin_version,
        "twin_id": constraints.twin_id,
        "twin_version": constraints.twin_version,
        "changeset_id": constraints.changeset_id,
        "request_sha256": constraints.request_sha256,
        "constraints_sha256": constraints.constraints_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "source_resolution_id": item.source_resolution_id,
                "fresh_candidate_present": item.fresh_candidate_present,
                "admission_sha256": item.admission_sha256,
                "candidate_run_id": item.candidate_run_id,
                "candidate_evidence_ids": list(item.candidate_evidence_ids),
            }
            for item in items
        ],
        "total_gap_count": total,
        "covered_gap_count": covered,
        "missing_gap_count": total - covered,
        "all_gaps_have_fresh_candidates": bool(total) and covered == total,
        "evidence_sufficiency_evaluated": False,
        "gap_closed": False,
        "classification_selected": False,
        "transition_resolution_created": False,
        "collection_authorized": False,
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


def build_future_security_evidence_freshness_coverage(
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    admissions: tuple[FutureSecurityEvidenceFreshnessAdmission, ...],
    candidate_contexts: tuple[RunContext, ...],
    *,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessCoverage:
    """Report freshness coverage for every unresolved constraint item."""

    validate_future_security_evidence_freshness_constraints(
        constraints,
        request,
        plan,
        report,
        preview,
        proposal,
        resolutions,
        source_contexts,
        state,
    )
    if not isinstance(admissions, tuple):
        raise ValueError("freshness coverage admissions must be an immutable tuple")
    if not isinstance(candidate_contexts, tuple):
        raise ValueError("freshness coverage candidate_contexts must be an immutable tuple")

    admission_by_resolution: dict[str, FutureSecurityEvidenceFreshnessAdmission] = {}
    for admission in admissions:
        if not isinstance(admission, FutureSecurityEvidenceFreshnessAdmission):
            raise ValueError("freshness coverage admission has an invalid type")
        if admission.source_resolution_id in admission_by_resolution:
            raise ValueError("freshness coverage has duplicate source admissions")
        admission_by_resolution[admission.source_resolution_id] = admission

    contexts_by_run: dict[str, RunContext] = {}
    for context in candidate_contexts:
        if not isinstance(context, RunContext):
            raise ValueError("freshness coverage candidate context has an invalid type")
        if context.run_id in contexts_by_run:
            raise ValueError("freshness coverage has duplicate candidate run contexts")
        contexts_by_run[context.run_id] = context

    known_resolution_ids = {
        item.source_resolution_id for item in constraints.items
    }
    if set(admission_by_resolution) - known_resolution_ids:
        raise ValueError("freshness coverage contains a foreign source admission")

    referenced_run_ids: set[str] = set()
    for admission in admissions:
        candidate_context = contexts_by_run.get(admission.candidate_run_id)
        if candidate_context is None:
            raise ValueError("freshness coverage candidate RunContext is missing")
        referenced_run_ids.add(candidate_context.run_id)
        validate_future_security_evidence_freshness_admission(
            admission,
            constraints,
            candidate_context=candidate_context,
            request=request,
            plan=plan,
            report=report,
            preview=preview,
            proposal=proposal,
            resolutions=resolutions,
            source_contexts=source_contexts,
            state=state,
        )

    if set(contexts_by_run) != referenced_run_ids:
        raise ValueError("freshness coverage has unreferenced candidate RunContexts")

    coverage_items: list[FutureSecurityEvidenceFreshnessCoverageItem] = []
    for constraint_item in constraints.items:
        admission = admission_by_resolution.get(constraint_item.source_resolution_id)
        if admission is None:
            coverage_items.append(
                FutureSecurityEvidenceFreshnessCoverageItem(
                    change_node_id=constraint_item.change_node_id,
                    subject_node_id=constraint_item.subject_node_id,
                    source_resolution_id=constraint_item.source_resolution_id,
                    fresh_candidate_present=False,
                    admission_sha256=None,
                    candidate_run_id=None,
                    candidate_evidence_ids=(),
                )
            )
            continue

        if (
            admission.change_node_id != constraint_item.change_node_id
            or admission.subject_node_id != constraint_item.subject_node_id
        ):
            raise ValueError("freshness coverage admission identity mismatch")
        coverage_items.append(
            FutureSecurityEvidenceFreshnessCoverageItem(
                change_node_id=constraint_item.change_node_id,
                subject_node_id=constraint_item.subject_node_id,
                source_resolution_id=constraint_item.source_resolution_id,
                fresh_candidate_present=True,
                admission_sha256=admission.admission_sha256,
                candidate_run_id=admission.candidate_run_id,
                candidate_evidence_ids=admission.candidate_evidence_ids,
            )
        )

    items = tuple(
        sorted(
            coverage_items,
            key=lambda item: (
                item.change_node_id,
                item.subject_node_id,
                item.source_resolution_id,
            ),
        )
    )
    total_gap_count = len(items)
    if total_gap_count != constraints.freshness_item_count:
        raise ValueError("freshness coverage gap count does not match constraints")
    covered_gap_count = sum(1 for item in items if item.fresh_candidate_present)
    missing_gap_count = total_gap_count - covered_gap_count
    all_gaps_have_fresh_candidates = (
        total_gap_count > 0 and covered_gap_count == total_gap_count
    )
    coverage_sha256 = _coverage_digest(
        constraints=constraints,
        items=items,
    )
    return FutureSecurityEvidenceFreshnessCoverage(
        schema_version=COVERAGE_SCHEMA_VERSION,
        client_id=constraints.client_id,
        current_twin_id=constraints.current_twin_id,
        current_twin_version=constraints.current_twin_version,
        twin_id=constraints.twin_id,
        twin_version=constraints.twin_version,
        changeset_id=constraints.changeset_id,
        request_sha256=constraints.request_sha256,
        constraints_sha256=constraints.constraints_sha256,
        items=items,
        total_gap_count=total_gap_count,
        covered_gap_count=covered_gap_count,
        missing_gap_count=missing_gap_count,
        all_gaps_have_fresh_candidates=all_gaps_have_fresh_candidates,
        coverage_sha256=coverage_sha256,
    )


def validate_future_security_evidence_freshness_coverage(
    coverage: FutureSecurityEvidenceFreshnessCoverage,
    constraints: FutureSecurityEvidenceFreshnessConstraints,
    admissions: tuple[FutureSecurityEvidenceFreshnessAdmission, ...],
    candidate_contexts: tuple[RunContext, ...],
    *,
    request: FutureSecurityEvidenceCollectionRequest,
    plan: FutureSecurityRemediationRetestPlan,
    report: FutureAttackPathSecurityDeltaReport,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    source_contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityEvidenceFreshnessCoverage:
    """Rebuild persisted freshness coverage against live admissions and evidence."""

    if not isinstance(coverage, FutureSecurityEvidenceFreshnessCoverage):
        raise ValueError("coverage must be FutureSecurityEvidenceFreshnessCoverage")
    rebuilt = build_future_security_evidence_freshness_coverage(
        constraints,
        admissions,
        candidate_contexts,
        request=request,
        plan=plan,
        report=report,
        preview=preview,
        proposal=proposal,
        resolutions=resolutions,
        source_contexts=source_contexts,
        state=state,
    )
    if rebuilt != coverage:
        raise ValueError("evidence freshness coverage does not match live validated state")
    return rebuilt


_COVERAGE_KEYS = {
    "schema_version",
    "client_id",
    "current_twin_id",
    "current_twin_version",
    "twin_id",
    "twin_version",
    "changeset_id",
    "request_sha256",
    "constraints_sha256",
    "items",
    "total_gap_count",
    "covered_gap_count",
    "missing_gap_count",
    "all_gaps_have_fresh_candidates",
    "coverage_sha256",
    "evidence_sufficiency_evaluated",
    "gap_closed",
    "classification_selected",
    "transition_resolution_created",
    "collection_authorized",
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

_COVERAGE_ITEM_KEYS = {
    "change_node_id",
    "subject_node_id",
    "source_resolution_id",
    "fresh_candidate_present",
    "admission_sha256",
    "candidate_run_id",
    "candidate_evidence_ids",
}


def _strict_identifier(value: object, *, name: str) -> str:
    if not isinstance(value, str) or not value or value != value.strip():
        raise ValueError(f"{name} must be a canonical non-empty string")
    if len(value) > 256 or any(ord(char) < 32 or ord(char) == 127 for char in value):
        raise ValueError(f"{name} is not canonical")
    return value


def _strict_sha256(value: object, *, name: str) -> str:
    if (
        not isinstance(value, str)
        or len(value) != 64
        or any(char not in "0123456789abcdef" for char in value)
    ):
        raise ValueError(f"{name} must be a canonical lowercase SHA-256")
    return value


def _strict_id_list(
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


def _coverage_digest_from_coverage(
    coverage: FutureSecurityEvidenceFreshnessCoverage,
) -> str:
    payload = {
        "schema_version": COVERAGE_SCHEMA_VERSION,
        "client_id": coverage.client_id,
        "current_twin_id": coverage.current_twin_id,
        "current_twin_version": coverage.current_twin_version,
        "twin_id": coverage.twin_id,
        "twin_version": coverage.twin_version,
        "changeset_id": coverage.changeset_id,
        "request_sha256": coverage.request_sha256,
        "constraints_sha256": coverage.constraints_sha256,
        "items": [
            {
                "change_node_id": item.change_node_id,
                "subject_node_id": item.subject_node_id,
                "source_resolution_id": item.source_resolution_id,
                "fresh_candidate_present": item.fresh_candidate_present,
                "admission_sha256": item.admission_sha256,
                "candidate_run_id": item.candidate_run_id,
                "candidate_evidence_ids": list(item.candidate_evidence_ids),
            }
            for item in coverage.items
        ],
        "total_gap_count": len(coverage.items),
        "covered_gap_count": sum(
            1 for item in coverage.items if item.fresh_candidate_present
        ),
        "missing_gap_count": sum(
            1 for item in coverage.items if not item.fresh_candidate_present
        ),
        "all_gaps_have_fresh_candidates": bool(coverage.items)
        and all(item.fresh_candidate_present for item in coverage.items),
        "evidence_sufficiency_evaluated": False,
        "gap_closed": False,
        "classification_selected": False,
        "transition_resolution_created": False,
        "collection_authorized": False,
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


def future_security_evidence_freshness_coverage_from_dict(
    payload: dict,
) -> FutureSecurityEvidenceFreshnessCoverage:
    """Parse exact freshness coverage JSON and verify all derived semantics."""

    if not isinstance(payload, dict):
        raise ValueError("evidence freshness coverage payload must be an object")
    if set(payload) != _COVERAGE_KEYS:
        raise ValueError("evidence freshness coverage payload schema mismatch")
    if payload["schema_version"] != COVERAGE_SCHEMA_VERSION:
        raise ValueError("evidence freshness coverage schema version mismatch")

    for field in (
        "client_id",
        "current_twin_id",
        "twin_id",
        "changeset_id",
    ):
        _strict_identifier(payload[field], name=f"coverage {field}")
    for field in ("request_sha256", "constraints_sha256", "coverage_sha256"):
        _strict_sha256(payload[field], name=f"coverage {field}")

    for field in (
        "current_twin_version",
        "twin_version",
        "total_gap_count",
        "covered_gap_count",
        "missing_gap_count",
    ):
        value = payload[field]
        if not isinstance(value, int) or isinstance(value, bool) or value < 0:
            raise ValueError(f"coverage {field} must be a non-negative integer")

    if not isinstance(payload["all_gaps_have_fresh_candidates"], bool):
        raise ValueError("coverage all_gaps_have_fresh_candidates must be boolean")

    for field in (
        "evidence_sufficiency_evaluated",
        "gap_closed",
        "classification_selected",
        "transition_resolution_created",
        "collection_authorized",
        "tool_call_created",
        "execution_allowed",
        "target_interaction_allowed",
        "remediation_authoring_allowed",
        "future_state_retest_allowed",
        "deployment_authorized",
        "attack_path_mutation_allowed",
    ):
        if payload[field] is not False:
            raise ValueError(f"coverage safety flag {field} must remain false")
    if payload["future_semantics"] != "unresolved":
        raise ValueError("coverage future semantics must remain unresolved")
    if payload["security_verdict"] != "not_evaluated":
        raise ValueError("coverage must not claim a security verdict")

    raw_items = payload["items"]
    if not isinstance(raw_items, list) or not raw_items:
        raise ValueError("evidence freshness coverage items must be non-empty")

    items: list[FutureSecurityEvidenceFreshnessCoverageItem] = []
    for raw_item in raw_items:
        if not isinstance(raw_item, dict) or set(raw_item) != _COVERAGE_ITEM_KEYS:
            raise ValueError("evidence freshness coverage item schema mismatch")
        change_node_id = _strict_identifier(
            raw_item["change_node_id"],
            name="coverage change_node_id",
        )
        subject_node_id = _strict_identifier(
            raw_item["subject_node_id"],
            name="coverage subject_node_id",
        )
        source_resolution_id = _strict_identifier(
            raw_item["source_resolution_id"],
            name="coverage source_resolution_id",
        )
        present = raw_item["fresh_candidate_present"]
        if not isinstance(present, bool):
            raise ValueError("coverage fresh_candidate_present must be boolean")

        if present:
            admission_sha256 = _strict_sha256(
                raw_item["admission_sha256"],
                name="coverage admission_sha256",
            )
            candidate_run_id = _strict_identifier(
                raw_item["candidate_run_id"],
                name="coverage candidate_run_id",
            )
            candidate_evidence_ids = _strict_id_list(
                raw_item["candidate_evidence_ids"],
                name="coverage candidate_evidence_ids",
                allow_empty=False,
            )
        else:
            if raw_item["admission_sha256"] is not None:
                raise ValueError(
                    "uncovered freshness item cannot carry an admission digest"
                )
            if raw_item["candidate_run_id"] is not None:
                raise ValueError(
                    "uncovered freshness item cannot carry a candidate run"
                )
            candidate_evidence_ids = _strict_id_list(
                raw_item["candidate_evidence_ids"],
                name="coverage candidate_evidence_ids",
                allow_empty=True,
            )
            if candidate_evidence_ids:
                raise ValueError(
                    "uncovered freshness item cannot carry candidate evidence"
                )
            admission_sha256 = None
            candidate_run_id = None

        items.append(
            FutureSecurityEvidenceFreshnessCoverageItem(
                change_node_id=change_node_id,
                subject_node_id=subject_node_id,
                source_resolution_id=source_resolution_id,
                fresh_candidate_present=present,
                admission_sha256=admission_sha256,
                candidate_run_id=candidate_run_id,
                candidate_evidence_ids=candidate_evidence_ids,
            )
        )

    parsed_items = tuple(items)
    identities = tuple(
        (item.change_node_id, item.subject_node_id, item.source_resolution_id)
        for item in parsed_items
    )
    if len(set(identities)) != len(identities):
        raise ValueError("coverage item identities must be unique")
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
        raise ValueError("coverage items must be canonically ordered")

    total = len(parsed_items)
    covered = sum(1 for item in parsed_items if item.fresh_candidate_present)
    missing = total - covered
    all_covered = bool(total) and covered == total
    if payload["total_gap_count"] != total:
        raise ValueError("coverage total gap count mismatch")
    if payload["covered_gap_count"] != covered:
        raise ValueError("coverage covered gap count mismatch")
    if payload["missing_gap_count"] != missing:
        raise ValueError("coverage missing gap count mismatch")
    if payload["all_gaps_have_fresh_candidates"] is not all_covered:
        raise ValueError("coverage all-gaps flag mismatch")

    coverage = FutureSecurityEvidenceFreshnessCoverage(
        schema_version=payload["schema_version"],
        client_id=payload["client_id"],
        current_twin_id=payload["current_twin_id"],
        current_twin_version=payload["current_twin_version"],
        twin_id=payload["twin_id"],
        twin_version=payload["twin_version"],
        changeset_id=payload["changeset_id"],
        request_sha256=payload["request_sha256"],
        constraints_sha256=payload["constraints_sha256"],
        items=parsed_items,
        total_gap_count=payload["total_gap_count"],
        covered_gap_count=payload["covered_gap_count"],
        missing_gap_count=payload["missing_gap_count"],
        all_gaps_have_fresh_candidates=payload[
            "all_gaps_have_fresh_candidates"
        ],
        coverage_sha256=payload["coverage_sha256"],
        evidence_sufficiency_evaluated=False,
        gap_closed=False,
        classification_selected=False,
        transition_resolution_created=False,
        collection_authorized=False,
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
    expected = _coverage_digest_from_coverage(coverage)
    if coverage.coverage_sha256 != expected:
        raise ValueError("evidence freshness coverage digest mismatch")
    return coverage
