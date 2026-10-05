"""Fail-closed ST5 CI security verdict over live-validated ST4 output.

This package evaluates Security Twin deltas for CI consumption only. It does not
merge, deploy, mutate attack paths, widen authorization, or interact with a
target. Even a PASS verdict is not deployment authorization.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
from enum import Enum
from hashlib import sha256
import json

from .ai.orchestration import RunContext
from .future_attack_path_graph_diff_policy import (
    FutureAttackPathGraphDiffPolicyDecision,
    GraphDiffPolicyDisposition,
    decide_future_attack_path_graph_diff_policy,
)
from .future_attack_path_graph_diff_preview import FutureAttackPathGraphDiffPreview
from .future_attack_path_security_delta_report import (
    FutureAttackPathSecurityDeltaReport,
    build_future_attack_path_security_delta_report,
)
from .future_attack_path_transition import FutureAttackPathTransitionProposal
from .future_attack_path_transition_resolution import (
    AttackPathTransitionClassification,
    FutureAttackPathTransitionResolution,
)
from .state import StateStore


VERDICT_SCHEMA_VERSION = "st5.ci_security_verdict.v1"


class SecurityCIVerdict(str, Enum):
    PASS = "PASS"
    PASS_WITH_WARNING = "PASS_WITH_WARNING"
    REVIEW_REQUIRED = "REVIEW_REQUIRED"
    BLOCK = "BLOCK"


_CI_CONCLUSION = {
    SecurityCIVerdict.PASS: "success",
    SecurityCIVerdict.PASS_WITH_WARNING: "neutral",
    SecurityCIVerdict.REVIEW_REQUIRED: "action_required",
    SecurityCIVerdict.BLOCK: "failure",
}

_VERDICT_RANK = {
    SecurityCIVerdict.PASS: 0,
    SecurityCIVerdict.PASS_WITH_WARNING: 1,
    SecurityCIVerdict.REVIEW_REQUIRED: 2,
    SecurityCIVerdict.BLOCK: 3,
}


@dataclass(frozen=True)
class FutureSecurityCIVerdictPolicy:
    policy_id: str
    policy_version: int
    introduced: SecurityCIVerdict = SecurityCIVerdict.BLOCK
    worsened: SecurityCIVerdict = SecurityCIVerdict.BLOCK
    improved: SecurityCIVerdict = SecurityCIVerdict.PASS
    removed: SecurityCIVerdict = SecurityCIVerdict.PASS


@dataclass(frozen=True)
class FutureSecurityCIVerdictDecision:
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
    report_sha256: str
    graph_diff_policy_decision_sha256: str
    policy_id: str
    policy_version: int
    policy_sha256: str
    verdict: SecurityCIVerdict
    ci_conclusion: str
    reason_codes: tuple[str, ...]
    contributing_classifications: tuple[AttackPathTransitionClassification, ...]
    evidence_ids: tuple[str, ...]
    capability_ids: tuple[str, ...]
    verdict_sha256: str
    deployment_authorized: bool = False
    attack_path_mutation_allowed: bool = False
    future_semantics: str = "unresolved"

    @property
    def security_verdict(self) -> str:
        return self.verdict.value

    def as_dict(self) -> dict:
        value = asdict(self)
        value["security_verdict"] = self.security_verdict
        return value

    def to_json(self) -> str:
        return json.dumps(
            self.as_dict(),
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        )


def _require_nonempty_text(name: str, value: object) -> str:
    if not isinstance(value, str) or not value:
        raise ValueError(f"{name} must be non-empty text")
    return value


def _validate_policy(policy: FutureSecurityCIVerdictPolicy) -> None:
    if not isinstance(policy, FutureSecurityCIVerdictPolicy):
        raise ValueError("policy must be a FutureSecurityCIVerdictPolicy")
    _require_nonempty_text("policy_id", policy.policy_id)
    if (
        not isinstance(policy.policy_version, int)
        or isinstance(policy.policy_version, bool)
        or policy.policy_version < 1
    ):
        raise ValueError("policy_version must be a positive integer")
    for name in ("introduced", "worsened", "improved", "removed"):
        if not isinstance(getattr(policy, name), SecurityCIVerdict):
            raise ValueError(f"{name} policy must be a SecurityCIVerdict")


def _policy_digest(policy: FutureSecurityCIVerdictPolicy) -> str:
    payload = {
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "introduced": policy.introduced.value,
        "worsened": policy.worsened.value,
        "improved": policy.improved.value,
        "removed": policy.removed.value,
        "insufficient_evidence": SecurityCIVerdict.REVIEW_REQUIRED.value,
    }
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def _policy_verdict_for_classification(
    classification: AttackPathTransitionClassification,
    policy: FutureSecurityCIVerdictPolicy,
) -> SecurityCIVerdict:
    if classification is AttackPathTransitionClassification.INSUFFICIENT_EVIDENCE:
        return SecurityCIVerdict.REVIEW_REQUIRED
    mapping = {
        AttackPathTransitionClassification.INTRODUCED: policy.introduced,
        AttackPathTransitionClassification.WORSENED: policy.worsened,
        AttackPathTransitionClassification.IMPROVED: policy.improved,
        AttackPathTransitionClassification.REMOVED: policy.removed,
    }
    try:
        return mapping[classification]
    except KeyError as exc:
        raise ValueError("unsupported ST4 attack-path classification") from exc


def _max_verdict(verdicts: tuple[SecurityCIVerdict, ...]) -> SecurityCIVerdict:
    if not verdicts:
        raise ValueError("CI verdict requires at least one security delta item")
    return max(verdicts, key=_VERDICT_RANK.__getitem__)


def _validate_st4_lineage(
    *,
    report: FutureAttackPathSecurityDeltaReport,
    decision: FutureAttackPathGraphDiffPolicyDecision,
    preview: FutureAttackPathGraphDiffPreview,
) -> None:
    fields = (
        "client_id",
        "current_twin_id",
        "current_twin_version",
        "twin_id",
        "twin_version",
        "changeset_id",
        "proposal_sha256",
        "impact_analysis_sha256",
        "preview_sha256",
    )
    for field in fields:
        expected = getattr(preview, field)
        if getattr(report, field) != expected or getattr(decision, field) != expected:
            raise ValueError(f"ST4 lineage mismatch for {field}")

    if not report.report_complete:
        raise ValueError("CI verdict requires a complete ST4 security delta report")
    if report.attack_path_mutation_allowed or decision.attack_path_mutation_allowed:
        raise ValueError("ST4 handoff must not allow attack-path mutation")
    if report.future_semantics != "unresolved" or decision.future_semantics != "unresolved":
        raise ValueError("ST4 handoff future_semantics must remain unresolved")
    if report.security_verdict != "not_evaluated":
        raise ValueError("ST4 security delta report must not precompute a verdict")
    if decision.security_verdict != "not_evaluated":
        raise ValueError("ST4 graph-diff policy must not precompute a verdict")

    if report.contains_insufficient_evidence:
        if decision.disposition is not GraphDiffPolicyDisposition.REQUIRES_MORE_EVIDENCE:
            raise ValueError(
                "insufficient-evidence report requires more-evidence policy disposition"
            )
    elif decision.disposition is not GraphDiffPolicyDisposition.ELIGIBLE_FOR_OPERATOR_REVIEW:
        raise ValueError(
            "evidence-complete report requires operator-review eligible disposition"
        )


def _verdict_digest(
    *,
    report: FutureAttackPathSecurityDeltaReport,
    decision: FutureAttackPathGraphDiffPolicyDecision,
    policy: FutureSecurityCIVerdictPolicy,
    policy_sha256: str,
    verdict: SecurityCIVerdict,
    reason_codes: tuple[str, ...],
    classifications: tuple[AttackPathTransitionClassification, ...],
    evidence_ids: tuple[str, ...],
    capability_ids: tuple[str, ...],
) -> str:
    payload = {
        "schema_version": VERDICT_SCHEMA_VERSION,
        "client_id": report.client_id,
        "current_twin_id": report.current_twin_id,
        "current_twin_version": report.current_twin_version,
        "twin_id": report.twin_id,
        "twin_version": report.twin_version,
        "changeset_id": report.changeset_id,
        "proposal_sha256": report.proposal_sha256,
        "impact_analysis_sha256": report.impact_analysis_sha256,
        "preview_sha256": report.preview_sha256,
        "report_sha256": report.report_sha256,
        "graph_diff_policy_decision_sha256": decision.decision_sha256,
        "policy_id": policy.policy_id,
        "policy_version": policy.policy_version,
        "policy_sha256": policy_sha256,
        "verdict": verdict.value,
        "ci_conclusion": _CI_CONCLUSION[verdict],
        "reason_codes": list(reason_codes),
        "contributing_classifications": [
            classification.value for classification in classifications
        ],
        "evidence_ids": list(evidence_ids),
        "capability_ids": list(capability_ids),
        "deployment_authorized": False,
        "attack_path_mutation_allowed": False,
        "future_semantics": "unresolved",
    }
    return sha256(
        json.dumps(
            payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=True,
        ).encode("utf-8")
    ).hexdigest()


def decide_future_security_ci_verdict(
    report: FutureAttackPathSecurityDeltaReport,
    decision: FutureAttackPathGraphDiffPolicyDecision,
    policy: FutureSecurityCIVerdictPolicy,
    preview: FutureAttackPathGraphDiffPreview,
    proposal: FutureAttackPathTransitionProposal,
    resolutions: tuple[FutureAttackPathTransitionResolution, ...],
    contexts: tuple[RunContext, ...],
    state: StateStore,
) -> FutureSecurityCIVerdictDecision:
    """Return a deterministic CI security verdict after independent ST4 revalidation."""

    _validate_policy(policy)

    live_report = build_future_attack_path_security_delta_report(
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if report != live_report:
        raise ValueError(
            "security delta report is stale, tampered, cross-tenant, or lineage-drifted"
        )

    live_decision = decide_future_attack_path_graph_diff_policy(
        preview,
        proposal,
        resolutions,
        contexts,
        state,
    )
    if decision != live_decision:
        raise ValueError(
            "graph diff policy decision is stale, tampered, cross-tenant, or lineage-drifted"
        )

    _validate_st4_lineage(report=report, decision=decision, preview=preview)

    classifications = tuple(
        sorted(
            {item.classification for item in report.items},
            key=lambda classification: classification.value,
        )
    )
    item_verdicts = tuple(
        _policy_verdict_for_classification(item.classification, policy)
        for item in report.items
    )
    verdict = _max_verdict(item_verdicts)

    reason_codes = {
        f"policy:{item.classification.value}:{item_verdict.value.lower()}"
        for item, item_verdict in zip(report.items, item_verdicts)
    }
    if report.contains_insufficient_evidence:
        reason_codes.add("insufficient_evidence")
        if _VERDICT_RANK[verdict] < _VERDICT_RANK[SecurityCIVerdict.REVIEW_REQUIRED]:
            verdict = SecurityCIVerdict.REVIEW_REQUIRED

    ordered_reasons = tuple(sorted(reason_codes))
    evidence_ids = tuple(
        sorted({evidence_id for item in report.items for evidence_id in item.evidence_ids})
    )
    capability_ids = tuple(
        sorted(
            {
                capability_id
                for item in report.items
                for capability_id in item.capability_ids
            }
        )
    )
    policy_sha256 = _policy_digest(policy)
    verdict_sha256 = _verdict_digest(
        report=report,
        decision=decision,
        policy=policy,
        policy_sha256=policy_sha256,
        verdict=verdict,
        reason_codes=ordered_reasons,
        classifications=classifications,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
    )

    return FutureSecurityCIVerdictDecision(
        schema_version=VERDICT_SCHEMA_VERSION,
        client_id=report.client_id,
        current_twin_id=report.current_twin_id,
        current_twin_version=report.current_twin_version,
        twin_id=report.twin_id,
        twin_version=report.twin_version,
        changeset_id=report.changeset_id,
        proposal_sha256=report.proposal_sha256,
        impact_analysis_sha256=report.impact_analysis_sha256,
        preview_sha256=report.preview_sha256,
        report_sha256=report.report_sha256,
        graph_diff_policy_decision_sha256=decision.decision_sha256,
        policy_id=policy.policy_id,
        policy_version=policy.policy_version,
        policy_sha256=policy_sha256,
        verdict=verdict,
        ci_conclusion=_CI_CONCLUSION[verdict],
        reason_codes=ordered_reasons,
        contributing_classifications=classifications,
        evidence_ids=evidence_ids,
        capability_ids=capability_ids,
        verdict_sha256=verdict_sha256,
    )
