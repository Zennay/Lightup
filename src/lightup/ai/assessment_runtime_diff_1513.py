"""Offline laboratory benchmark comparison for assessment-runtime (#1513).

This is a pure read-only diagnostic over already-recorded lab measurements.
It never authorizes an assessment, probes assets, or dispatches a tool.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timedelta
from math import isfinite

from .orchestration import RunContext
from ..engagements import AssessmentMode, RiskLevel
from ..labeval import EvaluationMetrics, EvaluationRecord

_COUNTERS = (
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "scope_violations",
    "policy_violations", "human_interventions", "tool_calls",
)
_SCORES = (
    "evidence_quality", "reproducibility", "remediation_quality",
    "retest_correctness",
)
_COSTS = ("runtime_seconds", "compute_cost_usd")
# All metrics are reported; only unambiguously worse outcomes hold the review.
_HIGHER_IS_BETTER = frozenset(("valid_findings", "coverage_assessed", *_SCORES))
_LOWER_IS_BETTER = frozenset((
    "invalid_findings", "missed_findings", "scope_violations", "policy_violations",
))
_MAX_COUNTER = 1_000_000_000


@dataclass(frozen=True)
class MetricChange:
    name: str
    baseline: int | float
    candidate: int | float
    delta: int | float
    regression: bool


@dataclass(frozen=True)
class LabComparison:
    status: str
    changes: tuple[MetricChange, ...] = ()
    regressions: tuple[str, ...] = ()
    # No constructor parameter can turn a diagnostic into security authority.
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _valid_label(value: object) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= 256
        and value == value.strip()
        and all(32 <= ord(ch) <= 126 for ch in value)
    )


def _valid_utc_instant(value: object) -> bool:
    """Reject naive, non-UTC, subclassed or malformed timestamps."""
    if type(value) is datetime:
        return value.tzinfo is not None and value.utcoffset() == timedelta(0)
    if not _valid_label(value) or "T" not in value:
        return False
    try:
        parsed = datetime.fromisoformat(value)
    except ValueError:
        return False
    return parsed.tzinfo is not None and parsed.utcoffset() == timedelta(0)


def _valid_metrics(value: object) -> bool:
    # Independent of the original EvaluationMetrics.validate() owner (#834).
    if type(value) is not EvaluationMetrics:
        return False
    for name in _COUNTERS:
        number = getattr(value, name)
        if type(number) is not int or not 0 <= number <= _MAX_COUNTER:
            return False
    for name in _SCORES:
        number = getattr(value, name)
        if (type(number) not in (int, float) or not 0 <= number <= 1
                or (type(number) is float and not isfinite(number))):
            return False
    for name in _COSTS:
        number = getattr(value, name)
        if (type(number) not in (int, float) or number < 0
                or (type(number) is int and number > 1_000_000_000_000)
                or (type(number) is float and not isfinite(number))):
            return False
    return True


def _valid_record(record: object, context: object) -> bool:
    if type(record) is not EvaluationRecord or type(context) is not RunContext:
        return False
    if not all(_valid_label(getattr(record, key)) for key in (
        "record_id", "scenario_id", "run_id", "engine_version",
    )):
        return False
    if type(record.notes) is not str or type(record.created_at) is not str or not _valid_utc_instant(record.created_at):
        return False
    if type(record.model_bindings) is not tuple or len(record.model_bindings) > 64:
        return False
    if not all(
        type(pair) is tuple and len(pair) == 2
        and _valid_label(pair[0]) and _valid_label(pair[1])
        for pair in record.model_bindings
    ):
        return False
    if (
        type(context.is_lab) is not bool or context.is_lab is not True
        or context.mode is not AssessmentMode.LAB_AUTONOMOUS
        or context.approved_risk is not RiskLevel.DESTRUCTIVE_LAB_ONLY
        or context.authorization is not None
        or not _valid_label(context.run_id)
        or not _valid_label(context.engagement_id)
        or not _valid_label(context.client_id)
        or type(context.created_at) is not datetime
        or not _valid_utc_instant(context.created_at)
        or context.run_id != record.run_id
        or context.engagement_id != record.scenario_id
    ):
        return False
    return _valid_metrics(record.metrics)


def compare_lab_evaluations(
    baseline: EvaluationRecord,
    candidate: EvaluationRecord,
    baseline_context: RunContext,
    candidate_context: RunContext,
) -> LabComparison:
    """Compare two already-finished lab evaluations, with no side effects.

    HOLD is deliberately generic for rejected inputs (no echo). For accepted
    inputs, HOLD includes named degradations. REVIEW_ONLY still provides
    *zero* authority: this is not consent, provenance, or release clearance.
    Both records and contexts are supplied by the caller, not authenticated.
    """
    if (
        not _valid_record(baseline, baseline_context)
        or not _valid_record(candidate, candidate_context)
        or baseline.scenario_id != candidate.scenario_id
    ):
        return LabComparison("HOLD")

    changes: list[MetricChange] = []
    regressions: list[str] = []
    for name in (*_COUNTERS, *_SCORES, *_COSTS):
        old = getattr(baseline.metrics, name)
        new = getattr(candidate.metrics, name)
        delta = new - old
        bad = (
            (name in _HIGHER_IS_BETTER and new < old)
            or (name in _LOWER_IS_BETTER and new > old)
        )
        changes.append(MetricChange(name, old, new, delta, bad))
        if bad:
            regressions.append(name)
    return LabComparison(
        "HOLD" if regressions else "REVIEW_ONLY",
        tuple(changes),
        tuple(regressions),
    )
