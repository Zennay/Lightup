"""Atomic, read-only multi-scenario lab benchmark comparison (#1513)."""
from __future__ import annotations

from dataclasses import dataclass, field

from .assessment_runtime_diff_1513 import (
    LabComparison, _valid_record, compare_lab_evaluations,
)
from .orchestration import RunContext
from ..labeval import EvaluationRecord


@dataclass(frozen=True)
class LabCohortComparison:
    status: str
    comparisons: tuple[tuple[str, LabComparison], ...] = ()
    regressed_scenarios: tuple[str, ...] = ()
    authorized: bool = field(default=False, init=False)
    consent_verified: bool = field(default=False, init=False)
    dispatch_allowed: bool = field(default=False, init=False)
    release_allowed: bool = field(default=False, init=False)


def _index(entries: object) -> dict[str, tuple[EvaluationRecord, RunContext]] | None:
    if type(entries) is not tuple or not 1 <= len(entries) <= 64:
        return None
    result: dict[str, tuple[EvaluationRecord, RunContext]] = {}
    for pair in entries:
        if type(pair) is not tuple or len(pair) != 2:
            return None
        record, context = pair
        if not _valid_record(record, context) or record.scenario_id in result:
            return None
        result[record.scenario_id] = (record, context)
    return result


def compare_lab_cohorts(
    baselines: tuple[tuple[EvaluationRecord, RunContext], ...],
    candidates: tuple[tuple[EvaluationRecord, RunContext], ...],
) -> LabCohortComparison:
    """Reject incomplete/duplicate scenario sets atomically; never grant authority.

    Every supplied record/context is unauthenticated. An adverse metric in even
    one scenario returns HOLD, regardless of improvements in other scenarios.
    """
    before, after = _index(baselines), _index(candidates)
    if before is None or after is None or before.keys() != after.keys():
        return LabCohortComparison("HOLD")

    compared: list[tuple[str, LabComparison]] = []
    regressions: list[str] = []
    for scenario in sorted(before):
        old, old_context = before[scenario]
        new, new_context = after[scenario]
        comparison = compare_lab_evaluations(old, new, old_context, new_context)
        if not comparison.changes:
            return LabCohortComparison("HOLD")  # no partial input echo
        compared.append((scenario, comparison))
        if comparison.regressions:
            regressions.append(scenario)
    return LabCohortComparison(
        "HOLD" if regressions else "REVIEW_ONLY", tuple(compared), tuple(regressions),
    )
