"""Atomic offline review of scored lab scenario cohorts; never authorization."""
from __future__ import annotations

from .assessment_runtime_cohort_1513 import LabCohortComparison
from .assessment_runtime_diff_1513 import _valid_record
from .assessment_runtime_scenario_1513 import (
    _valid_scenario, compare_ground_truthed_lab_evaluations,
)
from .orchestration import RunContext
from ..labeval import EvaluationRecord, LabScenario


def _index_cases(entries: object) -> dict[str, tuple[LabScenario, EvaluationRecord, RunContext]] | None:
    if type(entries) is not tuple or not 1 <= len(entries) <= 64:
        return None
    indexed = {}
    for entry in entries:
        if type(entry) is not tuple or len(entry) != 3:
            return None
        scenario, record, context = entry
        if (not _valid_scenario(scenario) or not _valid_record(record, context)
                or scenario.scenario_id != record.scenario_id
                or scenario.scenario_id in indexed):
            return None
        indexed[scenario.scenario_id] = entry
    return indexed


def compare_ground_truthed_lab_cohorts(
    baselines: tuple[tuple[LabScenario, EvaluationRecord, RunContext], ...],
    candidates: tuple[tuple[LabScenario, EvaluationRecord, RunContext], ...],
) -> LabCohortComparison:
    """Fail closed atomically on scenario/ground-truth drift or invalid inputs.

    Neither side's caller-provided lab provenance is authenticated. Even a
    REVIEW_ONLY receipt cannot grant consent, handler execution or release.
    """
    before, after = _index_cases(baselines), _index_cases(candidates)
    if before is None or after is None or before.keys() != after.keys():
        return LabCohortComparison('HOLD')
    comparisons = []
    regressions = []
    for key in sorted(before):
        old_s, old_r, old_c = before[key]
        new_s, new_r, new_c = after[key]
        result = compare_ground_truthed_lab_evaluations(
            old_s, new_s, old_r, new_r, old_c, new_c,
        )
        if not result.changes:
            return LabCohortComparison('HOLD')  # never leak partial results
        comparisons.append((key, result))
        if result.regressions:
            regressions.append(key)
    return LabCohortComparison(
        'HOLD' if regressions else 'REVIEW_ONLY',
        tuple(comparisons), tuple(regressions),
    )
