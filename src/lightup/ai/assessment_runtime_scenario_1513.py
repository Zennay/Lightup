"""Opt-in ground-truth scenario fence for offline assessment comparisons (#1513).

Scenario IDs alone do not prove that targets and expected findings stayed
unchanged between two lab benchmark runs. This pure adapter fails closed if
the entire caller-provided scenario contract differs. It grants no authority.
"""
from __future__ import annotations

from .assessment_runtime_diff_1513 import LabComparison, compare_lab_evaluations
from .orchestration import RunContext
from ..labeval import EvaluationRecord, ExpectedFinding, LabScenario


def _valid_text(value: object, limit: int) -> bool:
    return (
        type(value) is str
        and 0 < len(value) <= limit
        and value == value.strip()
        and all(32 <= ord(ch) <= 126 for ch in value)
    )


def _valid_scenario(value: object) -> bool:
    if type(value) is not LabScenario:
        return False
    if not _valid_text(value.scenario_id, 256) or not _valid_text(value.name, 256):
        return False
    if type(value.description) is not str or len(value.description) > 8_192:
        return False
    if (type(value.targets) is not tuple or not 1 <= len(value.targets) <= 64
            or type(value.endpoints) is not tuple
            or len(value.endpoints) != len(value.targets)):
        return False
    if not all(_valid_text(target, 2_048) for target in value.targets):
        return False
    if not all(_valid_text(endpoint, 2_048) for endpoint in value.endpoints):
        return False
    ground_truth = value.expected_findings
    if type(ground_truth) is not tuple or len(ground_truth) > 1_024:
        return False  # None is an unscored run, not verified ground truth.
    seen: set[str] = set()
    for finding in ground_truth:
        if type(finding) is not ExpectedFinding:
            return False
        if not all(_valid_text(getattr(finding, key), 256) for key in (
            "identifier", "title", "capability_id", "severity"
        )):
            return False
        if finding.identifier in seen:
            return False
        seen.add(finding.identifier)
    return True


def compare_ground_truthed_lab_evaluations(
    baseline_scenario: LabScenario,
    candidate_scenario: LabScenario,
    baseline: EvaluationRecord,
    candidate: EvaluationRecord,
    baseline_context: RunContext,
    candidate_context: RunContext,
) -> LabComparison:
    """Compare only identical, explicitly scored, lab-only scenario contracts.

    A matching copied scenario is not authenticated provenance or human
    consent. Both contexts and both scenarios are caller-supplied. A changed
    target/endpoints, expected finding, description, name or scenario identity
    must not silently pass as a like-for-like benchmark.
    """
    if (
        not _valid_scenario(baseline_scenario)
        or not _valid_scenario(candidate_scenario)
        or baseline_scenario != candidate_scenario
        or baseline_scenario.scenario_id != getattr(baseline, "scenario_id", None)
        or candidate_scenario.scenario_id != getattr(candidate, "scenario_id", None)
    ):
        return LabComparison("HOLD")  # No echo of targets or ground truth.
    return compare_lab_evaluations(
        baseline, candidate, baseline_context, candidate_context,
    )
