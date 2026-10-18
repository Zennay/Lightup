"""Offline scored lab cohort review: 2 REVIEW_ONLY / 3 HOLD, NEVER a grant.

Usage: python scripts/assessment_runtime_ground_truth_cohort_cli_1513.py old.json new.json
Only two explicitly supplied local files are read, never a network endpoint.
"""
from __future__ import annotations

import json
import sys

from assessment_runtime_compare_cli_1513 import _parse_case_document, _read_json
from assessment_runtime_compare_cohort_cli_1513 import _display, COHORT_BYTES
from lightup.ai.assessment_runtime_cohort_1513 import LabCohortComparison
from lightup.ai.assessment_runtime_ground_truth_cohort_1513 import compare_ground_truthed_lab_cohorts
from lightup.labeval import ExpectedFinding, LabScenario

SCENARIO_KEYS = frozenset(('scenario_id', 'name', 'description', 'targets', 'endpoints', 'expected_findings'))
FINDING_KEYS = frozenset(('identifier', 'title', 'capability_id', 'severity'))


def _parse_scored_case(packet):
    if type(packet) is not dict or set(packet) != {'scenario', 'record', 'context'}:
        raise ValueError('invalid scored case schema')
    data = packet['scenario']
    if type(data) is not dict or set(data) != SCENARIO_KEYS:
        raise ValueError('invalid scenario schema')
    raw_targets, raw_endpoints, findings = (
        data['targets'], data['endpoints'], data['expected_findings'],
    )
    if (type(raw_targets) is not list or not 1 <= len(raw_targets) <= 64
            or type(raw_endpoints) is not list or len(raw_targets) != len(raw_endpoints)
            or type(findings) is not list or len(findings) > 1024):
        raise ValueError('invalid scenario lists')
    if any(type(target) is not str for target in raw_targets + raw_endpoints):
        raise ValueError('invalid target types')
    if any(type(item) is not dict or set(item) != FINDING_KEYS
           or any(type(value) is not str for value in item.values()) for item in findings):
        raise ValueError('invalid finding types')
    # Construction applies LightUp's existing *local* lab-only target policy;
    # the post-construction review independently checks every asset binding.
    scenario = LabScenario(
        scenario_id=data['scenario_id'], name=data['name'],
        description=data['description'], targets=tuple(raw_targets),
        expected_findings=tuple(ExpectedFinding(**item) for item in findings),
    )
    if scenario.endpoints != tuple(raw_endpoints):
        raise ValueError('mismatched original endpoints')
    record, context = _parse_case_document({
        'record': packet['record'], 'context': packet['context'],
    })
    return scenario, record, context


def _load(path):
    packets = _read_json(path, maximum_bytes=COHORT_BYTES)
    if type(packets) is not list or not 1 <= len(packets) <= 64:
        raise ValueError('invalid scored cohort shape')
    return tuple(_parse_scored_case(packet) for packet in packets)


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    review = LabCohortComparison('HOLD')
    if len(args) == 2:
        try:
            review = compare_ground_truthed_lab_cohorts(_load(args[0]), _load(args[1]))
        except (OSError, ValueError, KeyError, TypeError, OverflowError,
                UnicodeError, RecursionError, PermissionError):
            pass
    print(json.dumps(_display(review), sort_keys=True, separators=(',', ':')))
    return 2 if review.status == 'REVIEW_ONLY' else 3


if __name__ == '__main__':
    raise SystemExit(main())
