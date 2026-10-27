"""Opt-in read-only JSON lab benchmark comparison, never an execution gate.

Usage: python scripts/assessment_runtime_compare_cli_1513.py base.json next.json
Returns 2 REVIEW_ONLY or 3 HOLD; never 0. Only explicit local files are read.
"""
from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timedelta
import json
import math
from pathlib import Path
import sys

from lightup.ai.assessment_runtime_diff_1513 import compare_lab_evaluations
from lightup.ai.orchestration import RunContext
from lightup.engagements import AssessmentMode, RiskLevel
from lightup.labeval import EvaluationMetrics, EvaluationRecord

MAX_BYTES = 65_536
METRIC_FIELDS = frozenset(f.name for f in fields(EvaluationMetrics))
RECORD_FIELDS = frozenset(f.name for f in fields(EvaluationRecord))
CONTEXT_FIELDS = frozenset((
    "run_id", "client_id", "engagement_id", "mode", "approved_risk",
    "authorization", "is_lab", "created_at",
))


def _dict_no_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _reject_nonfinite(_value):
    raise ValueError("nonfinite JSON literal")


def _read_json(path, maximum_bytes=MAX_BYTES):
    with Path(path).open("rb") as handle:
        payload = handle.read(maximum_bytes + 1)
    if not payload or len(payload) > maximum_bytes:
        raise ValueError("invalid input size")
    return json.loads(
        payload.decode("utf-8"), object_pairs_hook=_dict_no_duplicates,
        parse_constant=_reject_nonfinite,
    )


def _parse_case_document(document):
    if type(document) is not dict or set(document) != {"record", "context"}:
        raise ValueError("invalid case schema")
    record_data, context_data = document["record"], document["context"]
    if type(record_data) is not dict or set(record_data) != RECORD_FIELDS:
        raise ValueError("invalid record schema")
    if type(context_data) is not dict or set(context_data) != CONTEXT_FIELDS:
        raise ValueError("invalid context schema")

    metrics_data = record_data["metrics"]
    if type(metrics_data) is not dict:
        raise ValueError("invalid metric schema")
    if set(metrics_data) not in (METRIC_FIELDS, METRIC_FIELDS | {"false_positive_rate"}):
        raise ValueError("unexpected metric fields")
    metrics = EvaluationMetrics(**{key: metrics_data[key] for key in METRIC_FIELDS})

    bindings = record_data["model_bindings"]
    if type(bindings) is not list or len(bindings) > 64:
        raise ValueError("invalid model binding shape")
    if any(type(pair) is not list or len(pair) != 2 for pair in bindings):
        raise ValueError("invalid model binding pair")

    record = EvaluationRecord(**{
        **record_data,
        "metrics": metrics,
        "model_bindings": tuple(tuple(pair) for pair in bindings),
    })
    # Serialized false_positive_rate is derived from counters, not trusted.
    if "false_positive_rate" in metrics_data:
        stated = metrics_data["false_positive_rate"]
        if type(stated) not in (int, float) or not math.isfinite(stated):
            raise ValueError("invalid derived rate")
        # Avoid computing derived metrics from producer-impossible counter types.
        if any(type(getattr(metrics, name)) is not int for name in ("valid_findings", "invalid_findings")):
            raise ValueError("invalid rate counters")
        if not math.isclose(stated, metrics.false_positive_rate, abs_tol=1e-12, rel_tol=0):
            raise ValueError("mismatched derived rate")

    if type(context_data["approved_risk"]) is not int:
        raise ValueError("risk must be an exact integer")
    if type(context_data["is_lab"]) is not bool:
        raise ValueError("lab marker must be a boolean")
    if type(context_data["created_at"]) is not str:
        raise ValueError("datetime must be a string")
    created = datetime.fromisoformat(context_data["created_at"])
    if created.utcoffset() != timedelta(0):
        raise ValueError("lab record requires UTC creation timestamp")
    context = RunContext(
        run_id=context_data["run_id"],
        client_id=context_data["client_id"],
        engagement_id=context_data["engagement_id"],
        mode=AssessmentMode(context_data["mode"]),
        approved_risk=RiskLevel(context_data["approved_risk"]),
        authorization=context_data["authorization"],
        is_lab=context_data["is_lab"],
        created_at=created,
    )
    return record, context


def _parse_case(path):
    return _parse_case_document(_read_json(path))


def _output(result):
    return {
        "status": result.status,
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "regressions": list(result.regressions),
        "changes": [
            {"name": x.name, "baseline": x.baseline, "candidate": x.candidate,
             "delta": x.delta, "regression": x.regression}
            for x in result.changes
        ],
    }


def main(argv=None):
    args = sys.argv[1:] if argv is None else argv
    result = None
    if len(args) == 2:
        try:
            baseline, baseline_context = _parse_case(args[0])
            candidate, candidate_context = _parse_case(args[1])
            result = compare_lab_evaluations(
                baseline, candidate, baseline_context, candidate_context,
            )
        except (OSError, ValueError, TypeError, KeyError, OverflowError, UnicodeError, RecursionError):
            pass
    if result is None:
        # A rejected packet never reflects caller-supplied metadata or paths.
        from lightup.ai.assessment_runtime_diff_1513 import LabComparison
        result = LabComparison("HOLD")
    print(json.dumps(_output(result), sort_keys=True, separators=(",", ":")))
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
