"""Offline, stdlib-only structural intake of LightUp HUMAN lab-review JSON.

Accepts a locally supplied review-bundle-json artifact, never an asset/target,
and never authenticates original evidence, consent or permission to dispatch.
All invalid input produces a generic HOLD with no source identifiers.
"""
from __future__ import annotations

import json
import math
import os
import stat
import sys
from decimal import Decimal, InvalidOperation

import assessment_runtime_report_html_1513 as reports


_MAX_INPUT_BYTES = 32 * 1024 * 1024
_FALSE_AUTHORITY = (
    "authorized", "consent_verified", "dispatch_allowed",
    "release_allowed", "source_provenance_authenticated",
)
_TOP_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "notice", "accepted_case_count", "metric_review", "human_actions",
    "resource_observations", *_FALSE_AUTHORITY,
))
_METRIC_FIELDS = frozenset((
    "metric", "baseline", "candidate", "delta",
    "source_regression_flag", "source_unknown_coverage",
))
_METRIC_CASE_FIELDS = frozenset((
    "scenario_ordinal", "source_status", "source_adverse_metric_count", "metrics",
))
_METRIC_SUMMARY_FIELDS = frozenset((
    "metric", "observed_case_count", "source_regression_case_count",
    "candidate_higher_case_count", "candidate_lower_case_count",
    "candidate_equal_case_count", "candidate_unknown_coverage_case_count",
))
_HUMAN_QUESTION_FIELDS = frozenset((
    "review_order", "scenario_ordinal", "human_review_group",
    "scope_policy_signal", "source_adverse_metric_count",
    "source_unknown_coverage", "matching_focus_signals",
    "suggested_human_question",
))
_RESOURCE_CASE_FIELDS = frozenset(("scenario_ordinal", "metrics"))
_RESOURCE_OBSERVATION_FIELDS = frozenset((
    "baseline", "candidate", "delta", "percent_change", "direction",
))
_RESOURCE_TOTAL_FIELDS = frozenset((
    "baseline_total", "candidate_total", "delta_total",
    "increased_cases", "decreased_cases",
))
_METRIC_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "notice", "accepted_case_count", "source_adverse_case_count",
    "source_unknown_coverage_case_count", "metric_summary", "cases",
    *_FALSE_AUTHORITY,
))
_HUMAN_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "focus_filter", "accepted_case_count", "selected_case_count",
    "excluded_case_count", "notice", "human_review_questions",
    *_FALSE_AUTHORITY,
))
_RESOURCE_REPORT_FIELDS = frozenset((
    "schema_version", "report_type", "source_status", "input_admitted",
    "readout", "accepted_case_count", "cases", "aggregate",
    *_FALSE_AUTHORITY,
))
_REPORT_TYPES = frozenset(("single_case", "cohort", "scored_cohort"))
_STATUSES = frozenset(("REVIEW_ONLY", "HOLD"))


def _pairs_without_duplicates(pairs):
    out = {}
    for key, value in pairs:
        if key in out:
            raise ValueError("duplicate JSON key")
        out[key] = value
    return out


def _reject_constant(_value):
    raise ValueError("nonfinite JSON number")


def _shape(value, fields) -> bool:
    return type(value) is dict and set(value) == fields


def _false_authority(value) -> bool:
    return all(value.get(key) is False for key in _FALSE_AUTHORITY)


def _count(value) -> bool:
    return type(value) is int and value >= 0


def _finite_number(value) -> bool:
    return type(value) in (int, float) and math.isfinite(value)


def _finite_decimal_text(value) -> bool:
    return type(value) is str and Decimal(value).is_finite()


def _admitted_components(payload) -> bool:
    metrics = payload["metric_review"]
    human = payload["human_actions"]
    resources = payload["resource_observations"]
    if not (
        _shape(metrics, _METRIC_REPORT_FIELDS)
        and _shape(human, _HUMAN_REPORT_FIELDS)
        and _shape(resources, _RESOURCE_REPORT_FIELDS)
    ):
        return False
    kind, status, count = (
        payload["report_type"], payload["source_status"],
        payload["accepted_case_count"],
    )
    for section in (metrics, human, resources):
        if (
            type(section["schema_version"]) is not int
            or section["schema_version"] != 1
            or section["report_type"] != kind
            or section["source_status"] != status
            or section["input_admitted"] is not True
            or section["accepted_case_count"] != count
            or not _false_authority(section)
        ):
            return False
    if (
        metrics["notice"] != "requires_human_review"
        or human["notice"] != "human_review_only"
        or human["focus_filter"] != "all"
        or not _count(human["selected_case_count"])
        or not _count(human["excluded_case_count"])
        or human["selected_case_count"] != count
        or human["excluded_case_count"] != 0
        or resources["readout"] != "informational_only"
        or not all(_count(v) for v in (
            metrics["source_adverse_case_count"],
            metrics["source_unknown_coverage_case_count"],
        ))
    ):
        return False

    metric_cases = metrics["cases"]
    human_questions = human["human_review_questions"]
    resource_cases = resources["cases"]
    if not (
        type(metric_cases) is list and type(human_questions) is list
        and type(resource_cases) is list and type(metrics["metric_summary"]) is list
        and len(metric_cases) == len(human_questions) == len(resource_cases) == count
        and len(metrics["metric_summary"]) == len(reports._METRIC_LABELS)
        and all(
            _shape(item, _METRIC_SUMMARY_FIELDS)
            and item["metric"] in reports._METRIC_LABELS
            and all(_count(item[key]) for key in (
                "observed_case_count", "source_regression_case_count",
                "candidate_higher_case_count", "candidate_lower_case_count",
                "candidate_equal_case_count",
                "candidate_unknown_coverage_case_count",
            ))
            for item in metrics["metric_summary"]
        )
    ):
        return False
    for case in metric_cases:
        if not (
            _shape(case, _METRIC_CASE_FIELDS)
            and _count(case["scenario_ordinal"])
            and case["source_status"] in _STATUSES
            and _count(case["source_adverse_metric_count"])
            and not (
                case["source_status"] == "REVIEW_ONLY"
                and case["source_adverse_metric_count"] > 0
            )
            and type(case["metrics"]) is list
            and len(case["metrics"]) == len(reports._METRIC_LABELS)
        ):
            return False
        for metric in case["metrics"]:
            if not (
                _shape(metric, _METRIC_FIELDS)
                and metric["metric"] in reports._METRIC_LABELS
                and all(_finite_number(metric[key]) for key in (
                    "baseline", "candidate", "delta",
                ))
                and metric["source_regression_flag"] in (True, False)
                and type(metric["source_regression_flag"]) is bool
                and type(metric["source_unknown_coverage"]) is bool
                and metric["source_unknown_coverage"] is (
                    metric["metric"] == "coverage_unknown" and metric["candidate"] > 0
                )
            ):
                return False
    for question in human_questions:
        if not (
            _shape(question, _HUMAN_QUESTION_FIELDS)
            and _count(question["review_order"])
            and _count(question["scenario_ordinal"])
            and _count(question["source_adverse_metric_count"])
            and _finite_number(question["source_unknown_coverage"])
            and type(question["scope_policy_signal"]) is bool
            and type(question["matching_focus_signals"]) is list
            and all(type(x) is str for x in question["matching_focus_signals"])
            and type(question["suggested_human_question"]) is str
        ):
            return False
    for case in resource_cases:
        if not (
            _shape(case, _RESOURCE_CASE_FIELDS)
            and _count(case["scenario_ordinal"])
            and _shape(case["metrics"], set(reports._EFFICIENCY_FIELDS))
        ):
            return False
        for metric in case["metrics"].values():
            if not (
                _shape(metric, _RESOURCE_OBSERVATION_FIELDS)
                and all(_finite_decimal_text(metric[key]) for key in (
                    "baseline", "candidate", "delta",
                ))
                and (metric["percent_change"] is None or
                     _finite_decimal_text(metric["percent_change"]))
                and Decimal(metric["baseline"]) >= 0
                and Decimal(metric["candidate"]) >= 0
                and metric["direction"] in ("increase", "decrease", "unchanged")
            ):
                return False
    if not _shape(resources["aggregate"], set(reports._EFFICIENCY_FIELDS)):
        return False
    for metric in resources["aggregate"].values():
        if not (
            _shape(metric, _RESOURCE_TOTAL_FIELDS)
            and all(_finite_decimal_text(metric[key]) for key in (
                "baseline_total", "candidate_total", "delta_total",
            ))
            and Decimal(metric["baseline_total"]) >= 0
            and Decimal(metric["candidate_total"]) >= 0
            and _count(metric["increased_cases"])
            and _count(metric["decreased_cases"])
        ):
            return False
    return (
        reports._bundle_case_alignment(metric_cases, human_questions, resource_cases)
        and reports._bundle_summary_alignment(metrics, resources)
    )


def _inspect(raw: bytes):
    payload = json.loads(
        raw.decode("utf-8"),
        object_pairs_hook=_pairs_without_duplicates,
        parse_constant=_reject_constant,
    )
    if not (
        _shape(payload, _TOP_FIELDS)
        and type(payload["schema_version"]) is int
        and payload["schema_version"] == 1
        and payload["report_type"] in _REPORT_TYPES
        and payload["source_status"] in _STATUSES
        and type(payload["input_admitted"]) is bool
        and _count(payload["accepted_case_count"])
        and _false_authority(payload)
    ):
        return None
    if payload["input_admitted"]:
        if (
            payload["notice"] != "requires_human_review"
            or payload["accepted_case_count"] <= 0
            or not _admitted_components(payload)
        ):
            return None
    elif not (
        payload["source_status"] == "HOLD"
        and payload["notice"] == "input_hold"
        and payload["accepted_case_count"] == 0
        and all(payload[name] is None for name in (
            "metric_review", "human_actions", "resource_observations",
        ))
    ):
        return None
    return payload


def inspect_review_bundle_bytes(raw: bytes) -> dict:
    """Source-minimal structural consistency readout, never provenance proof."""
    payload = None
    try:
        if type(raw) is bytes and len(raw) <= _MAX_INPUT_BYTES:
            payload = _inspect(raw)
    except (UnicodeError, ValueError, TypeError, KeyError, IndexError,
            OverflowError, AttributeError, ZeroDivisionError, InvalidOperation,
            RecursionError):
        pass
    return {
        "schema_version": 1,
        "format_consistent": payload is not None,
        "source_status": payload["source_status"] if payload is not None else "HOLD",
        "input_admitted": payload["input_admitted"] if payload is not None else False,
        "accepted_case_count": payload["accepted_case_count"] if payload is not None else 0,
        "notice": "structure_only_unauthenticated" if payload is not None else "input_hold",
        "authorized": False,
        "consent_verified": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "source_provenance_authenticated": False,
    }


def _read_private_bundle(path: str) -> bytes:
    """Pin an ordinary local file through symlink-free directory descriptors.

    A path can change between stat and open; first pin the regular inode with
    O_PATH, then open only that descriptor through procfs. Compare identity
    before and after the bounded read. Unsafe/unsupported platforms fail closed.
    """
    if type(path) is not str or not path or "\x00" in path:
        raise ValueError("invalid local review path")
    required = ("O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK", "O_PATH")
    if not all(hasattr(os, option) for option in required):
        raise ValueError("safe local review access unavailable")
    parts = (path if os.path.isabs(path) else os.path.join(os.getcwd(), path))
    components = [part for part in parts.split(os.sep) if part]
    if not components or any(part in (".", "..") for part in components):
        raise ValueError("unsafe local review path")

    directory_fd = os.open(
        os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
    )
    path_fd = None
    read_fd = None
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component, os.O_RDONLY | os.O_DIRECTORY |
                os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        name = components[-1]
        original = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(original.st_mode):
            raise ValueError("local review is not a regular file")
        path_fd = os.open(
            name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC,
            dir_fd=directory_fd,
        )
        pinned = os.fstat(path_fd)

        def identity(info):
            return (
                info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns,
            )

        if (
            not stat.S_ISREG(pinned.st_mode)
            or identity(pinned) != identity(original)
            or pinned.st_size <= 0 or pinned.st_size > _MAX_INPUT_BYTES
        ):
            raise ValueError("local review changed or exceeds cap")
        read_fd = os.open(
            f"/proc/self/fd/{path_fd}",
            os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        before = os.fstat(read_fd)
        if identity(before) != identity(pinned):
            raise ValueError("local review changed during open")

        pieces = []
        remaining = _MAX_INPUT_BYTES + 1
        while remaining:
            piece = os.read(read_fd, min(65_536, remaining))
            if not piece:
                break
            pieces.append(piece)
            remaining -= len(piece)
        data = b"".join(pieces)
        after = os.fstat(read_fd)
        pinned_after = os.fstat(path_fd)
        final_entry = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not data or len(data) > _MAX_INPUT_BYTES
            or not stat.S_ISREG(final_entry.st_mode)
            or identity(before) != identity(after)
            or identity(after) != identity(pinned_after)
            or identity(pinned_after) != identity(final_entry)
        ):
            raise ValueError("local review changed during read")
        return data
    finally:
        if read_fd is not None:
            os.close(read_fd)
        if path_fd is not None:
            os.close(path_fd)
        os.close(directory_fd)


def main(argv=None) -> int:
    args = sys.argv[1:] if argv is None else argv
    outcome = inspect_review_bundle_bytes(b"")
    if len(args) == 1:
        try:
            outcome = inspect_review_bundle_bytes(_read_private_bundle(args[0]))
        except (OSError, ValueError):
            pass
    print(json.dumps(outcome, sort_keys=True, separators=(",", ":")))
    return 2 if outcome["format_consistent"] and outcome["source_status"] == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
