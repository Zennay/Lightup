"""Opt-in read-only JSON lab benchmark comparison, never an execution gate.

Usage: python scripts/assessment_runtime_compare_cli_1513.py [--format json|text|html|csv|actions-csv|actions-html|actions-json|efficiency-json|efficiency-html|review-json|review-bundle-json|review-bundle-html] [--focus all|scope|adverse|unknown|source] base.json next.json
Focus selectors match every source signal, even under a higher-priority label.
Source focus covers every admitted unauthenticated case; focus questions match the selected signal.
Returns 2 REVIEW_ONLY or 3 HOLD; never 0. Only explicit local files are read.
"""
from __future__ import annotations

from dataclasses import fields
from datetime import datetime, timedelta
import json
import math
import os
import stat
import sys

from assessment_runtime_cli_options_1513 import parse_offline_cli_args

from assessment_runtime_report_html_1513 import (
    render_comparison_html, render_comparison_csv,
    render_human_actions_csv, render_human_actions_html,
    render_human_actions_json, render_efficiency_json, render_efficiency_html,
    render_metric_review_json, render_review_bundle_json,
    render_review_bundle_html,
)

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
    """Read one bounded ordinary file without following user path symlinks.

    Directory components are opened relative to pinned directory descriptors.
    O_PATH pins the final inode before a readable descriptor is acquired via
    /proc/self/fd, so a raced FIFO/device cannot be opened as the input. The
    final descriptor and directory entry must remain byte-source-stable.
    """
    if type(maximum_bytes) is not int or not 1 <= maximum_bytes <= 1_048_576:
        raise ValueError("invalid input size limit")
    try:
        raw_path = os.fspath(path)
    except TypeError as exc:
        raise ValueError("invalid input path") from exc
    if type(raw_path) is not str or not raw_path or "\x00" in raw_path:
        raise ValueError("invalid input path")
    if not all(hasattr(os, flag) for flag in (
        "O_NOFOLLOW", "O_DIRECTORY", "O_CLOEXEC", "O_NONBLOCK", "O_PATH"
    )):
        raise ValueError("safe file access unavailable")

    # Reject dot components instead of normalizing a path whose OS resolution
    # could traverse a symlink before processing "..".
    if os.path.isabs(raw_path):
        components = raw_path.split(os.sep)
    else:
        components = os.getcwd().split(os.sep) + raw_path.split(os.sep)
    components = [part for part in components if part]
    if not components or any(part in (".", "..") for part in components):
        raise ValueError("unsafe input path")

    directory_fd = os.open(
        os.sep, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
    )
    path_fd = None
    file_fd = None
    try:
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd

        name = components[-1]
        entry_before = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if not stat.S_ISREG(entry_before.st_mode):
            raise ValueError("input must be a regular file")

        # O_PATH does not open a FIFO/device for reading. O_NOFOLLOW pins a
        # final symlink itself, which is rejected by the regular-file check.
        path_fd = os.open(
            name, os.O_PATH | os.O_NOFOLLOW | os.O_CLOEXEC, dir_fd=directory_fd
        )
        pinned = os.fstat(path_fd)
        if not stat.S_ISREG(pinned.st_mode):
            raise ValueError("input must be a regular file")
        if (pinned.st_dev, pinned.st_ino) != (entry_before.st_dev, entry_before.st_ino):
            raise ValueError("input changed during open")
        if pinned.st_size <= 0 or pinned.st_size > maximum_bytes:
            raise ValueError("invalid input size")

        # This procfs path is constructed only from our pinned descriptor, not
        # from caller input; it opens the already-inspected inode for reading.
        file_fd = os.open(
            f"/proc/self/fd/{path_fd}", os.O_RDONLY | os.O_NONBLOCK | os.O_CLOEXEC
        )
        before = os.fstat(file_fd)
        def _identity(info):
            return (
                info.st_dev, info.st_ino, info.st_mode, info.st_size,
                info.st_mtime_ns, info.st_ctime_ns,
            )
        if not stat.S_ISREG(before.st_mode) or _identity(before) != _identity(pinned):
            raise ValueError("input changed during open")

        chunks = []
        remaining = maximum_bytes + 1
        while remaining:
            chunk = os.read(file_fd, min(65_536, remaining))
            if not chunk:
                break
            chunks.append(chunk)
            remaining -= len(chunk)
        payload = b"".join(chunks)

        after = os.fstat(file_fd)
        pinned_after = os.fstat(path_fd)
        entry_after = os.stat(name, dir_fd=directory_fd, follow_symlinks=False)
        if (
            not stat.S_ISREG(entry_after.st_mode)
            or _identity(before) != _identity(after)
            or _identity(after) != _identity(pinned_after)
            or _identity(pinned_after) != _identity(entry_after)
        ):
            raise ValueError("input changed during read")
        if not payload or len(payload) > maximum_bytes:
            raise ValueError("invalid input size")
    finally:
        if file_fd is not None:
            os.close(file_fd)
        if path_fd is not None:
            os.close(path_fd)
        os.close(directory_fd)

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


def _display_text(result) -> str:
    """Render a local human summary without source identifiers or input paths."""
    lines = [
        "LightUp assessment-runtime comparison",
        f"Status: {result.status}",
        "Input mode: explicit local files only; source provenance is unauthenticated.",
        "REVIEW_ONLY is not a pass, remediation proof, consent or release approval.",
    ]
    if result.changes:
        for change in result.changes:
            flag = "FLAGGED" if change.regression else "not flagged"
            lines.append(
                f"  {change.name}: baseline={change.baseline} "
                f"candidate={change.candidate} delta={change.delta} [{flag}]"
            )
    else:
        lines.append(
            "No metric details emitted; input admission or comparison consistency "
            "did not permit a complete comparison."
        )
    if result.regressions:
        lines.append("Source-reported adverse metrics: " + ", ".join(result.regressions))
    else:
        lines.append("Source-reported adverse metrics: none reported")
    lines.extend([
        "Authority: authorized=false; consent_verified=false; "
        "dispatch_allowed=false; release_allowed=false.",
        "No target, network, handler, grant, state write or deployment was used.",
    ])
    return "\n".join(lines)


def main(argv=None):
    output_format, focus_filter, positional, malformed = parse_offline_cli_args(
        sys.argv[1:] if argv is None else argv
    )
    result = None
    if len(positional) == 2 and not malformed:
        try:
            baseline, baseline_context = _parse_case(positional[0])
            candidate, candidate_context = _parse_case(positional[1])
            result = compare_lab_evaluations(
                baseline, candidate, baseline_context, candidate_context,
            )
        except (
            OSError, ValueError, TypeError, KeyError, OverflowError,
            UnicodeError, RecursionError,
        ):
            pass
    if result is None:
        # A rejected packet never reflects caller-supplied metadata or paths.
        from lightup.ai.assessment_runtime_diff_1513 import LabComparison
        result = LabComparison("HOLD")
    if output_format == "text":
        print(_display_text(result))
    elif output_format == "html":
        print(render_comparison_html(result), end="")
    elif output_format == "review-bundle-html":
        print(render_review_bundle_html(result), end="")
    elif output_format == "review-bundle-json":
        print(render_review_bundle_json(result), end="")
    elif output_format == "review-json":
        print(render_metric_review_json(result), end="")
    elif output_format == "efficiency-json":
        print(render_efficiency_json(result), end="")
    elif output_format == "efficiency-html":
        print(render_efficiency_html(result), end="")
    elif output_format == "actions-json":
        print(render_human_actions_json(result, focus=focus_filter), end="")
    elif output_format == "actions-html":
        print(render_human_actions_html(result, focus=focus_filter), end="")
    elif output_format == "actions-csv":
        print(render_human_actions_csv(result, focus=focus_filter), end="")
    elif output_format == "csv":
        print(render_comparison_csv(result), end="")
    else:
        print(json.dumps(_output(result), sort_keys=True, separators=(",", ":")))
    return 2 if result.status == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
