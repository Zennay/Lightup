"""Offline, read-only admission contract for isolated-lab review artifacts."""
from __future__ import annotations

import argparse
import json
import math
import os
import stat
from typing import Any

MAX_SOURCE_BYTES = 8 * 1024 * 1024
MAX_FINDINGS = 2048
SEVERITIES = ("critical", "high", "medium", "low", "info")
COVERAGE = ("assessed", "partially_assessed", "not_applicable", "not_authorized", "unknown")
RETEST = ("not_tested", "fixed", "fix_pending", "regression")
INT_METRICS = ("valid_findings", "invalid_findings", "missed_findings", "coverage_assessed",
               "coverage_unknown", "scope_violations", "policy_violations",
               "human_interventions", "tool_calls")
RATIO_METRICS = ("evidence_quality", "reproducibility", "remediation_quality",
                 "retest_correctness", "false_positive_rate")
OTHER_METRICS = ("runtime_seconds", "compute_cost_usd")


class ArtifactRejected(ValueError):
    """The selected artifact is not admitted; errors never contain source data."""


def require(ok: bool) -> None:
    if not ok:
        raise ArtifactRejected("private lab result is not admitted")


def pairs_no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        require(type(key) is str and key not in result)
        result[key] = value
    return result


def reject_constant(_value: str) -> None:
    raise ArtifactRejected("private lab result is not admitted")


def finite_float(token: str) -> float:
    value = float(token)
    require(math.isfinite(value))
    return value


def obj(value: Any) -> dict[str, Any]:
    require(type(value) is dict)
    return value


def arr(value: Any, maximum: int, minimum: int = 0) -> list[Any]:
    require(type(value) is list and minimum <= len(value) <= maximum)
    return value


def text(value: Any, limit: int = 10_000, nonempty: bool = False) -> None:
    require(type(value) is str and len(value) <= limit)
    require(not nonempty or bool(value.strip()))


def integer(value: Any, maximum: int = 1_000_000_000) -> None:
    if type(value) is int:
        require(0 <= value <= maximum)
    elif type(value) is float:
        require(math.isfinite(value) and value.is_integer() and 0 <= value <= maximum)
    else:
        require(False)


def number(value: Any, maximum: float = 1_000_000_000.0, minimum: float = 0.0) -> None:
    require(type(value) in (int, float) and math.isfinite(value) and minimum <= value <= maximum)


def exact(value: Any, required: set[str], optional: set[str] | None = None) -> dict[str, Any]:
    result = obj(value)
    allowed = required | (optional or set())
    require(required <= set(result) and set(result) <= allowed)
    return result


def bounded_tree(value: Any, depth: int = 0, budget: list[int] | None = None) -> None:
    if budget is None:
        budget = [200_000]
    budget[0] -= 1
    require(budget[0] >= 0 and depth <= 64)
    if type(value) is dict:
        for key, child in value.items():
            text(key, 1024)
            bounded_tree(child, depth + 1, budget)
    elif type(value) is list:
        require(len(value) <= 100_000)
        for child in value:
            bounded_tree(child, depth + 1, budget)
    elif type(value) is str:
        text(value, 200_000)
    elif type(value) is float:
        require(math.isfinite(value))
        if value.is_integer():
            require(abs(value) <= 1_000_000_000_000)
    elif value is None or type(value) in (bool, int):
        if type(value) is int:
            require(abs(value) <= 1_000_000_000_000)
    else:
        require(False)


def validate_source(source: Any) -> dict[str, Any]:
    root = exact(source, {
        "run_id", "scenario_id", "targets", "plan", "denied",
        "elevation_requests", "findings", "coverage", "evaluation", "report_markdown",
    }, {"review", "review_skipped"})
    bounded_tree(root)
    text(root["run_id"], 256, True)
    text(root["scenario_id"], 256, True)
    for target in arr(root["targets"], 16, 1):
        text(target, 2048, True)

    for call in arr(root["plan"], 128):
        item = exact(call, {"tool_id", "asset", "arguments"})
        text(item["tool_id"], 256, True)
        text(item["asset"], 2048)
        args = obj(item["arguments"])
        require(len(args) <= 128)
        bounded_tree(args)
    for denial in arr(root["denied"], 256):
        item = exact(denial, {"tool_id", "reason"})
        text(item["tool_id"], 256, True)
        text(item["reason"], 2048, True)
    for request in arr(root["elevation_requests"], 256):
        text(request, 2048)

    findings = arr(root["findings"], MAX_FINDINGS)
    for finding in findings:
        item = exact(finding, {
            "finding", "severity", "impact", "fix", "retest", "check_id",
            "capability_id", "target", "evidence_ids",
        })
        text(item["finding"], 10_000)
        require(type(item["severity"]) is str and item["severity"] in SEVERITIES)
        text(item["impact"], 20_000)
        text(item["fix"], 20_000)
        require(type(item["retest"]) is str and item["retest"] in RETEST)
        text(item["check_id"], 256, True)
        text(item["capability_id"], 256, True)
        text(item["target"], 2048, True)
        for ref in arr(item["evidence_ids"], 64):
            text(ref, 512, True)

    coverage = exact(root["coverage"], {"domains", "counts", "clean_bill_of_health", "note"})
    domains = obj(coverage["domains"])
    require(len(domains) <= 256)
    derived = {key: 0 for key in COVERAGE}
    for capability, status in domains.items():
        text(capability, 256, True)
        require(type(status) is str and status in COVERAGE)
        derived[status] += 1
    counts = exact(coverage["counts"], set(COVERAGE))
    for status in COVERAGE:
        integer(counts[status])
        require(counts[status] == derived[status])
    require(coverage["clean_bill_of_health"] is None or coverage["clean_bill_of_health"] is False)
    text(coverage["note"], 2048)

    evaluation = exact(root["evaluation"], {
        "record_id", "scenario_id", "run_id", "engine_version", "model_bindings",
        "metrics", "created_at", "notes",
    })
    for field in ("record_id", "scenario_id", "run_id", "engine_version", "created_at"):
        text(evaluation[field], 256, True)
    require(evaluation["scenario_id"] == root["scenario_id"] and evaluation["run_id"] == root["run_id"])
    text(evaluation["notes"], 10_000)
    for pair in arr(evaluation["model_bindings"], 64):
        values = arr(pair, 2, 2)
        text(values[0], 256, True)
        text(values[1], 512, True)
    metrics = exact(evaluation["metrics"], set(INT_METRICS + RATIO_METRICS + OTHER_METRICS))
    for field in INT_METRICS:
        integer(metrics[field])
    for field in RATIO_METRICS:
        number(metrics[field], 1.0)
    for field in OTHER_METRICS:
        number(metrics[field])
    text(root["report_markdown"], 200_000)

    if "review" in root:
        require("review_skipped" not in root)
        review = exact(root["review"], {"findings", "report", "model_bindings"})
        reviewed = arr(review["findings"], MAX_FINDINGS)
        require(len(reviewed) == len(findings))
        for original, candidate in zip(findings, reviewed):
            item = exact(candidate, {"finding", "severity", "verdict", "remediation_advice"})
            text(item["finding"], 10_000)
            require(item["finding"] == original["finding"])
            require(item["severity"] == original["severity"])
            require(type(item["severity"]) is str and item["severity"] in SEVERITIES)
            text(item["verdict"], 10_000)
            text(item["remediation_advice"], 20_000)
        text(review["report"], 200_000)
        bindings = obj(review["model_bindings"])
        require(len(bindings) <= 64)
        for role, model in bindings.items():
            text(role, 256, True)
            text(model, 512, True)
    if "review_skipped" in root:
        text(root["review_skipped"], 2048)
    return root


def _open_without_symlink_components(path: str) -> int:
    """Open a path while refusing symlinks in every supplied path component."""
    require(type(path) is str and bool(path) and "\x00" not in path)
    nofollow = getattr(os, "O_NOFOLLOW", 0)
    directory = getattr(os, "O_DIRECTORY", 0)
    require(bool(nofollow) and bool(directory) and os.open in os.supports_dir_fd)
    require(not path.endswith(os.sep))

    if os.path.isabs(path):
        directory_fd = os.open(os.sep, os.O_RDONLY | directory | nofollow)
        parts = path.split(os.sep)[1:]
    else:
        directory_fd = os.open(".", os.O_RDONLY | directory | nofollow)
        parts = path.split(os.sep)

    try:
        require(bool(parts) and parts[-1] not in ("", ".") and all(part != ".." for part in parts))
        components = [part for part in parts if part not in ("", ".")]
        require(bool(components))
        for component in components[:-1]:
            next_fd = os.open(
                component,
                os.O_RDONLY | directory | nofollow,
                dir_fd=directory_fd,
            )
            os.close(directory_fd)
            directory_fd = next_fd
        return os.open(
            components[-1],
            os.O_RDONLY | nofollow | getattr(os, "O_NONBLOCK", 0),
            dir_fd=directory_fd,
        )
    finally:
        os.close(directory_fd)


def read_explicit_file(path: str) -> bytes:
    fd = -1
    try:
        fd = _open_without_symlink_components(path)
        before = os.fstat(fd)
        require(stat.S_ISREG(before.st_mode) and before.st_nlink == 1)
        require(0 < before.st_size <= MAX_SOURCE_BYTES)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(MAX_SOURCE_BYTES + 1)
            after = os.fstat(stream.fileno())
        require(len(raw) == before.st_size and len(raw) <= MAX_SOURCE_BYTES)
        require((before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns,
                 before.st_ctime_ns, before.st_nlink) ==
                (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                 after.st_ctime_ns, after.st_nlink))
        return raw
    except (OSError, ValueError, TypeError, OverflowError, MemoryError, RecursionError):
        raise ArtifactRejected("private lab result is not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)


def inspect_bytes(raw: bytes) -> dict[str, Any]:
    require(type(raw) is bytes and 0 < len(raw) <= MAX_SOURCE_BYTES)
    try:
        source = json.loads(raw.decode("utf-8", errors="strict"),
                            object_pairs_hook=pairs_no_duplicates,
                            parse_constant=reject_constant, parse_float=finite_float)
    except (UnicodeError, json.JSONDecodeError, ValueError, TypeError, RecursionError, OverflowError):
        raise ArtifactRejected("private lab result is not admitted") from None
    result = validate_source(source)
    severity_counts = {severity: 0 for severity in SEVERITIES}
    for finding in result["findings"]:
        severity_counts[finding["severity"]] += 1
    return {
        "schema": "lightup.lab_review.summary.v1",
        "status": "REVIEW_ONLY",
        "source_authenticated": False,
        "ground_truth_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        "finding_count": len(result["findings"]),
        "severity_counts": severity_counts,
        "coverage_counts": {key: result["coverage"]["counts"][key] for key in COVERAGE},
        "review_included": "review" in result,
        "review_skipped": "review_skipped" in result,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="assessment-lab-review")
    parser.add_argument("source", help="explicit local JSON result produced by the isolated lab")
    args = parser.parse_args(argv)
    try:
        summary = inspect_bytes(read_explicit_file(args.source))
    except ArtifactRejected:
        print(json.dumps({
            "schema": "lightup.lab_review.summary.v1", "status": "HOLD",
            "authorization_granted": False, "dispatch_allowed": False,
            "release_allowed": False, "reason": "selected private lab result was not admitted",
        }, sort_keys=True, indent=2))
        return 2
    print(json.dumps(summary, sort_keys=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
