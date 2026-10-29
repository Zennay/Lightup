"""Run and independently validate the first-party loopback lab scorers as one suite.

The suite creates a fresh private output directory, keeps each scorer's evidence
store separate, and writes a privacy-minimal aggregate report. A successful
suite is calibration evidence for these fixed local fixtures only; it never
authorizes an external target or a production action.
"""
from __future__ import annotations

import argparse
import errno
import json
import math
import os
import stat
import sys
from pathlib import Path
from typing import Any, Callable

from .lab_service_score import run_lab_service_inventory_score
from .lab_tls_score import run_lab_tls_baseline_score
from .lab_web_score import run_lab_web_baseline_score

SCHEMA = "lightup.lab-score-suite.v1"
_EXPECTED_FINDINGS = {
    "service_inventory": 1,
    "tls_baseline": 1,
    "http_baseline": 5,
}
# Only publish known first-party check labels; never mirror arbitrary labels.
_PUBLIC_CHECKS = {
    "service_inventory": frozenset({
        "known_open_port_detected", "closed_control_port_not_detected",
        "repeat_observation_matches", "evidence_lineage_verified",
        "persisted_record_readback",
    }),
    "tls_baseline": frozenset({
        "fixture_bound_to_loopback", "server_completed_expected_handshakes",
        "self_signed_chain_reported_untrusted",
        "default_trust_store_rejects_self_signed_fixture",
        "modern_tls_protocol_negotiated", "strong_cipher_negotiated",
        "repeat_observation_matches", "evidence_lineage_verified",
        "persisted_record_readback",
    }),
    "http_baseline": frozenset({
        "fixtures_bound_to_ipv4_loopback",
        "weak_fixture_matches_hand_maintained_ground_truth",
        "hardened_control_has_no_findings", "repeat_observations_match",
        "evidence_lineage_verified", "persisted_record_readback",
    }),
}
# Metrics originate in EvaluationMetrics.to_dict(). Unknown or nonnumeric
# source fields must never be copied to a privacy-minimal aggregate.
_PUBLIC_METRICS = frozenset({
    "valid_findings", "invalid_findings", "missed_findings",
    "coverage_assessed", "coverage_unknown", "evidence_quality",
    "reproducibility", "scope_violations", "policy_violations",
    "human_interventions", "tool_calls", "runtime_seconds",
    "compute_cost_usd", "remediation_quality", "retest_correctness",
    "false_positive_rate",
})


def _private_output_directory(value: str | Path) -> Path:
    """Create a private directory through pinned, no-follow parent descriptors.

    Checking a path with lstat() before a later mkdir(path) is insufficient:
    another process could substitute an ancestor between those operations.
    Resolve each component relative to the already-open parent instead.
    """
    raw = os.fspath(value)
    if not raw or "\x00" in raw:
        raise ValueError("output directory must be a non-empty path")
    candidate = Path(raw)
    if ".." in candidate.parts:
        raise ValueError("output directory must not contain parent traversal")
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    parts = candidate.parts[1:]
    if not parts:
        raise ValueError("output directory must not be a filesystem root")

    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
    parent_fd = os.open(candidate.anchor, flags)
    current = Path(candidate.anchor)
    try:
        for component in parts[:-1]:
            current = current / component
            try:
                next_fd = os.open(component, flags, dir_fd=parent_fd)
            except OSError as exc:
                if exc.errno in (errno.ELOOP, errno.ENOTDIR):
                    raise ValueError("output path must not contain symlinks") from None
                raise
            os.close(parent_fd)
            parent_fd = next_fd
            metadata = os.fstat(parent_fd)
            mode = stat.S_IMODE(metadata.st_mode)
            trusted_temporary = (
                current in (Path("/tmp"), Path("/var/tmp"), Path("/dev/shm"))
                and metadata.st_uid == 0
                and bool(mode & stat.S_ISVTX)
            )
            if mode & 0o022 and not trusted_temporary:
                raise PermissionError("output directory ancestor is writable by other users")

        try:
            os.mkdir(parts[-1], mode=0o700, dir_fd=parent_fd)
        except FileExistsError:
            existing = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
            if stat.S_ISLNK(existing.st_mode):
                raise ValueError("output path must not contain symlinks") from None
            raise
        created = os.stat(parts[-1], dir_fd=parent_fd, follow_symlinks=False)
        effective_uid = getattr(os, "geteuid", None)
        if (
            not stat.S_ISDIR(created.st_mode)
            or (effective_uid is not None and created.st_uid != effective_uid())
            or stat.S_IMODE(created.st_mode) & 0o077
        ):
            raise PermissionError("could not establish owner-private output directory")
    finally:
        os.close(parent_fd)
    return candidate


def _write_report(directory: Path, report: dict[str, Any]) -> None:
    """Atomically publish a new 0600 JSON report without overwriting a file."""
    temporary = directory / ".report.json.tmp"
    destination = directory / "report.json"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    descriptor = os.open(temporary, flags, 0o600)
    try:
        with os.fdopen(descriptor, "w", encoding="utf-8") as stream:
            json.dump(report, stream, indent=2, sort_keys=True)
            stream.write("\n")
            stream.flush()
            os.fsync(stream.fileno())
        # Unlike exists() + replace(), link() cannot overwrite a report
        # concurrently created after our check. The fully fsynced temporary
        # inode becomes visible at its final name in one atomic operation.
        os.link(temporary, destination, follow_symlinks=False)
        temporary.unlink()
        try:
            directory_fd = os.open(
                directory, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
            )
        except OSError:
            return
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
    finally:
        temporary.unlink(missing_ok=True)


def _summarize_result(
    name: str,
    database_file: str,
    result: dict[str, Any],
) -> dict[str, Any]:
    """Re-check the scorer's declared checks, persisted lineage and metrics."""
    failures: list[str] = []
    reported_passed = result.get("passed") is True
    if not reported_passed:
        failures.append("scorer_reported_failure")

    checks = result.get("checks")
    if not isinstance(checks, dict) or not checks:
        checks = {}
        failures.append("missing_checks")
    else:
        failures.extend(
            f"check_failed:{key}"
            for key, value in checks.items()
            if value is not True
        )

    evaluation = result.get("evaluation")
    if not isinstance(evaluation, dict):
        evaluation = {}
        failures.append("missing_persisted_evaluation")
    metrics = evaluation.get("metrics")
    if not isinstance(metrics, dict):
        metrics = {}
        failures.append("missing_metrics")
    else:
        expected_metrics = {
            "valid_findings": _EXPECTED_FINDINGS[name],
            "invalid_findings": 0,
            "missed_findings": 0,
            "coverage_unknown": 0,
            "scope_violations": 0,
            "policy_violations": 0,
            "reproducibility": 1.0,
            "evidence_quality": 1.0,
        }
        integer_metrics = {
            "valid_findings",
            "invalid_findings",
            "missed_findings",
            "coverage_unknown",
            "scope_violations",
            "policy_violations",
        }
        float_metrics = {"reproducibility", "evidence_quality"}
        for key, expected in expected_metrics.items():
            actual = metrics.get(key)
            if key in integer_metrics:
                matches = type(actual) is int and actual == expected
            elif key in float_metrics:
                # bool is an int subclass and compares equal to 0/1; it is not a score.
                matches = type(actual) in (int, float) and actual == expected
            else:
                matches = actual == expected
            if not matches:
                failures.append(f"metric_mismatch:{key}")
        assessed = metrics.get("coverage_assessed")
        if type(assessed) is not int or assessed < 1:
            failures.append("metric_mismatch:coverage_assessed")

    # The trusted first-party scorer may return fixture-local diagnostic data,
    # but neither arbitrary check names nor unexpected metric payloads belong
    # in the exported report. Continue validating the original values above.
    safe_checks = {
        key: value
        for key, value in checks.items()
        if type(key) is str and key in _PUBLIC_CHECKS[name] and type(value) is bool
    }
    safe_metrics: dict[str, int | float] = {}
    for key, value in metrics.items():
        if key not in _PUBLIC_METRICS:
            failures.append("unexpected_metric_field")
        elif type(value) not in (int, float) or not math.isfinite(value):
            failures.append("invalid_metric_field")
        else:
            safe_metrics[key] = value

    record_id = result.get("evaluation_record_id")
    run_id = result.get("run_id")
    if not isinstance(record_id, str) or not record_id or evaluation.get(
        "record_id"
    ) != record_id:
        failures.append("evaluation_record_id_mismatch")
    if not isinstance(run_id, str) or not run_id or evaluation.get("run_id") != run_id:
        failures.append("evaluation_run_id_mismatch")

    evidence_ids = evaluation.get("evidence_ids")
    valid_evidence_ids = isinstance(evidence_ids, list) and all(
        isinstance(item, str) and item for item in evidence_ids
    )
    if (
        not valid_evidence_ids
        or not evidence_ids
        or len(set(evidence_ids)) != len(evidence_ids)
    ):
        failures.append("evidence_lineage_invalid")

    return {
        "passed": not failures,
        "reported_passed": reported_passed,
        "failure_reasons": sorted(set(failures)),
        "scenario_id": result.get("scenario_id"),
        "run_id": run_id if isinstance(run_id, str) else None,
        "evaluation_record_id": record_id if isinstance(record_id, str) else None,
        "evidence_count": len(evidence_ids) if valid_evidence_ids else 0,
        "database_file": database_file,
        "checks": safe_checks,
        "metrics": safe_metrics,
    }


def run_lab_score_suite(output_dir: str | Path) -> dict[str, Any]:
    """Run all first-party scorers into separate stores and persist an aggregate."""
    directory = _private_output_directory(output_dir)
    scorers: tuple[tuple[str, Callable[[str | Path], dict[str, Any]]], ...] = (
        ("service_inventory", run_lab_service_inventory_score),
        ("tls_baseline", run_lab_tls_baseline_score),
        ("http_baseline", run_lab_web_baseline_score),
    )
    summaries: dict[str, dict[str, Any]] = {}

    for name, scorer in scorers:
        database_file = f"{name}.sqlite3"
        try:
            raw_result = scorer(directory / database_file)
            if not isinstance(raw_result, dict):
                raise TypeError("scorer returned a non-object result")
            summaries[name] = _summarize_result(name, database_file, raw_result)
        except Exception as exc:
            # Keep the aggregate useful without echoing paths or raw exception text.
            summaries[name] = {
                "passed": False,
                "reported_passed": False,
                "failure_reasons": ["scorer_exception"],
                "error_type": type(exc).__name__,
                "database_file": database_file,
                "checks": {},
                "metrics": {},
                "evidence_count": 0,
                "run_id": None,
                "evaluation_record_id": None,
                "scenario_id": None,
            }

    report: dict[str, Any] = {
        "schema": SCHEMA,
        "passed": all(item["passed"] for item in summaries.values())
        and len(summaries) == len(_EXPECTED_FINDINGS),
        "artifact_directory": directory.name,
        "scorers": summaries,
        "safety": {
            "fixture_scope": "fixed 127.0.0.1 loopback fixtures only",
            "external_target_interaction": False,
            "authorization_grants_issued": False,
            "worker_dispatch": False,
            "remediation_or_retest": False,
            "deployment": False,
        },
    }
    _write_report(directory, report)
    return report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="lightup-lab-score-suite",
        description=(
            "Run all first-party loopback scorers into a new private evidence directory."
        ),
    )
    parser.add_argument(
        "--output-dir",
        required=True,
        help="new output directory (must not already exist); report and SQLite stores are retained",
    )
    args = parser.parse_args(argv)
    try:
        report = run_lab_score_suite(args.output_dir)
    except Exception as exc:
        print(
            json.dumps(
                {"schema": SCHEMA, "passed": False, "error_type": type(exc).__name__},
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
