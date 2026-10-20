"""Privacy-minimal local inspection of PRIVATE LightUp lab artifacts.

This is read-only, offline and non-authorizing. It never calls the lab
runner, planner, model gateway or a target-capable worker. No original target,
title, evidence, model prompt, customer ID or filesystem path is printed.
"""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import stat

_MAX_BYTES = 8 * 1024 * 1024
_MAX_FINDINGS = 2048
_SEVERITIES = ("critical", "high", "medium", "low", "info")


class ArtifactRejected(ValueError):
    """An unsupported private artifact, with no source text in the message."""


def _require(condition: bool) -> None:
    if not condition:
        raise ArtifactRejected("private lab artifact is not admitted")


def _reject_duplicate_keys(pairs: list[tuple[str, object]]) -> dict:
    output: dict = {}
    for key, value in pairs:
        _require(type(key) is str and key not in output)
        output[key] = value
    return output


def _read_private_json(name: str) -> dict:
    """Open only one explicit ordinary file; bound BEFORE parsing."""
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(name, flags)
        source_stat = os.fstat(fd)
        _require(stat.S_ISREG(source_stat.st_mode))
        _require(0 < source_stat.st_size <= _MAX_BYTES)
        with os.fdopen(fd, "rb") as stream:
            fd = -1
            raw = stream.read(_MAX_BYTES + 1)
        _require(0 < len(raw) <= _MAX_BYTES)
        decoded = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_reject_duplicate_keys,
            parse_constant=lambda _: (_ for _ in ()).throw(ArtifactRejected()),
        )
        _require(type(decoded) is dict)
        return decoded
    except (OSError, UnicodeError, ValueError, RecursionError,
            OverflowError, MemoryError, TypeError) as exc:
        raise ArtifactRejected("private lab artifact is not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)


def _overview(source: dict) -> dict:
    """Aggregate only; source declarations are NOT trusted security evidence."""
    if source.get("mode") == "LAB_INPUT_PREVIEW_ONLY":
        _require(type(source.get("endpoint_count")) is int
                 and 1 <= source["endpoint_count"] <= 16)
        _require(type(source.get("lab_host_candidates")) is list
                 and len(source["lab_host_candidates"]) == source["endpoint_count"])
        _require(all(type(item) is str for item in source["lab_host_candidates"]))
        _require(all(source.get(flag) is False for flag in (
            "plan_created", "model_called", "target_interaction_performed",
            "authorization_granted",
        )))
        return {
            "artifact_kind": "isolated_lab_input_preview",
            "declared_endpoint_count": source["endpoint_count"],
            "assessment_executed": False,
        }

    if set(source) == {"record", "context"}:
        record, context = source["record"], source["context"]
        _require(type(record) is dict and type(context) is dict)
        _require(type(record.get("metrics")) is dict)
        _require(type(record.get("scenario_id")) is str
                 and type(record.get("run_id")) is str)
        _require(type(context.get("run_id")) is str
                 and context["run_id"] == record["run_id"])
        _require(context.get("is_lab") is True
                 and context.get("authorization", "UNKNOWN") is None)
        metrics = record["metrics"]
        counts = {}
        for key in ("valid_findings", "invalid_findings", "missed_findings",
                    "coverage_assessed", "coverage_unknown"):
            value = metrics.get(key)
            _require(type(value) is int and 0 <= value <= 1_000_000_000)
            counts["declared_" + key] = value
        return {
            "artifact_kind": "offline_lab_benchmark_source",
            "assessment_executed": "caller_declares_lab_record",
            "declared_metrics": counts,
            "comparison_performed": False,
        }

    _require(type(source.get("run_id")) is str
             and type(source.get("scenario_id")) is str)
    _require(type(source.get("targets")) is list
             and 1 <= len(source["targets"]) <= 16)
    _require(all(type(item) is str for item in source["targets"]))
    findings = source.get("findings")
    _require(type(findings) is list and len(findings) <= _MAX_FINDINGS)
    severities = {level: 0 for level in _SEVERITIES}
    with_evidence_ref = with_evidence_summary = with_finding_id = 0
    seen_ids: set[str] = set()
    for finding in findings:
        _require(type(finding) is dict)
        severity = finding.get("severity")
        _require(type(severity) is str and severity in severities)
        severities[severity] += 1
        refs = finding.get("evidence_ids")
        _require(type(refs) is list and len(refs) <= 64)
        _require(all(type(ref) is str for ref in refs))
        with_evidence_ref += bool(refs)
        summary = finding.get("evidence_summary")
        _require(summary is None or type(summary) is str)
        with_evidence_summary += bool(summary)
        fid = finding.get("finding_id")
        if fid is not None:
            _require(type(fid) is str and fid and fid not in seen_ids)
            seen_ids.add(fid)
            with_finding_id += 1
    review = source.get("review")
    _require(review is None or type(review) is dict)
    if review is not None:
        reviewed = review.get("findings")
        _require(type(reviewed) is list and len(reviewed) == len(findings))
    return {
        "artifact_kind": "isolated_lab_assessment",
        "assessment_executed": "caller_declares_lab_result",
        "declared_target_count": len(source["targets"]),
        "declared_finding_count": len(findings),
        "declared_severity_counts": severities,
        "findings_with_source_reference": with_evidence_ref,
        "findings_with_source_summary": with_evidence_summary,
        "findings_with_unique_identity": with_finding_id,
        "model_review_included": review is not None,
        "comparison_performed": False,
    }


def inspect_artifact(path: str) -> dict:
    """Produce a non-authorizing aggregate without disclosing private source."""
    summary = _overview(_read_private_json(path))
    return {
        "schema": "lightup.lab_artifact_inspection.v1",
        "status": "REVIEW_ONLY",
        "source_authenticated": False,
        "ground_truth_verified": False,
        "client_consent_verified": False,
        "operator_consent_verified": False,
        "authorization_granted": False,
        "dispatch_allowed": False,
        "release_allowed": False,
        **summary,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lightup lab-inspect")
    parser.add_argument("artifact", help="explicit local PRIVATE lab artifact JSON file")
    args = parser.parse_args(argv)
    try:
        result = inspect_artifact(args.artifact)
    except ArtifactRejected:
        result = {
            "schema": "lightup.lab_artifact_inspection.v1",
            "status": "HOLD",
            "authorization_granted": False,
            "release_allowed": False,
            "reason": "local private lab artifact was not admitted",
        }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 2 if result["status"] == "REVIEW_ONLY" else 3


if __name__ == "__main__":
    raise SystemExit(main())
