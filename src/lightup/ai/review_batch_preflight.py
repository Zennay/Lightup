"""Opt-in, non-authorizing whole-batch preflight for offline finding review.

The existing AssessmentReviewPipeline.review entrypoint is NOT changed. This
helper copies only bounded, canonical presentation data, rejects the entire
batch before any model dispatch, and never touches targets or persistence.

A successful preflight does NOT authenticate, verify evidence, authorize a
model/provider, confer a security verdict or permit remediation.
"""
from __future__ import annotations

from .pipeline import AssessmentReviewPipeline, ReviewResult

_MAX_FINDINGS = 128
_MAX_SOURCE_KEYS = 32
_MAX_TEXT = 8192
_MAX_TARGET = 2048
_MAX_EVIDENCE_REFS = 64
_MAX_EVIDENCE_REF = 256
_MAX_SUMMARY = 4096
_MAX_TARGETS = 32
_MAX_COUNTS = 64


def _mapping(value: object, field: str) -> dict:
    if type(value) is not dict or len(value) > _MAX_SOURCE_KEYS:
        raise ValueError(f"{field} must be a bounded canonical object")
    if any(type(key) is not str for key in value):
        raise ValueError(f"{field} must use canonical string keys")
    return value


def _text(value: object, field: str, maximum: int = _MAX_TEXT) -> str:
    if type(value) is not str or len(value) > maximum or not value.strip():
        raise ValueError(f"{field} must be bounded canonical non-empty text")
    return value


def preflight_review_batch(source: object) -> dict:
    """Return a detached presentation-only snapshot or fail before model I/O.

    Does not canonicalize, repair or silently deduplicate evidence IDs.
    Source order and exact fix text are retained. The returned dict is a
    private copy for immediate review, not a durable or authenticated record.
    """
    root = _mapping(source, "review batch")
    target = root.get("target")
    if target is not None:
        target = _text(target, "target", _MAX_TARGET)

    raw_targets = root.get("targets", [])
    if type(raw_targets) is not list or len(raw_targets) > _MAX_TARGETS:
        raise ValueError("targets must be a bounded canonical list")
    targets = [_text(item, "target", _MAX_TARGET) for item in raw_targets]

    raw_findings = root.get("findings")
    if type(raw_findings) is not list or len(raw_findings) > _MAX_FINDINGS:
        raise ValueError("findings must be a bounded canonical list")

    raw_coverage = _mapping(root.get("coverage", {}), "coverage")
    raw_counts = raw_coverage.get("counts", {})
    if type(raw_counts) is not dict or len(raw_counts) > _MAX_COUNTS:
        raise ValueError("coverage counts must be a bounded canonical object")
    counts: dict[str, int] = {}
    for key, value in raw_counts.items():
        if type(key) is not str or not key or len(key) > 64:
            raise ValueError("coverage count name must be canonical text")
        if type(value) is not int or not (0 <= value <= 1_000_000_000):
            raise ValueError("coverage count must be a bounded nonnegative integer")
        counts[key] = value

    # Never fall back from an *explicit* empty finding-local list.
    # Legacy fallback is permitted only for missing/null finding-local refs.
    top_ref = root.get("evidence_id")
    normalized: list[dict] = []
    for item in raw_findings:
        finding = _mapping(item, "finding")
        title = _text(finding.get("finding"), "finding title")
        severity = _text(finding.get("severity"), "severity")
        impact = _text(finding.get("impact"), "impact")
        fix = _text(finding.get("fix"), "current fix")
        summary = _text(finding.get("evidence_summary"), "evidence summary", _MAX_SUMMARY)

        raw_refs = finding.get("evidence_ids")
        if raw_refs is None:
            refs = [top_ref] if top_ref is not None else []
        else:
            if type(raw_refs) is not list:
                raise ValueError("evidence references must be a canonical list")
            refs = raw_refs
        if not refs or len(refs) > _MAX_EVIDENCE_REFS:
            raise ValueError("evidence references must be bounded and non-empty")
        seen: set[str] = set()
        copied: list[str] = []
        for ref in refs:
            canonical = _text(ref, "evidence reference", _MAX_EVIDENCE_REF)
            if canonical in seen:
                raise ValueError("duplicate evidence reference")
            seen.add(canonical)
            copied.append(canonical)

        row = {
            "finding": title,
            "severity": severity,
            "impact": impact,
            "fix": fix,
            "evidence_ids": copied,
            "evidence_summary": summary,
        }
        if "target" in finding:
            row["target"] = _text(finding["target"], "finding target", _MAX_TARGET)
        normalized.append(row)

    # Deliberately exclude unknown fields, especially raw evidence and tokens.
    # This snapshot must not be mutated between preflight and review.
    return {"target": target, "targets": targets, "findings": normalized,
            "coverage": {"counts": counts}}


def review_with_batch_preflight(
    pipeline: AssessmentReviewPipeline, source: object
) -> ReviewResult:
    """Opt-in whole-batch admission. Not wired into the default entrypoint.

    A real provider still needs trusted tenant/session permissions, a
    separately approved data-disclosure policy and provider configuration.
    """
    if type(pipeline) is not AssessmentReviewPipeline:
        raise ValueError("canonical review pipeline required")
    checked = preflight_review_batch(source)  # Entire batch, zero model calls.
    return pipeline.review(checked)
