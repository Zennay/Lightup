"""Opt-in, read-only admission for evidence-grounded remediation review batches.

This is a detached M3/M7 reference component. It does not modify or call the
installed review pipeline, any model, network, scope gate or retest executor.
Consumers must explicitly call this before any model dispatch and separately
enforce tenant/authorization gates. A successfully prepared batch is NOT an
authorization grant, a verifier verdict or proof that evidence is genuine.
"""
from __future__ import annotations

from dataclasses import dataclass


MAX_FINDINGS = 64
MAX_EVIDENCE_REFS = 64
MAX_EVIDENCE_REF_CHARS = 256
MAX_EVIDENCE_SUMMARY_CHARS = 4096
MAX_CURRENT_FIX_CHARS = 4096
MAX_BATCH_FIX_CHARS = 65536
MAX_TITLE_CHARS = 512
MAX_IMPACT_CHARS = 4096
MAX_TARGET_CHARS = 1024
MAX_SEVERITY_CHARS = 32


@dataclass(frozen=True, slots=True)
class PreparedRemediationFinding:
    """Immutable accepted *text metadata*, never raw evidence or authority."""

    title: str
    severity: str
    impact: str
    target: str
    current_fix: str
    evidence_summary: str
    evidence_ids: tuple[str, ...]


@dataclass(frozen=True, slots=True)
class PreparedRemediationBatch:
    """Atomic return: no partial batch is exposed on invalid input."""

    findings: tuple[PreparedRemediationFinding, ...]


def _text(value: object, label: str, limit: int) -> str:
    # Reject subclasses and coercions before any slicing/normalization.
    if type(value) is not str or not value or len(value) > limit or not value.strip():
        raise ValueError(f"review input {label} must be a bounded, nonblank exact string")
    # Python can hold unpaired surrogates that downstream encoders cannot.
    if any(0xD800 <= ord(char) <= 0xDFFF for char in value):
        raise ValueError(f"review input {label} contains an invalid Unicode surrogate")
    return value


def _references(finding: dict, source: dict) -> tuple[str, ...]:
    if "evidence_ids" in finding:
        raw = finding["evidence_ids"]
        if type(raw) is not list:
            raise ValueError("review input evidence_ids must be an exact list")
        if raw:
            refs = raw
        else:
            refs = []
    else:
        refs = []

    if not refs:
        if "evidence_id" not in source:
            raise ValueError("review input requires evidence references")
        refs = [source["evidence_id"]]

    if len(refs) > MAX_EVIDENCE_REFS:
        raise ValueError("review input has too many evidence references")
    accepted: list[str] = []
    seen: set[str] = set()
    for ref in refs:
        reference = _text(ref, "evidence reference", MAX_EVIDENCE_REF_CHARS)
        if reference in seen:
            raise ValueError("review input duplicate evidence reference")
        seen.add(reference)
        accepted.append(reference)
    return tuple(accepted)


def prepare_remediation_review_inputs(lab_result: object) -> PreparedRemediationBatch:
    """Preflight *the entire* synthetic/authorized-result metadata batch.

    Input must have plain JSON-like Python containers. There is no mutation,
    model dispatch, target contact, evidence collection, authorization, or
    persistence. The caller controls invocation and must never treat this
    optional helper as replacing the canonical scope and evidence gates.
    """
    if type(lab_result) is not dict:
        raise ValueError("review input batch must be an exact dictionary")
    raw_findings = lab_result.get("findings")
    if type(raw_findings) is not list:
        raise ValueError("review input findings must be an exact list")
    if len(raw_findings) > MAX_FINDINGS:
        raise ValueError("review input has too many findings")

    prepared: list[PreparedRemediationFinding] = []
    cumulative_fix_chars = 0
    for finding in raw_findings:
        if type(finding) is not dict:
            raise ValueError("review input finding must be an exact dictionary")
        current_fix = _text(
            finding.get("fix"), "current remediation fix", MAX_CURRENT_FIX_CHARS
        )
        cumulative_fix_chars += len(current_fix)
        if cumulative_fix_chars > MAX_BATCH_FIX_CHARS:
            raise ValueError("review input remediation text exceeds batch budget")
        evidence_ids = _references(finding, lab_result)
        prepared.append(
            PreparedRemediationFinding(
                title=_text(finding.get("finding"), "title", MAX_TITLE_CHARS),
                severity=_text(finding.get("severity"), "severity", MAX_SEVERITY_CHARS),
                impact=_text(finding.get("impact"), "impact", MAX_IMPACT_CHARS),
                target=_text(
                    finding.get("target", lab_result.get("target")),
                    "target label", MAX_TARGET_CHARS,
                ),
                current_fix=current_fix,
                evidence_summary=_text(
                    finding.get("evidence_summary"), "evidence summary",
                    MAX_EVIDENCE_SUMMARY_CHARS,
                ),
                evidence_ids=evidence_ids,
            )
        )

    return PreparedRemediationBatch(tuple(prepared))
