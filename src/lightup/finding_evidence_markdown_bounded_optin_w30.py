"""Opt-in bounded-input Markdown finding presentation for W28 evidence lineage.

Not wired into any default report, DomainStore, auth path or file producer.
Counts validated UTF-8 *input* bytes, not a guaranteed output-size bound.
"""
from __future__ import annotations

from .finding_evidence_markdown_checked_optin_w28 import render_checked_findings_markdown
from .models import Finding, RetestStatus, Severity

_ERROR = "invalid legacy finding evidence integrity"
_MAX_FINDINGS = 128
_MAX_EVIDENCE_PER_FINDING = 128
_MAX_FIELD_BYTES = 16_384
_MAX_REF_BYTES = 4_096
_MAX_TOTAL_INPUT_BYTES = 1_048_576


def _bounded_text(value: object, ceiling: int) -> int:
    if type(value) is not str:
        raise ValueError(_ERROR)
    # UTF-8 uses at least one byte per Unicode code point. Reject obviously
    # oversized strings before strip()/encode() can copy untrusted input.
    if len(value) > ceiling or not value.strip():
        raise ValueError(_ERROR)
    try:
        size = len(value.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise ValueError(_ERROR) from exc
    if size > ceiling:
        raise ValueError(_ERROR)
    return size


def render_bounded_findings_markdown(findings: object) -> str:
    """Validate and snapshot all input before passing copies to W28.

    Failed late entries never invoke the Markdown renderer. The function does
    not escape Markdown/HTML or redact secrets; privacy review is still needed.
    """
    if type(findings) is not list or len(findings) > _MAX_FINDINGS:
        raise ValueError(_ERROR)

    total = 0
    snapshots: list[Finding] = []
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError(_ERROR)
        if type(finding.severity) is not Severity:
            raise ValueError(_ERROR)
        if type(finding.retest_status) is not RetestStatus:
            raise ValueError(_ERROR)

        evidence = finding.evidence
        if type(evidence) is not list or len(evidence) > _MAX_EVIDENCE_PER_FINDING:
            raise ValueError(_ERROR)

        # Snapshot only existing displayed fields, not caller-owned metadata.
        fields = (finding.finding_id, finding.title,
                  finding.target, finding.remediation)
        for field in fields:
            total += _bounded_text(field, _MAX_FIELD_BYTES)
            if total > _MAX_TOTAL_INPUT_BYTES:
                raise ValueError(_ERROR)

        copied_evidence = []
        for reference in evidence:
            total += _bounded_text(reference, _MAX_REF_BYTES)
            if total > _MAX_TOTAL_INPUT_BYTES:
                raise ValueError(_ERROR)
            copied_evidence.append(reference)

        snapshots.append(Finding(
            finding_id=fields[0],
            title=fields[1],
            severity=finding.severity,
            target=fields[2],
            evidence=copied_evidence,
            remediation=fields[3],
            retest_status=finding.retest_status,
        ))

    return render_checked_findings_markdown(snapshots)
