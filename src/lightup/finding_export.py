"""Offline, presentation-only CSV export of already-authorized findings."""
from __future__ import annotations

import csv
import io

from .models import Finding, RetestStatus, Severity
from .redaction import redact_text

_COLUMNS = ("finding_id", "title", "severity", "retest_status", "remediation")


def _text(value: object, field: str) -> str:
    if type(value) is not str or not value.strip():
        raise ValueError(f"{field} must be non-empty text")
    return value


def _cell(value: str) -> str:
    # Redact before presentation escaping; neither operation mutates the finding.
    value = redact_text(value)
    # Spreadsheet parsers may skip leading whitespace/control characters.
    offset = 0
    while offset < len(value) and (value[offset].isspace() or ord(value[offset]) < 32):
        offset += 1
    probe = value[offset:]
    if probe.startswith(("=", "+", "-", "@")) or value.startswith(("\t", "\r", "\n")):
        return "'" + value
    return value


def render_findings_csv(findings: list[Finding]) -> str:
    """Render a summary; caller must first authorize/select the findings.

    Omits targets, raw evidence and arbitrary metadata. This export does not
    certify evidence, completeness, tenant ownership or security outcomes.
    Known credential patterns use the shared redactor; free text still needs
    human review before external sharing.
    """
    if type(findings) is not list:
        raise ValueError("findings must be a list")
    rows: list[tuple[str, ...]] = []
    seen: set[str] = set()
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError("each entry must be a Finding")
        finding_id = _text(finding.finding_id, "finding_id")
        if finding_id in seen:
            raise ValueError("duplicate finding_id")
        seen.add(finding_id)
        if type(finding.severity) is not Severity:
            raise ValueError("severity must be a Severity")
        if type(finding.retest_status) is not RetestStatus:
            raise ValueError("retest_status must be a RetestStatus")
        # Validate required source data without including the target in output.
        _text(finding.target, "target")
        rows.append(tuple(_cell(value) for value in (
            finding_id,
            _text(finding.title, "title"),
            finding.severity.value,
            finding.retest_status.value,
            _text(finding.remediation, "remediation"),
        )))
    output = io.StringIO(newline="")
    writer = csv.writer(output, quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(_COLUMNS)
    writer.writerows(rows)
    return output.getvalue()
