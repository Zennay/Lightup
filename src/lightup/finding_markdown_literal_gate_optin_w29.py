"""Opt-in conservative literal-line admission for legacy Finding Markdown reports.

Deny-only presentation guard above W28. Not the default renderer and not a
general Markdown sanitizer, secret scrubber, client authorization, or release gate.
Only synthetic PLAN/LAB use until source-owner and privacy review.
"""
from __future__ import annotations

import re
import unicodedata

from .finding_evidence_markdown_checked_optin_w28 import (
    render_checked_findings_markdown,
)
from .models import Finding, RetestStatus, Severity

_ERROR = "invalid finding markdown presentation integrity"
_ALLOWED_PUNCTUATION = frozenset(" .,;:/-'")
_MAX_FINDINGS = 128
_MAX_EVIDENCE = 128
_MAX_FIELD_LENGTH = 1024


def _literal_line(value: object) -> str:
    """Permit only a conservative, single-line literal display alphabet.

    Apply the lexical check to NFKC text so compatibility-width Markdown
    delimiters cannot avoid admission; never normalize or modify output.
    """
    if type(value) is not str or not value.strip() or len(value) > _MAX_FIELD_LENGTH:
        raise ValueError(_ERROR)
    normalized = unicodedata.normalize("NFKC", value)
    if not normalized or not normalized.strip() or len(normalized) > _MAX_FIELD_LENGTH:
        raise ValueError(_ERROR)
    for char in normalized:
        category = unicodedata.category(char)
        if not (
            category.startswith(("L", "N"))
            or char in _ALLOWED_PUNCTUATION
        ):
            raise ValueError(_ERROR)
    if not normalized[0].isalnum() or re.match(r"^[0-9]{1,9}[.)] ", normalized):
        raise ValueError(_ERROR)
    return value


def render_literal_checked_findings_markdown(findings: object) -> str:
    """Snapshot all source fields before calling the W28 checked renderer.

    Fail the entire batch before producing any report when an untrusted field
    could introduce Markdown structural syntax, HTML, invisible format marks,
    multiline content or noncanonical identity. Nothing is persisted.
    """
    if type(findings) is not list or len(findings) > _MAX_FINDINGS:
        raise ValueError(_ERROR)
    sealed: list[Finding] = []
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError(_ERROR)
        if type(finding.severity) is not Severity or type(finding.retest_status) is not RetestStatus:
            raise ValueError(_ERROR)
        evidence = finding.evidence
        if type(evidence) is not list or len(evidence) > _MAX_EVIDENCE:
            raise ValueError(_ERROR)
        values = {
            field: _literal_line(getattr(finding, field))
            for field in ("finding_id", "title", "target", "remediation")
        }
        sealed.append(
            Finding(
                **values,
                severity=finding.severity,
                retest_status=finding.retest_status,
                evidence=[_literal_line(item) for item in evidence],
            )
        )
    return render_checked_findings_markdown(sealed)
