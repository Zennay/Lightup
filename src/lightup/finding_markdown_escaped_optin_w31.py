"""Experimental opt-in literal escaping for in-memory Finding Markdown.

No default renderer, DomainStore, web entrypoint, client authorization,
target interaction or remediation/retest verification is changed here.
"""
from __future__ import annotations

import html
import unicodedata

from .models import Finding, RetestStatus, Severity

_ERROR = "invalid finding markdown evidence integrity"
_MAX_FINDINGS = 128
_MAX_EVIDENCE_PER_FINDING = 128
_MAX_FIELD_BYTES = 16_384
_MAX_BATCH_BYTES = 1_048_576

# Colon, slash and at-sign discourage renderer-specific implicit URL links.
_LITERAL_ESCAPE = frozenset("\\*_{}[]()#+-.!|>~:/@") | {chr(96)}
_COMPAT_MARKUP = frozenset("<>[](){}*#|!~\\:_@+-") | {chr(96)}


def _checked_literal(value: object) -> tuple[str, int]:
    """Admit bounded single-line readable Unicode without coercing the input."""
    if type(value) is not str or not value.strip():
        raise ValueError(_ERROR)
    try:
        byte_count = len(value.encode("utf-8", "strict"))
    except UnicodeError:
        raise ValueError(_ERROR) from None
    if byte_count > _MAX_FIELD_BYTES:
        raise ValueError(_ERROR)

    has_base = False
    for character in value:
        category = unicodedata.category(character)
        if category[0] == "C" or category in ("Zl", "Zp") or character == "\u034f":
            raise ValueError(_ERROR)
        if category == "Zs":
            if character != " ":
                raise ValueError(_ERROR)
            has_base = False
        elif category[0] == "M":
            if not has_base:
                raise ValueError(_ERROR)
        else:
            # Punctuation cannot anchor a Unicode combining/variation mark.
            # Letters, numbers and symbols (including emoji) can.
            has_base = category[0] in "LNS"
        compatibility = unicodedata.normalize("NFKC", character)
        if compatibility != character and any(
            char in _COMPAT_MARKUP or char in "<>&"
            for char in compatibility
        ):
            raise ValueError(_ERROR)
    return value, byte_count


def _escape_literal(value: str) -> str:
    """Escape untrusted text as literal inline Markdown, not as raw HTML."""
    escaped = "".join(
        "\\" + char if char in _LITERAL_ESCAPE else char
        for char in value
    )
    return html.escape(escaped, quote=True)


def render_escaped_evidence_markdown_optin_w31(findings: object) -> str:
    """Whole-batch preflight followed by literal Markdown presentation.

    Separate renderer: backslash escapes do not work in Markdown code spans.
    Source snapshots exclude metadata entirely.
    """
    if type(findings) is not list or len(findings) > _MAX_FINDINGS:
        raise ValueError(_ERROR)

    snapshots = []
    seen_finding_ids: set[str] = set()
    total_bytes = 0
    for finding in findings:
        if (
            type(finding) is not Finding
            or type(finding.severity) is not Severity
            or type(finding.retest_status) is not RetestStatus
            or type(finding.evidence) is not list
            or len(finding.evidence) > _MAX_EVIDENCE_PER_FINDING
        ):
            raise ValueError(_ERROR)
        fields = []
        for value in (
            finding.finding_id, finding.title, finding.target, finding.remediation
        ):
            checked, size = _checked_literal(value)
            fields.append(checked)
            total_bytes += size
        # A report must not silently represent the same finding identity
        # as two independent findings. Keep equality exact; no coercion.
        if fields[0] in seen_finding_ids:
            raise ValueError(_ERROR)
        seen_finding_ids.add(fields[0])
        evidence = []
        seen_evidence_ids: set[str] = set()
        for value in finding.evidence:
            checked, size = _checked_literal(value)
            if checked in seen_evidence_ids:
                raise ValueError(_ERROR)
            seen_evidence_ids.add(checked)
            evidence.append(checked)
            total_bytes += size
        if total_bytes > _MAX_BATCH_BYTES:
            raise ValueError(_ERROR)
        snapshots.append((
            *fields,
            finding.severity.value,
            finding.retest_status.value,
            tuple(evidence),
        ))

    lines = ["# LightUp Assessment Findings", ""]
    if not snapshots:
        return "# LightUp Assessment Findings\n\nNo findings recorded.\n"

    for finding_id, title, target, remediation, severity, retest_status, evidence in snapshots:
        lines.extend([
            "## " + _escape_literal(title),
            "- ID: " + _escape_literal(finding_id),
            "- Severity: **" + severity + "**",
            "- Target: " + _escape_literal(target),
            "- Retest: " + retest_status,
            "",
            "### Evidence",
        ])
        if evidence:
            lines.extend("- " + _escape_literal(item) for item in evidence)
        else:
            lines.append("- No evidence recorded.")
        lines.extend(["", "### Remediation", _escape_literal(remediation), ""])
    return "\n".join(lines)
