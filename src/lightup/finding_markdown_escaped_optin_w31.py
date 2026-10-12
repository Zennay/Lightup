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
_MAX_OUTPUT_BYTES = 2_097_152

# Colon, slash and at-sign discourage renderer-specific implicit URL links.
# Dollar is special in Markdown math extensions; escape literal budgets.
_LITERAL_ESCAPE = frozenset("\\*_{}[]()#+-.!|>~:/@$") | {chr(96)}
_COMPAT_MARKUP = frozenset("<>[](){}*#|!~\\:_@+-$") | {chr(96)}


def _checked_literal(value: object) -> tuple[str, int]:
    """Admit bounded single-line readable Unicode without coercing the input."""
    # UTF-8 uses at least one byte per Unicode code point. Reject an
    # impossible field before strip(), encode() or a character-by-character
    # Unicode scan can traverse an arbitrarily large caller-owned string.
    if type(value) is not str or len(value) > _MAX_FIELD_BYTES:
        raise ValueError(_ERROR)
    if not value.strip():
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
            if total_bytes + size > _MAX_BATCH_BYTES:
                raise ValueError(_ERROR)
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
            # Stop preflight at the first source-byte overrun, rather than
            # scanning all remaining evidence before rejecting this finding.
            if total_bytes + size > _MAX_BATCH_BYTES:
                raise ValueError(_ERROR)
            if checked in seen_evidence_ids:
                raise ValueError(_ERROR)
            seen_evidence_ids.add(checked)
            evidence.append(checked)
            total_bytes += size
        snapshots.append((
            *fields,
            finding.severity.value,
            finding.retest_status.value,
            tuple(evidence),
        ))

    # Keep the UTF-8 byte budget during assembly rather than after building
    # every escaped line. Each line is bounded before it enters the list.
    # All finding/evidence preflight above still completes before rendering.
    lines: list[str] = []
    output_bytes = 0

    def append_line(line: str) -> None:
        nonlocal output_bytes
        size = len(line.encode("utf-8", "strict")) + (1 if lines else 0)
        if output_bytes + size > _MAX_OUTPUT_BYTES:
            raise ValueError(_ERROR)
        lines.append(line)
        output_bytes += size

    if not snapshots:
        return "# LightUp Assessment Findings\n\nNo findings recorded.\n"

    append_line("# LightUp Assessment Findings")
    append_line("")
    for finding_id, title, target, remediation, severity, retest_status, evidence in snapshots:
        append_line("## " + _escape_literal(title))
        append_line("- ID: " + _escape_literal(finding_id))
        append_line("- Severity: **" + severity + "**")
        append_line("- Target: " + _escape_literal(target))
        append_line("- Retest: " + retest_status)
        append_line("")
        append_line("### Evidence")
        if evidence:
            for item in evidence:
                append_line("- " + _escape_literal(item))
        else:
            append_line("- No evidence recorded.")
        append_line("")
        append_line("### Remediation")
        append_line(_escape_literal(remediation))
        append_line("")
    return "\n".join(lines)
