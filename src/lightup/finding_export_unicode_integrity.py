"""Opt-in fail-closed text preflight for offline finding CSV rendering.

NOT a tenant/session/review/authorization gate. The regular renderer is called
only after the complete batch has been validated and copied. It is not wired to
the production exporter until source-owner review.
"""
from __future__ import annotations

import unicodedata

from .finding_export import render_findings_csv
from .models import Finding, RetestStatus, Severity

MAX_FINDINGS = 128
MAX_TOTAL_UTF8_BYTES = 262_144
MAX_FIELD_BYTES = {
    "finding_id": 256,
    "title": 8192,
    "target": 2048,
    "remediation": 8192,
}
_FORMULA_PREFIXES = ("=", "+", "-", "@")


def _mark_obscures_formula_prefix(value: str) -> bool:
    """Detect leading Unicode marks/spacing hiding a spreadsheet formula.

    Python str.lstrip() skips whitespace, not combining accents or variation
    selectors. Treat only marks *before any visible base* as ignorable and
    preserve marks after actual text (e.g. accented words or emoji).
    """
    probe = value.lstrip()
    index = 0
    saw_mark = False
    while index < len(probe):
        char = probe[index]
        if unicodedata.category(char).startswith("M"):
            saw_mark = True
        elif char.isspace() and saw_mark:
            pass
        else:
            break
        index += 1
    return saw_mark and probe[index:].startswith(_FORMULA_PREFIXES)


def _checked_text(value: object, field: str, max_bytes: int) -> tuple[str, int]:
    if type(value) is not str or not value.strip():
        raise ValueError("invalid CSV presentation field")
    try:
        byte_size = len(value.encode("utf-8", "strict"))
    except UnicodeError as exc:
        raise ValueError("invalid CSV presentation field") from exc
    if byte_size > max_bytes:
        raise ValueError("CSV field size exceeded")

    # Reject invisible formatting, surrogate/private-use, unassigned, ASCII
    # controls and Unicode line/paragraph separators. Ordinary Unicode
    # letters, combining marks and visible punctuation remain valid.
    for char in value:
        category = unicodedata.category(char)
        if category.startswith("C") or category in ("Zl", "Zp"):
            raise ValueError("unsafe CSV presentation character")

    normalized = unicodedata.normalize("NFKC", value)
    if any(unicodedata.category(char).startswith("C")
           or unicodedata.category(char) in ("Zl", "Zp")
           for char in normalized):
        raise ValueError("unsafe normalized CSV character")
    # Isolated marks and presentation selectors are not perceptible evidence
    # identifiers or remediation text. Preserve accents and selectors when a
    # real letter, number, punctuation or symbol is also present.
    if not any(unicodedata.category(char)[0] in "LNPS" for char in normalized):
        raise ValueError("CSV field requires visible base character")
    # The default renderer already quotes literal ASCII formula prefixes,
    # even after leading ordinary Unicode whitespace. Only block prefixes
    # that a spreadsheet's compatibility handling might uncover *after*
    # that existing escape decision.
    original_prefix = value.lstrip()
    normalized_prefix = normalized.lstrip()
    if normalized_prefix.startswith(_FORMULA_PREFIXES) and not (
        original_prefix.startswith(_FORMULA_PREFIXES)
    ):
        raise ValueError("compatibility-disguised CSV formula prefix")
    if _mark_obscures_formula_prefix(normalized_prefix):
        raise ValueError("Unicode-mark-disguised CSV formula prefix")
    return value, byte_size


def render_findings_csv_checked(findings: list[Finding]) -> str:
    """Return offline CSV only after atomic, bounded presentation preflight.

    The caller MUST have independently authorized the exact tenant/finding
    selection. A CSV is not evidence authenticity, review approval, verified
    remediation, secret-redaction completeness, or a safe spreadsheet verdict.
    """
    if type(findings) is not list or len(findings) > MAX_FINDINGS:
        raise ValueError("invalid CSV batch")
    total_bytes = 0
    snapshots: list[Finding] = []
    seen: set[str] = set()
    seen_compatibility_ids: set[str] = set()
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError("invalid CSV finding")
        severity = finding.severity
        retest_status = finding.retest_status
        if type(severity) is not Severity or type(retest_status) is not RetestStatus:
            raise ValueError("invalid CSV enum")
        values: dict[str, str] = {}
        for name, limit in MAX_FIELD_BYTES.items():
            value, nbytes = _checked_text(getattr(finding, name), name, limit)
            values[name] = value
            total_bytes += nbytes
            if total_bytes > MAX_TOTAL_UTF8_BYTES:
                raise ValueError("CSV batch size exceeded")
        if values["finding_id"] in seen:
            raise ValueError("duplicate CSV finding identity")
        seen.add(values["finding_id"])
        display_key = unicodedata.normalize("NFKC", values["finding_id"])
        if display_key in seen_compatibility_ids:
            raise ValueError("ambiguous CSV display identity")
        seen_compatibility_ids.add(display_key)
        # Do not retain references to mutable Finding instances. Only the five
        # rendered columns plus a non-rendered target are snapshotted. Raw
        # evidence and metadata are intentionally never copied or exported.
        snapshots.append(Finding(
            finding_id=values["finding_id"],
            title=values["title"],
            severity=severity,
            target=values["target"],
            remediation=values["remediation"],
            retest_status=retest_status,
        ))
    return render_findings_csv(snapshots)
