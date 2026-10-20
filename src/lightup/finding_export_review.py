"""Scriptless PRIVATE HUMAN review view of an already authorized tenant CSV.

The canonical authenticated tenant export is the sole input. This module does
not open a database, authenticate sessions, claim verified fixes or send data.
"""
from __future__ import annotations

from collections import Counter
import csv
from dataclasses import dataclass
import hashlib
from html import escape
import io
import json

from .domain import AccessContext, DomainStore
from .finding_export_service import render_client_findings_csv
from .models import RetestStatus, Severity

_HEADER = ("finding_id", "title", "severity", "retest_status", "remediation")
_MAX_ROWS = 128
_SEVERITIES = tuple(member.value for member in Severity)
_RETESTS = tuple(member.value for member in RetestStatus)
_HOLD = (
    "PRIVATE HUMAN REVIEW ONLY. Reported statuses are not independently "
    "verified remediations, authenticated evidence, client consent, or "
    "authority to scan or deploy. Free text may contain sensitive data."
)


@dataclass(frozen=True, slots=True)
class PrivateFindingReview:
    """Two sensitive, byte-bound representations of one tenant selection."""

    csv_text: str
    html_text: str
    summary_json: str
    csv_sha256: str
    finding_count: int


def _admit_export(csv_text: str) -> tuple[list[tuple[str, ...]], str]:
    """Admit only the full exact native five-column guarded CSV envelope."""
    if type(csv_text) is not str:
        raise ValueError("canonical exported CSV text required")
    raw = csv_text.encode("utf-8", "strict")
    # Source guard limits finding source text to 256 KiB, plus fixed CSV framing.
    if len(raw) > 300_000:
        raise ValueError("private CSV exceeds bounded review envelope")
    records = list(csv.reader(io.StringIO(csv_text, newline=""), strict=True))
    if not records or tuple(records[0]) != _HEADER:
        raise ValueError("unexpected private finding CSV columns")
    rows = [tuple(row) for row in records[1:]]
    if len(rows) > _MAX_ROWS or any(len(row) != len(_HEADER) for row in rows):
        raise ValueError("invalid PRIVATE finding row count or shape")
    if any(row[2] not in _SEVERITIES or row[3] not in _RETESTS for row in rows):
        raise ValueError("invalid exported finding status")
    return rows, hashlib.sha256(raw).hexdigest()


def _table(rows: list[tuple[str, ...]]) -> str:
    headings = ("Finding ID", "Reported title", "Reported severity",
                "Reported retest stage (unverified)", "Proposed remediation")
    cells = ["<table><caption>Private source-selected findings; HUMAN review only</caption>",
             "<thead><tr>"]
    cells.extend("<th scope=\"col\">" + escape(label) + "</th>" for label in headings)
    cells.extend(("</tr></thead><tbody>",))
    for row in rows:
        cells.append("<tr>")
        for value in row:
            cells.append("<td dir=\"auto\">" + escape(value, quote=True) + "</td>")
        cells.append("</tr>")
    cells.append("</tbody></table>")
    return "".join(cells)


def _summary(rows: list[tuple[str, ...]], digest: str) -> str:
    """PRIVATE machine-readable statistics; never data-free or anonymized."""
    severities = Counter(row[2] for row in rows)
    stages = Counter(row[3] for row in rows)
    return json.dumps({
        "schema": "lightup.private.finding-review.v1",
        "classification": "PRIVATE_HUMAN_REVIEW_ONLY",
        "finding_count": len(rows),
        "original_csv_sha256": digest,
        "reported_severity_counts": {
            value: severities[value] for value in _SEVERITIES
        },
        "reported_retest_stage_counts": {
            value: stages[value] for value in _RETESTS
        },
        "source_authenticated": False,
        "client_consent_verified": False,
        "remediation_verified": False,
        "release_approved": False,
    }, ensure_ascii=False, sort_keys=True, indent=2) + "\n"


def _render(rows: list[tuple[str, ...]], digest: str) -> str:
    severity_counts = Counter(row[2] for row in rows)
    stage_counts = Counter(row[3] for row in rows)
    summary = [
        "<!doctype html><html lang=\"en\"><head><meta charset=\"utf-8\">",
        "<meta name=\"referrer\" content=\"no-referrer\">",
        "<meta http-equiv=\"Content-Security-Policy\" ",
        "content=\"default-src 'none'; base-uri 'none'; form-action 'none'; ",
        "connect-src 'none'; img-src 'none'; object-src 'none'\">",
        "<title>PRIVATE Finding Review | LightUp</title></head><body>",
        "<main><h1>PRIVATE finding review</h1>",
        "<p role=\"status\">", escape(_HOLD), "</p>",
        "<p>Count: ", str(len(rows)), " (one authenticated tenant selection). ",
        "This view contains only the fields of the guarded CSV; never raw evidence or targets.</p>",
        "<h2>Reported severity</h2><ul>",
    ]
    for value in _SEVERITIES:
        summary.extend(("<li>", escape(value), ": ", str(severity_counts[value]), "</li>"))
    summary.extend(("</ul><h2>Reported retest stage (not verified)</h2><ul>",))
    for value in _RETESTS:
        summary.extend(("<li>", escape(value), ": ", str(stage_counts[value]), "</li>"))
    summary.extend(("</ul>", _table(rows) if rows else
                    "<p>No exported findings in this authorized selection.</p>",
                    "<h2>Local representation binding</h2><p>SHA-256 of the original ",
                    "UTF-8 CSV bytes: <code>", escape(digest), "</code></p>",
                    "<p>SHA-256 here detects local representation drift only: ",
                    "it is not a signature, source authentication, review approval, ",
                    "security claim or consent.</p></main></body></html>"))
    return "".join(summary)


def render_client_findings_review(
    store: DomainStore,
    ctx: AccessContext,
    client_id: str,
    *,
    engagement_id: str | None = None,
) -> PrivateFindingReview:
    """Build source-identical CSV + offline, scriptless HUMAN view atomically.

    Original authenticated selection and full batch Unicode/byte preflight are
    mandatory. No part of either representation is returned if admission fails.
    Caller must save both privately, if at all, and authorize disclosure.
    """
    csv_text = render_client_findings_csv(
        store, ctx, client_id, engagement_id=engagement_id)
    rows, digest = _admit_export(csv_text)
    html_text = _render(rows, digest)
    return PrivateFindingReview(csv_text, html_text, _summary(rows, digest),
                                digest, len(rows))
