"""Optional bounded legacy Finding evidence admission before Markdown rendering.

Does NOT alter Finding.validate, the default reporting entrypoint, client
authorization, historical stored evidence or Markdown escaping. This is an
uninstalled presentation integrity reference for source-owner issue #894.
"""
from __future__ import annotations

from .models import Finding, RetestStatus, Severity
from .reporting import render_markdown

_ERROR = "invalid legacy finding evidence integrity"
_MAX_FINDINGS = 128
_MAX_EVIDENCE_PER_FINDING = 128


def render_checked_findings_markdown(findings: object) -> str:
    """Validate all evidence before rendering; snapshot only displayed fields.

    Prevent malformed evidence containers/items from being rendered even when
    an invalid item occurs in the last finding. No in-place mutation, input
    coercion, target interaction or separate report write occurs here.
    """
    if type(findings) is not list or len(findings) > _MAX_FINDINGS:
        raise ValueError(_ERROR)
    snapshots: list[Finding] = []
    for finding in findings:
        if type(finding) is not Finding:
            raise ValueError(_ERROR)
        evidence = finding.evidence
        if type(evidence) is not list or len(evidence) > _MAX_EVIDENCE_PER_FINDING:
            raise ValueError(_ERROR)
        for ref in evidence:
            if type(ref) is not str or not ref.strip():
                raise ValueError(_ERROR)

        for field in ("finding_id", "title", "target", "remediation"):
            text = getattr(finding, field)
            if type(text) is not str or not text.strip():
                raise ValueError(_ERROR)
        if type(finding.severity) is not Severity:
            raise ValueError(_ERROR)
        if type(finding.retest_status) is not RetestStatus:
            raise ValueError(_ERROR)

        # Do not retain caller-mutable evidence/metadata and do not copy raw
        # unused finding metadata into the presentation boundary.
        snapshots.append(Finding(
            finding_id=finding.finding_id,
            title=finding.title,
            severity=finding.severity,
            target=finding.target,
            evidence=list(evidence),
            remediation=finding.remediation,
            retest_status=finding.retest_status,
        ))

    return render_markdown(snapshots)
