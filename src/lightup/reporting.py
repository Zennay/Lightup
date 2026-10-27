from __future__ import annotations

import html
import re

from .models import Finding


def _single_line(value: str) -> str:
    """Keep untrusted report metadata from creating new Markdown blocks."""
    return " ".join(value.splitlines())


def _plain_text(value: str) -> str:
    """Render untrusted text without allowing raw HTML through."""
    return html.escape(value, quote=False)


def _inline_code(value: str) -> str:
    """Wrap arbitrary single-line text in a Markdown code span safely."""
    value = _single_line(value)
    runs = re.findall(r"`+", value)
    fence = "`" * (max((len(run) for run in runs), default=0) + 1)
    if value.startswith("`") or value.endswith("`"):
        value = f" {value} "
    return f"{fence}{value}{fence}"


def render_markdown(findings: list[Finding]) -> str:
    lines = ["# LightUp Assessment Findings", ""]
    if not findings:
        lines.append("No findings recorded.")
        return "\n".join(lines) + "\n"

    for finding in findings:
        finding.validate()
        lines.extend(
            [
                f"## {_plain_text(_single_line(finding.title))}",
                f"- ID: {_inline_code(finding.finding_id)}",
                f"- Severity: **{finding.severity.value}**",
                f"- Target: {_inline_code(finding.target)}",
                f"- Retest: `{finding.retest_status.value}`",
                "",
                "### Evidence",
            ]
        )
        evidence = finding.evidence or ["No evidence recorded."]
        lines.extend(
            f"- {_plain_text(_single_line(item))}"
            for item in evidence
        )
        lines.extend(["", "### Remediation"])
        remediation_lines = finding.remediation.splitlines() or [""]
        lines.extend(f"> {_plain_text(line)}" for line in remediation_lines)
        lines.append("")
    return "\n".join(lines) + "\n"
