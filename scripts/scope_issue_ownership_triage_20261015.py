"""HOLD-only Dutch triage of transitive LightUp scope PR conflicts.

Reads a local, untrusted snapshot from stdin. No network, no owner assignment.
"""
from __future__ import annotations

import json
import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot, audit
from scope_issue_ownership_clusters_20261015 import conflict_groups
from scope_issue_ownership_report_20261015 import _safe_path, render


def triage(blob: bytes) -> str:
    audit_result = audit(blob)
    groups = conflict_groups(audit_result)
    base = render(audit_result)
    lines = [
        base.rstrip(),
        "",
        "## Samengevoegde conflictgroepen",
        "",
        "**Geen groep is ooit automatisch vrijgegeven.** Alleen binnen deze",
        "aangeleverde momentopname zijn exacte overlaprelaties vastgesteld.",
        "",
    ]
    if not groups["review_groups"]:
        lines.append("- Geen exact conflict binnen deze beperkte snapshot; actieve workers kunnen ontbreken.")
    else:
        for idx, group in enumerate(groups["review_groups"], 1):
            prs = ", ".join(f"#{n}" for n in group["prs"])
            lines.append(f"### Groep {idx} — PR {prs}")
            lines.append("")
            lines.append(f"- Conflictklasse: {group['review_priority']} (alleen triage).")
            lines.extend(f"- Dubbele issueclaim: #{n}" for n in group["duplicate_issues"])
            lines.extend(f"- Exact gedeeld bestand: \`{_safe_path(path)}\`" for path in group["colliding_paths"])
            lines.append("")
    lines.extend([
        "## Betrouwbaarheid van de momentopname",
        "",
        "- Dekking: **onbevestigd**; ontbrekende GitHub-pagina's of actieve branches zijn mogelijk.",
        "- Open issues zonder bekende PR-claim blijven **onbevestigde kandidaten**, geen vrije taken.",
        "- Controleer live PR-eigenaars, relevante Notion-lanes en actuele commits vóór wijziging.",
        "- Geen toestemming om te scannen, grants uit te geven, merges te doen of te deployen.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        report = triage(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, TypeError, OSError, KeyError, RecursionError):
        report = "# LightUp scope-authorization\n\n**HOLD — snapshot niet betrouwbaar.**\n"
    sys.stdout.write(report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
