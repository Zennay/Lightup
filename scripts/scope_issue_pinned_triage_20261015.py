"""Conservative Dutch PR-ownership report requiring self-asserted head consistency.

This is an opt-in *offline* report, not a review approval or worker lock.
"""
from __future__ import annotations

import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot
from scope_issue_ownership_report_20261015 import _safe_path
from scope_issue_pr_head_consistency_20261015 import head_consistency

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def render_pinned(blob: bytes) -> str:
    result = head_consistency(blob)
    if (type(result) is not dict or result.get("status") != "HOLD"
            or any(result.get(flag) is not False for flag in FLAGS)
            or result.get("candidate_list_suppressed") is not True):
        raise InvalidSnapshot("noncanonical unsafe review")
    lines = [
        "# LightUp — PR-eigenaarschap en commitversies",
        "",
        "**HOLD — offline advies; geen toestemming, werkeigenaar of vrijgave.**",
        "",
        "Brondata en commit-SHA's zijn alleen door de aanleveraar opgegeven.",
        "Ze zijn **niet** geverifieerd op live GitHub of Notion.",
        "",
        "## Commitconsistentie per PR",
        "",
    ]
    states = result["pr_head_states"]
    if not states:
        lines.append("- Geen open PR's met aangetoonde head-evidentie.")
    else:
        explanations = {
            "SELF_ASSERTED_STABLE_UNVERIFIED": "Intern dezelfde commitversie; niet onafhankelijk geverifieerd",
            "HEAD_CHANGED_OR_MIXED_VERSIONS": "WAARSCHUWING: versie veranderd of verschillende commits gecombineerd",
            "INCOMPLETE_HEAD_PAGE_EVIDENCE": "WAARSCHUWING: ontbrekend paginabewijs",
            "MISSING_HEAD_EVIDENCE": "WAARSCHUWING: geen commitversie vastgelegd",
        }
        for row in states:
            status = row["head_state"]
            if status not in explanations:
                raise InvalidSnapshot("unexpected head state")
            lines.append(f"- PR #{row['pr']}: {explanations[status]}.")
    lines.extend(["", "## Conflicten uit deze momentopname", ""])
    if result["review_consistency"] != "SELF_ASSERTED_STABLE_UNVERIFIED":
        lines.extend([
            "**Geen betrouwbare conflictgroeplijst: gegevens zijn onvolledig of inconsistent.**",
            "Er kunnen actieve maar onzichtbare PR's en bestandsconflicten ontbreken.",
        ])
    elif not result["observed_conflict_groups"]:
        lines.extend([
            "- Geen exact conflict waargenomen in de *zelf opgegeven* dataset.",
            "- Dit bewijst niet dat een issue, branch of bestand beschikbaar is.",
        ])
    else:
        for i, group in enumerate(result["observed_conflict_groups"], 1):
            prs = ", ".join(f"#{pr}" for pr in group["prs"])
            lines.extend([f"### Groep {i}: PR {prs}", ""])
            for issue in group["duplicate_issues"]:
                lines.append(f"- Dubbele claim op issue #{issue}.")
            for path in group["colliding_paths"]:
                lines.append(f"- Gedeeld of hernoemd pad: `{_safe_path(path)}`.")
            lines.append("")
    lines.extend([
        "",
        "## Vervolgactie (alleen door verantwoordelijke bronhouder)",
        "",
        "- Controleer live GitHub HEAD van iedere PR opnieuw vóór en na paginering.",
        "- Controleer de actuele Notion-lane, branch en eventuele andere actieve workers.",
        "- Wijzig geen andermans bestanden zonder expliciete overdracht.",
        "- Geen scan, runtimegrant, merge, deployment of productieactivatie op basis van dit rapport.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        rendered = render_pinned(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        rendered = "# LightUp — PR-versiecontrole\n\n**HOLD — ongeldige of niet te vertrouwen invoer.**\n"
    sys.stdout.write(rendered)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
