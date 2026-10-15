"""Dutch user-facing HOLD-only summary of GitHub REST-shaped offline PR exports."""
from __future__ import annotations

import sys

from scope_issue_github_rest_import_20261015 import review
from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot
from scope_issue_ownership_report_20261015 import _safe_path

FLAGS = ("can_authorize", "can_scan", "can_merge", "can_deploy", "can_release")


def render(blob: bytes) -> str:
    result = review(blob)
    if (result.get("status") != "HOLD"
            or any(result.get(flag) is not False for flag in FLAGS)
            or result.get("candidate_list_suppressed") is not True
            or result.get("unclaimed_candidates_not_permission") != []):
        raise InvalidSnapshot("cannot display authorizing data")
    out = [
        "# LightUp — werkverdeling op basis van GitHub-export",
        "",
        "**Status: HOLD — uitsluitend intern advies, geen toestemming of werkoverdracht.**",
        "",
        "De invoer is een zelf aangeleverde, niet geauthenticeerde export.",
        "**De actuele GitHub-/Notion-eigenaar en PR-HEAD zijn niet geverifieerd.**",
        "",
    ]
    if not result["snapshot_complete_self_asserted"]:
        out.extend([
            "## WAARSCHUWING: export is aantoonbaar onvolledig",
            "",
            "Eén of meer issue-, PR- of bestandenpagina's of expliciete claimverklaringen ontbreken.",
            "Er kunnen onzichtbare actieve PR's en bestandsconflicten zijn.",
            "",
        ])
    else:
        out.extend([
            "## Interne volledigheid",
            "",
            "De aanleveraar verklaart de pagina's compleet, maar de bron is niet bevestigd.",
            "",
        ])
    if result["open_fork_prs_require_review"]:
        out.extend(["## Fork-PR's vereisen aparte eigenaarscontrole", ""])
        out.extend(f"- PR #{pr}: externe source-branch; niet automatisch overnemen."
                   for pr in result["open_fork_prs_require_review"])
        out.append("")
    if result["missing_claim_declarations"]:
        out.extend(["## Ontbrekende expliciete issueclaims", ""])
        out.extend(f"- PR #{pr}: claim niet aangeleverd; geen conclusie over beschikbaarheid."
                   for pr in result["missing_claim_declarations"])
        out.append("")
    groups = result["conflict_observations"]
    out.extend(["## Waargenomen overlap (geen volledige risicobeoordeling)", ""])
    if not groups:
        out.extend([
            "- Geen directe of transitieve overlap gezien binnen de geleverde records.",
            "- Dit betekent **niet** dat een issue, PR of bestand vrij is.",
            "",
        ])
    else:
        for idx, group in enumerate(groups, 1):
            prs = ", ".join(f"#{number}" for number in group["prs"])
            out.extend([f"### Conflictgroep {idx}: PR {prs}", ""])
            for issue in group["duplicate_issues"]:
                out.append(f"- Dubbele claim op issue #{issue}.")
            for path in group["colliding_paths"]:
                out.append(f"- Gezamenlijk gewijzigd of hernoemd pad: `{_safe_path(path)}`.")
            out.append("")
    out.extend([
        "## Verplichte vervolgstap",
        "",
        "- Controleer live GitHub PR's, alle pagina's en begin-/eind-HEAD opnieuw.",
        "- Bevestig expliciet actuele eigenaar, Notion-lane en actieve workers.",
        "- Neem geen bestaande branch over zonder de bronhouder.",
        "- Geen scan, echte operatorgrant, merge, deploy of productieactivatie.",
        "",
    ])
    return "\n".join(out)


def main() -> int:
    try:
        summary = render(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        summary = "# LightUp — scope-authorization\n\n**HOLD — ongeldige of onbetrouwbare GitHub-export.**\n"
    sys.stdout.write(summary)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
