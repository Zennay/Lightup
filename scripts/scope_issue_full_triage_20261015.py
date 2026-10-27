"""Dutch HOLD-only LightUp parallel-worker conflict report with rename support."""
from __future__ import annotations

import sys

from scope_issue_ownership_audit_20261015 import MAX_INPUT, InvalidSnapshot
from scope_issue_ownership_report_20261015 import _safe_path
from scope_issue_rename_footprints_20261015 import rename_footprints


def render_report(blob: bytes) -> str:
    result = rename_footprints(blob)
    if (result.get("status") != "HOLD"
            or any(result.get(name) is not False for name in (
                "can_authorize", "can_scan", "can_merge", "can_deploy", "can_release"))
            or result.get("candidate_list_suppressed") is not True):
        raise InvalidSnapshot("noncanonical non-authorizing review")
    lines = [
        "# LightUp — scope-authorization werkconflicten",
        "",
        "**Status: HOLD — uitsluitend offline advies. Geen toestemming, scan of release.**",
        "",
        "Dekking van deze lokale momentopname: " + result["file_change_coverage"],
        "**Dit is niet geverifieerd tegen actuele GitHub, Notion of actieve workers.**",
        "",
    ]
    if result["file_change_coverage"] != "SELF_ASSERTED_COMPLETE_UNVERIFIED":
        lines.extend([
            "**WAARSCHUWING: niet alle PR-bestanden of wijzigingen zijn aangetoond.**",
            "Er kunnen ontbrekende conflicten zijn; neem geen werk over op basis van dit overzicht.",
            "",
        ])
    groups = result["observed_conflict_groups"]
    if not groups:
        lines.extend([
            "## Er zijn geen exact overlappende PR's waargenomen",
            "",
            "Dit bewijst niet dat een issue, branch of bestand vrij is.",
            "",
        ])
    else:
        lines.extend(["## Conflicten die menselijke afstemming vereisen", ""])
        for idx, group in enumerate(groups, 1):
            prs = ", ".join(f"#{pr}" for pr in group["prs"])
            lines.extend([f"### Groep {idx}: PR {prs}", "",
                          f"- Soort conflict: {group['review_priority']}."])
            for issue in group["duplicate_issues"]:
                lines.append(f"- Dubbel geclaimd issue: #{issue}")
            for filename in group["colliding_paths"]:
                lines.append(f"- Gedeeld of hernoemd bestandspad: `{_safe_path(filename)}`")
            lines.append("")
    lines.extend([
        "## Vereiste vervolgcontrole",
        "",
        "- Bekijk elke genoemde PR en gewijzigde bestandsnaam opnieuw op live GitHub.",
        "- Controleer de actuele Notion-werkverdeling en eventuele niet-vermelde workers.",
        "- Vraag de bronhouder om afstemming; geen automatische eigenaarsoverdracht.",
        "- Geen merge, deploy, operatorgrant, klantinteractie of security-goedgekeurde run.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        report = render_report(sys.stdin.buffer.read(MAX_INPUT + 1))
    except (InvalidSnapshot, ValueError, KeyError, TypeError, OSError, RecursionError):
        report = "# LightUp — scope-authorization\n\n**HOLD — ongeldige of niet te vertrouwen invoer.**\n"
    sys.stdout.write(report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
