"""Dutch, privacy-minimal release-gate transition summary; never a release verdict."""
from __future__ import annotations

import sys

from scope_release_dependency_inventory_20261015 import GATES, MAX_BYTES, InvalidPacket
from scope_release_dependency_nl_20261015 import EXPLANATIONS, STATUS_NL
from scope_release_gate_transition_20261015 import compare
from scope_release_stdin_20261015 import read_bounded_stdin

LABELS = {
    "UNCHANGED": "Geen verandering in zelfrapportage",
    "NEW_BLOCKER": "Nieuw als geblokkeerd gemeld",
    "NEW_UNVERIFIED_CLAIM": "Nieuw uitsluitend zelf als aanwezig gemeld",
    "BLOCKER_REMOVED_UNVERIFIED": "Blokkademelding ingetrokken, nog steeds niet geverifieerd",
    "CLAIM_WITHDRAWN": "Eerdere zelfrapportage ingetrokken",
    "CLAIM_WITHDRAWN_AND_BLOCKED": "Zelfrapportage ingetrokken en als geblokkeerd gemeld",
}
HEADER = (
    "# LightUp scope-vergelijking: GEEN VRIJGAVE",
    "",
    "**Uitkomst: HOLD.** Vergelijking van twee zelfgerapporteerde, "
    "niet-geverifieerde snapshots. Geen toestemming om te scannen, "
    "grants uit te geven, acties uit te voeren, te mergen of te deployen.",
    "",
)


def summarize(raw: bytes) -> str:
    try:
        data = compare(raw)
    except InvalidPacket:
        data = None
    lines = list(HEADER)
    if data is None:
        lines.extend([
            "Het vergelijkingsbestand is ongeldig of onvolledig. "
            "Er is geen eerdere of huidige voortgang vastgesteld.",
            "",
            "## Controle nodig",
            "",
        ])
        for gate in GATES:
            lines.append(f"- **{EXPLANATIONS[gate][0]} — Niet controleerbaar:** "
                         "Geen betrouwbare status beschikbaar.")
    else:
        lines.extend([
            f"Vorige zelfgerapporteerde voorwaarden: {data['previous_self_reported']} van {len(GATES)}.",
            f"Huidige zelfgerapporteerde voorwaarden: {data['current_self_reported']} van {len(GATES)}.",
            "Zelfrapportage is geen onafhankelijke autorisatie of vrijgave.",
            "",
            "## Per voorwaarde",
            "",
        ])
        changes = {x["gate"]: x for x in data["changes"]}
        for gate in GATES:
            label = EXPLANATIONS[gate][0]
            if gate in changes:
                change = changes[gate]
                before = STATUS_NL[change["previous"]]
                after = STATUS_NL[change["current"]]
                reason = LABELS[change["transition"]]
                lines.append(f"- **{label}:** {before} → {after}. {reason}.")
            else:
                lines.append(f"- **{label}:** {LABELS['UNCHANGED']}; "
                             "afzonderlijk bewijs blijft vereist.")
    lines.extend([
        "",
        "## Besluit",
        "",
        "**Vrijgave: NEE.** Voor alle negen voorwaarden is werkelijk, "
        "onafhankelijk bewijs nodig. Het offline rapport verandert geen "
        "klanttoestemming, autorisatie, runtimegrens of deploymentstatus.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        report = summarize(read_bounded_stdin(MAX_BYTES))
    except OSError:
        report = summarize(b"")
    sys.stdout.write(report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
