"""Privacy-minimal Dutch summary of *untrusted* LightUp release-gate claims."""
from __future__ import annotations

import sys
from scope_release_stdin_20261015 import read_bounded_stdin
from scope_release_dependency_inventory_20261015 import (
    GATES, MAX_BYTES, InvalidPacket, assess,
)

EXPLANATIONS = {
    "client_consent": ("Toestemming van de klant", "Toestemming voor het exacte doel ontbreekt of is niet onafhankelijk getoetst."),
    "asset_and_capability_scope": ("Toegestaan doel en handelingen", "De vastgelegde doelwitten, bevoegdheden en risico's zijn niet onafhankelijk bevestigd."),
    "live_grant_and_revocation": ("Actuele toestemming en intrekking", "De uitvoerder moet op het uitvoermoment de geldige toestemming en intrekking controleren."),
    "operator_step_up": ("Extra goedkeuring bij hoger risico", "Afzonderlijke geldige goedkeuring door een bevoegde operator moet aantoonbaar zijn."),
    "durable_prehandler_evidence": ("Bewijs vóór een actie", "De actie moet duurzaam traceerbaar zijn voordat de uitvoerhandler start."),
    "installed_ingress_and_egress": ("Echte server- en netwerkgrenzen", "Geïnstalleerde ingang en uitgaand netwerk moeten met onafhankelijke tests zijn afgeschermd."),
    "permanent_vps_ci": ("Tests op de echte VPS-runner", "Wachtrij of gehoste tests zijn geen bewijs van een uitgevoerde permanente VPS-run."),
    "independent_security_privacy_review": ("Onafhankelijke veiligheid- en privacycontrole", "Een afzonderlijke reviewer moet de totale keten beoordelen."),
    "explicit_human_release": ("Expliciet besluit door een mens", "Vrijgave vereist een afzonderlijk, expliciet menselijk besluit."),
}


def summarize(raw: bytes) -> str:
    try:
        result = assess(raw)
        invalid = False
    except InvalidPacket:
        result = None
        invalid = True
    lines = [
        "# LightUp scope-vrijgave: NIET TOEGESTAAN",
        "",
        "Status: HOLD. Deze beoordeling verleent geen toestemming om te scannen, acties te starten, grants uit te geven, te mergen of te deployen.",
        "",
    ]
    if invalid:
        lines.append("Het lokale checklistbestand is ongeldig of onvolledig. Alle negen voorwaarden moeten onafhankelijk worden gecontroleerd.")
    else:
        asserted = result["self_reported_count"]
        lines.append(f"Zelf ingevuld als aanwezig: {asserted} van {len(GATES)} voorwaarden. Zelfrapportage is geen verifieerbaar bewijs.")
    lines.extend(["", "## Voorwaarden die echte controle nodig hebben", ""])
    for gate in GATES:
        label, cause = EXPLANATIONS[gate]
        # Every gate is independently unverified, including self-reported ones.
        lines.append(f"- **{label}:** {cause}")
    lines.extend([
        "",
        "## Wat wel en niet kan",
        "",
        "Deze offline checklist controleert geen live toestemming, code, netwerk, logs of gebruikers. Zij helpt alleen om open afhankelijkheden te ordenen.",
        "**Vrijgave: NEE.** Eerst oorspronkelijke bronfouten herstellen, actuele CI- en VPS-uitvoering controleren, en afzonderlijk toestemming en menselijke goedkeuring verkrijgen.",
        "",
    ])
    return "\n".join(lines)


def main() -> int:
    try:
        raw = read_bounded_stdin(MAX_BYTES)
        report = summarize(raw)
    except OSError:
        report = summarize(b"")
    sys.stdout.write(report)
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
