"""Fixed non-authorizing remediation map for LightUp's nine release gates.

The catalog is planning guidance, not an attestation or a source of run
authority. Issue references are hand-off hints, never live issue status.
"""
from __future__ import annotations

from typing import NamedTuple

from scope_release_dependency_inventory_20261015 import GATES


class Remediation(NamedTuple):
    owner_role: str
    concrete_action: str
    acceptance_evidence: str
    reason_not_lifted: str
    owner_boundary: str


CATALOG: dict[str, Remediation] = {
    "client_consent": Remediation(
        "Klant of schriftelijk gemachtigde opdrachtgever",
        "Vraag afzonderlijke, actuele en doelgebonden toestemming aan de bevoegde partij.",
        "Gedateerde toestemming met exacte klant, doelen, looptijd en toegestane handelingen.",
        "Een zelf aangevinkte checklist is geen werkelijke toestemming.",
        "EXTERNAL_HUMAN"),
    "asset_and_capability_scope": Remediation(
        "Klant en onafhankelijke scopebeoordelaar",
        "Leg doelen, handelingen, risico's en tijdvenster exact vast en laat ze onafhankelijk bevestigen.",
        "Afzonderlijk bevestigde scope met exacte assets, capabilities, risicogrens en geldigheid.",
        "Een offline statusbericht bewijst geen concrete toegestane doelwitten.",
        "EXTERNAL_HUMAN"),
    "live_grant_and_revocation": Remediation(
        "Eigenaar van de geïnstalleerde scope-uitvoerder (#107)",
        "Herstel en bewijs actuele grant- en intrekkingscontrole direct vóór iedere doelgerichte uitvoering.",
        "Geïnstalleerde fail-closed test van actuele grant, intrekking, tenant, doel en racegrens.",
        "De originele runtimecontrole ligt bij een andere worker en is nog niet onafhankelijk aangetoond.",
        "OTHER_SOURCE_OWNER"),
    "operator_step_up": Remediation(
        "Scope-runtime-eigenaar en afzonderlijk bevoegde operator (#1172/#1173)",
        "Toets risico-5-acties met afzonderlijke operatorgoedkeuring die vlak vóór gebruik actueel blijft.",
        "Onafhankelijk vastgelegde operatoridentiteit, actuele stapgoedkeuring en bronregressie.",
        "Zelfrapportage kan de ontbrekende autorisatie of een intrekkingsrace niet repareren.",
        "OTHER_SOURCE_OWNER_AND_HUMAN"),
    "durable_prehandler_evidence": Remediation(
        "Eigenaar uitvoerder en bewijsopslag (#1454/#1455)",
        "Registreer duurzaam en atomair bewijs vóór iedere handlerstart; test opslagfouten.",
        "Geïnstalleerde test: geen handlerstart na mislukte bewijscommit, ook bij race en rollback.",
        "Een offline checklist beheert de echte SQLite-transactie of handler niet.",
        "OTHER_SOURCE_OWNER"),
    "installed_ingress_and_egress": Remediation(
        "Deploy-ops en onafhankelijke labnetwerkcontrole",
        "Controleer de werkelijk geïnstalleerde serveringang en uitgaande netwerkregels.",
        "Vastgelegde tests op de echte ingress, egress, loopback- en privéscopegrenzen.",
        "Configuratiesjablonen en losse proefresultaten bewijzen geen geïnstalleerde bescherming.",
        "OTHER_INFRA_OWNER"),
    "permanent_vps_ci": Remediation(
        "Beheerder permanente LightUp VPS-runner (#1144)",
        "Herstel runner-toewijzing en voer de volledige veiligheids-CI op de exacte commit uit.",
        "Geslaagde matrixjobs met aantoonbaar permanent runner-ID, SHA en originele logs.",
        "Wachtrij of alleen GitHub-hosted tests zijn niet hetzelfde als een VPS-uitvoering.",
        "OTHER_INFRA_OWNER"),
    "independent_security_privacy_review": Remediation(
        "Onafhankelijke security- en privacyreviewers",
        "Laat het totale bronpad, gegevensverwerking, toestemming en labisolatie los beoordelen.",
        "Gedocumenteerde bevindingen en afgesloten herstelpunten door onafhankelijke reviewers.",
        "De auteur of AI-worker kan de vereiste onafhankelijke toets niet zelf afgeven.",
        "EXTERNAL_REVIEWER"),
    "explicit_human_release": Remediation(
        "Bevoegde menselijke releaseverantwoordelijke",
        "Vraag pas na alle onafhankelijke bewijzen een expliciet releasebesluit.",
        "Afzonderlijk gedateerd menselijk GO met definitieve scope en bewezen controles.",
        "Een test, script of PR-status verleent nooit de vereiste menselijke GO.",
        "EXTERNAL_HUMAN"),
}


def remediation(gate: str) -> Remediation:
    """Only fixed exact gate identifiers; no user data interpolated."""
    if type(gate) is not str or gate not in CATALOG:
        raise ValueError("unknown release gate")
    return CATALOG[gate]


assert tuple(CATALOG) == GATES, "remediation map must match all nine scope gates"
