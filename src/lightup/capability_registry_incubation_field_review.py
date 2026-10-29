"""Non-authorizing field-level diagnostics for the reviewed M3/M7 capability catalog.

The expected human-readable fields are a static code-reviewed reference, not
obtained from the candidate. Receipts never expose either old/new free text.
This is not signed Git provenance or an executor permission decision.
"""
from __future__ import annotations

from dataclasses import dataclass

from .capability_registry_drift_review import _decode_manifest
from .capability_registry_incubation_catalog_review import review_incubation_catalog

# Deliberately independent reviewed semantic labels as of main
# 9616afe1e174f4f3c71e6b749ad194d92a404f45. Updating this mapping
# and its sibling full-catalog fingerprint requires explicit source review.
_EXPECTED_FIELDS: dict[str, tuple[str, str]] = {
    "abuse-fraud": ("Abuse & fraud resistance", "Automation, enumeration, resource-abuse and anti-abuse review"),
    "ai-llm": ("AI/LLM systems", "Prompt, tool permission, data-leakage and AI supply-chain review"),
    "api-baseline": ("APIs", "API exposure, authorization and security-control assessment"),
    "backup-recovery": ("Backup & recovery", "Restore controls, recoverability and resilience assessment"),
    "business-logic": ("Business logic", "Workflow, approval, billing and role-transition abuse review"),
    "cicd": ("CI/CD", "Pipeline, deployment credential and artifact-trust assessment"),
    "cloud-iam": ("Cloud & IAM", "Cloud configuration and privilege-boundary review"),
    "containers": ("Containers", "Container/image/runtime hardening assessment"),
    "containers-kubernetes": ("Kubernetes", "Cluster, workload identity, RBAC and configuration assessment"),
    "cryptography": ("Cryptography", "Key handling, TLS, randomness and certificate lifecycle review"),
    "database-storage": ("Databases & storage", "Access control, encryption, backup and exposure assessment"),
    "desktop-client": ("Desktop clients", "Local storage, update, IPC, privilege and backend-trust assessment"),
    "email-domain": ("Email & domains", "Domain, mail-security and spoofing-resistance posture"),
    "external-attack-surface": ("External attack surface", "Public asset and exposure mapping"),
    "host-hardening": ("Host hardening", "OS/service configuration and patch-posture assessment"),
    "human-layer-lab": ("Human-layer lab", "Non-production security-awareness simulation"),
    "identity-access": ("Identity & access", "Authentication, federation and privilege-boundary review"),
    "iot-embedded": ("IoT & embedded", "Firmware, device identity, update and backend-trust assessment"),
    "logging-detection": ("Logging & detection", "Security telemetry, alerting and auditability review"),
    "mobile": ("Mobile applications", "Mobile storage, transport, authentication and platform-control assessment"),
    "multi-tenancy": ("Multi-tenancy", "Cross-tenant data and function isolation assessment"),
    "network-services": ("Networks & services", "Authorized service inventory, segmentation and configuration review"),
    "ot-lab": ("OT/industrial lab", "Specialist control-system assessment in isolated environments"),
    "physical-security-lab": ("Physical integrations lab", "Isolated access-control and device-integration assessment"),
    "privacy-data": ("Privacy & data exposure", "Sensitive-data handling, exposure and retention assessment"),
    "saas-third-party": ("SaaS & third parties", "OAuth grants, integrations, webhooks and trust-boundary review"),
    "secrets": ("Secrets", "Secret-handling and accidental exposure assessment"),
    "social-engineering-lab": ("Social engineering lab", "Explicitly scoped human-layer simulation"),
    "supply-chain": ("Software supply chain", "Dependencies, SBOM, build inputs and third-party component review"),
    "web-baseline": ("Web applications", "HTTP/TLS/configuration and application-control assessment"),
    "wireless-lab": ("Wireless lab", "Isolated wireless-security simulation"),
}


@dataclass(frozen=True)
class IncubationFieldReview:
    status: str
    reason: str
    changed_fields: tuple[tuple[str, tuple[str, ...]], ...]
    catalog_fingerprint: str | None
    authorization_verified: bool = False
    permit_issued: bool = False
    execution_enabled: bool = False
    merge_approved: bool = False
    release_approved: bool = False

    def as_dict(self) -> dict[str, object]:
        return {
            "status": self.status,
            "reason": self.reason,
            "changed_fields": {
                ident: list(fields) for ident, fields in self.changed_fields
            },
            "catalog_fingerprint": self.catalog_fingerprint,
            "authorization_verified": False,
            "permit_issued": False,
            "execution_enabled": False,
            "merge_approved": False,
            "release_approved": False,
        }


def review_incubation_fields(raw: bytes) -> IncubationFieldReview:
    """Fail closed; semantic details never turn HOLD into authorization."""
    parent = review_incubation_catalog(raw)
    if parent.status == "HOLD" and parent.reason != "semantic_metadata_differs_from_reviewed_reference":
        return IncubationFieldReview("HOLD", "invalid_or_changed_catalog_boundary", (), None)
    if parent.status not in ("HOLD", "REVIEW_ONLY"):
        return IncubationFieldReview("HOLD", "invalid_or_changed_catalog_boundary", (), None)
    try:
        records = _decode_manifest(raw)
    except (TypeError, ValueError, RecursionError, OverflowError):
        return IncubationFieldReview("HOLD", "invalid_or_changed_catalog_boundary", (), None)
    # Never trust a mismatched ID set even if the external catalog reviewer
    # is edited or bypassed; no partial semantic field diagnosis is issued.
    if set(records) != set(_EXPECTED_FIELDS):
        return IncubationFieldReview("HOLD", "invalid_or_changed_catalog_boundary", (), None)
    differences: list[tuple[str, tuple[str, ...]]] = []
    for ident in sorted(_EXPECTED_FIELDS):
        _, _, name, description = records[ident]
        expected_name, expected_description = _EXPECTED_FIELDS[ident]
        labels = tuple(
            label for label, current, expected in (
                ("name", name, expected_name),
                ("description", description, expected_description),
            ) if current != expected
        )
        if labels:
            differences.append((ident, labels))
    # The full reviewed catalog pin includes state/activation too. Refuse
    # a contradictory parent status, not just the locally compared fields.
    if parent.status == "REVIEW_ONLY" and differences:
        return IncubationFieldReview("HOLD", "inconsistent_catalog_metadata", (), None)
    if parent.status == "HOLD" and not differences:
        return IncubationFieldReview("HOLD", "unexplained_semantic_metadata_drift", (), None)
    return IncubationFieldReview(
        "HOLD" if differences else "REVIEW_ONLY",
        "metadata_fields_require_review" if differences else "unchanged_reviewed_fields_only",
        tuple(differences),
        parent.metadata_fingerprint,
    )
