from __future__ import annotations

import re
from dataclasses import dataclass
from enum import Enum


class CapabilityState(str, Enum):
    PLANNING = "planning"
    LAB_ONLY = "lab_only"
    DISABLED = "disabled"


_CAPABILITY_ID_PATTERN = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*")


@dataclass(frozen=True)
class Capability:
    capability_id: str
    name: str
    description: str
    state: CapabilityState
    requires_explicit_activation: bool = True

    def __post_init__(self) -> None:
        if type(self.capability_id) is not str or not _CAPABILITY_ID_PATTERN.fullmatch(
            self.capability_id
        ):
            raise ValueError(
                "capability_id must be a canonical lowercase kebab-case string"
            )
        if type(self.name) is not str or not self.name.strip():
            raise ValueError("capability name must be a non-empty string")
        if type(self.description) is not str or not self.description.strip():
            raise ValueError("capability description must be a non-empty string")
        if type(self.state) is not CapabilityState:
            raise ValueError("capability state must be a CapabilityState member")
        if type(self.requires_explicit_activation) is not bool:
            raise ValueError("requires_explicit_activation must be an exact bool")


def _validate_registry(registry: tuple[Capability, ...]) -> None:
    seen_ids: set[str] = set()
    for capability in registry:
        if type(capability) is not Capability:
            raise ValueError("capability registry may contain only Capability records")
        if capability.capability_id in seen_ids:
            raise ValueError(
                f"duplicate capability id in registry: {capability.capability_id}"
            )
        seen_ids.add(capability.capability_id)


# High-level registry only. No exploit payloads or active target logic live here.
# Existing capability IDs are preserved for compatibility with the M0 state/tests.
REGISTRY: tuple[Capability, ...] = (
    Capability("external-attack-surface", "External attack surface", "Public asset and exposure mapping", CapabilityState.PLANNING),
    Capability("web-baseline", "Web applications", "HTTP/TLS/configuration and application-control assessment", CapabilityState.PLANNING),
    Capability("api-baseline", "APIs", "API exposure, authorization and security-control assessment", CapabilityState.PLANNING),
    Capability("identity-access", "Identity & access", "Authentication, federation and privilege-boundary review", CapabilityState.PLANNING),
    Capability("cloud-iam", "Cloud & IAM", "Cloud configuration and privilege-boundary review", CapabilityState.PLANNING),
    Capability("network-services", "Networks & services", "Authorized service inventory, segmentation and configuration review", CapabilityState.PLANNING),
    Capability("host-hardening", "Host hardening", "OS/service configuration and patch-posture assessment", CapabilityState.PLANNING),
    Capability("containers", "Containers", "Container/image/runtime hardening assessment", CapabilityState.PLANNING),
    Capability("containers-kubernetes", "Kubernetes", "Cluster, workload identity, RBAC and configuration assessment", CapabilityState.PLANNING),
    Capability("cicd", "CI/CD", "Pipeline, deployment credential and artifact-trust assessment", CapabilityState.PLANNING),
    Capability("supply-chain", "Software supply chain", "Dependencies, SBOM, build inputs and third-party component review", CapabilityState.PLANNING),
    Capability("mobile", "Mobile applications", "Mobile storage, transport, authentication and platform-control assessment", CapabilityState.PLANNING),
    Capability("desktop-client", "Desktop clients", "Local storage, update, IPC, privilege and backend-trust assessment", CapabilityState.PLANNING),
    Capability("email-domain", "Email & domains", "Domain, mail-security and spoofing-resistance posture", CapabilityState.PLANNING),
    Capability("secrets", "Secrets", "Secret-handling and accidental exposure assessment", CapabilityState.PLANNING),
    Capability("database-storage", "Databases & storage", "Access control, encryption, backup and exposure assessment", CapabilityState.PLANNING),
    Capability("saas-third-party", "SaaS & third parties", "OAuth grants, integrations, webhooks and trust-boundary review", CapabilityState.PLANNING),
    Capability("business-logic", "Business logic", "Workflow, approval, billing and role-transition abuse review", CapabilityState.PLANNING),
    Capability("abuse-fraud", "Abuse & fraud resistance", "Automation, enumeration, resource-abuse and anti-abuse review", CapabilityState.PLANNING),
    Capability("multi-tenancy", "Multi-tenancy", "Cross-tenant data and function isolation assessment", CapabilityState.PLANNING),
    Capability("logging-detection", "Logging & detection", "Security telemetry, alerting and auditability review", CapabilityState.PLANNING),
    Capability("backup-recovery", "Backup & recovery", "Restore controls, recoverability and resilience assessment", CapabilityState.PLANNING),
    Capability("cryptography", "Cryptography", "Key handling, TLS, randomness and certificate lifecycle review", CapabilityState.PLANNING),
    Capability("privacy-data", "Privacy & data exposure", "Sensitive-data handling, exposure and retention assessment", CapabilityState.PLANNING),
    Capability("ai-llm", "AI/LLM systems", "Prompt, tool permission, data-leakage and AI supply-chain review", CapabilityState.PLANNING),
    Capability("iot-embedded", "IoT & embedded", "Firmware, device identity, update and backend-trust assessment", CapabilityState.PLANNING),
    Capability("ot-lab", "OT/industrial lab", "Specialist control-system assessment in isolated environments", CapabilityState.LAB_ONLY),
    Capability("wireless-lab", "Wireless lab", "Isolated wireless-security simulation", CapabilityState.LAB_ONLY),
    Capability("social-engineering-lab", "Social engineering lab", "Explicitly scoped human-layer simulation", CapabilityState.LAB_ONLY),
    Capability("human-layer-lab", "Human-layer lab", "Non-production security-awareness simulation", CapabilityState.LAB_ONLY),
    Capability("physical-security-lab", "Physical integrations lab", "Isolated access-control and device-integration assessment", CapabilityState.LAB_ONLY),
)

_validate_registry(REGISTRY)


def get_capabilities() -> tuple[Capability, ...]:
    _validate_registry(REGISTRY)
    return REGISTRY
