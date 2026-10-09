"""Lab-only TLS baseline worker.

Third capability worker (capability ``cryptography``): opens one TLS
connection to an isolated lab endpoint and evaluates transport security —
protocol version, cipher strength and whether the certificate chain verifies
against the system trust store. No application data is sent.

Same defense in depth as the other workers: only reachable through the
ToolExecutor's LAB_ACTIVE boundary, plus an independent
:func:`lightup.labeval.assert_lab_target` check before any socket is opened.
"""

from __future__ import annotations

import json
import socket
import ssl
import warnings
from dataclasses import dataclass
from typing import Any

from ..ai.orchestration import (
    ParamKind,
    RunContext,
    ToolDefinition,
    ToolOutput,
    ToolParameter,
    ToolRegistry,
)
from ..engagements import RiskLevel
from ..execution_policy import InteractionKind
from ..labeval import LabIsolationError, assert_lab_target
from ..models import Severity

TOOL_ID = "lab-tls-baseline"
CAPABILITY_ID = "cryptography"

# check_id -> (title, severity, impact, remediation)
TLS_CHECKS: dict[str, tuple[str, Severity, str, str]] = {
    "legacy-tls-protocol": (
        "Legacy TLS protocol accepted",
        Severity.MEDIUM,
        "Connections can be downgraded to protocol versions with known weaknesses.",
        "Disable TLS 1.0/1.1; require TLS 1.2 or newer.",
    ),
    "untrusted-certificate-chain": (
        "Certificate chain not trusted",
        Severity.MEDIUM,
        "Clients cannot distinguish the real endpoint from an impostor, "
        "normalizing certificate warnings.",
        "Serve a certificate from a trusted CA (or the internal CA that "
        "clients are provisioned with) covering the exact hostname.",
    ),
    "weak-cipher-suite": (
        "Weak cipher suite negotiated",
        Severity.LOW,
        "The negotiated cipher offers reduced resistance against recorded-"
        "traffic attacks.",
        "Restrict the server cipher list to AEAD suites (AES-GCM/ChaCha20).",
    ),
}

_WEAK_CIPHER_MARKERS = ("RC4", "3DES", "DES", "NULL", "EXPORT", "MD5", "CBC")


@dataclass(frozen=True)
class TlsIssue:
    check_id: str
    title: str
    severity: Severity
    impact: str
    remediation: str


@dataclass(frozen=True)
class TlsObservation:
    host: str
    port: int
    protocol: str
    cipher: str
    chain_trusted: bool
    issues: tuple[TlsIssue, ...]

    def to_json(self) -> str:
        return json.dumps(
            {"host": self.host, "port": self.port, "protocol": self.protocol,
             "cipher": self.cipher, "chain_trusted": self.chain_trusted,
             "issues": [issue.check_id for issue in self.issues]},
            sort_keys=True,
        )


def _issue(check_id: str) -> TlsIssue:
    title, severity, impact, remediation = TLS_CHECKS[check_id]
    return TlsIssue(check_id, title, severity, impact, remediation)


def observe(host: str, port: int, timeout: float = 5.0) -> TlsObservation:
    """Handshake once with a lab endpoint and evaluate transport security."""
    lab_host = assert_lab_target(host)
    if not 1 <= port <= 65535:
        raise ValueError(f"port {port} out of range")

    # Permissive handshake first: labs run self-signed fixtures, and we need
    # the negotiated protocol/cipher even when the chain does not verify.
    permissive = ssl.create_default_context()
    permissive.check_hostname = False
    permissive.verify_mode = ssl.CERT_NONE
    with warnings.catch_warnings():
        # Deliberate: accept legacy protocols so they can be observed and flagged.
        warnings.simplefilter("ignore", DeprecationWarning)
        permissive.minimum_version = ssl.TLSVersion.TLSv1  # observe, then judge
    with socket.create_connection((lab_host, port), timeout=timeout) as raw:
        with permissive.wrap_socket(raw, server_hostname=lab_host) as tls:
            protocol = tls.version() or "unknown"
            cipher_info = tls.cipher()
            cipher = cipher_info[0] if cipher_info else "unknown"

    # Second handshake with real verification to judge chain trust.
    strict = ssl.create_default_context()
    chain_trusted = True
    try:
        with socket.create_connection((lab_host, port), timeout=timeout) as raw:
            with strict.wrap_socket(raw, server_hostname=lab_host):
                pass
    except (ssl.SSLError, OSError):
        chain_trusted = False

    issues: list[TlsIssue] = []
    if protocol in {"TLSv1", "TLSv1.1", "SSLv3"}:
        issues.append(_issue("legacy-tls-protocol"))
    if not chain_trusted:
        issues.append(_issue("untrusted-certificate-chain"))
    if any(marker in cipher.upper() for marker in _WEAK_CIPHER_MARKERS):
        issues.append(_issue("weak-cipher-suite"))

    return TlsObservation(host=lab_host, port=port, protocol=protocol,
                          cipher=cipher, chain_trusted=chain_trusted,
                          issues=tuple(issues))


def run_tls_baseline(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    if not context.is_lab:
        raise LabIsolationError("the TLS baseline worker only runs in lab contexts")
    observation = observe(str(arguments["host"]), int(arguments["port"]))
    found = ", ".join(i.check_id for i in observation.issues) or "none"
    return ToolOutput(
        summary=(f"TLS baseline on {observation.host}:{observation.port}: "
                 f"{observation.protocol}/{observation.cipher}, issues: {found}"),
        evidence_kind="tls-baseline-observation",
        evidence_payload=observation.to_json().encode("utf-8"),
        metadata=(
            ("protocol", observation.protocol),
            ("cipher", observation.cipher),
            ("issues", ",".join(i.check_id for i in observation.issues)),
        ),
    )


TLS_BASELINE_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Single TLS handshake against an isolated lab endpoint; "
                "evaluates protocol version, cipher and chain trust.",
    parameters=(
        ToolParameter("host", ParamKind.STRING, required=True,
                      description="Lab host (loopback/private)"),
        ToolParameter("port", ParamKind.INTEGER, required=True,
                      description="TLS port on the lab host"),
    ),
)


def register(registry: ToolRegistry) -> None:
    registry.register(TLS_BASELINE_TOOL, run_tls_baseline)
