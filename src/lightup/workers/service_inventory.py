"""Lab-only TCP service inventory worker.

Second capability worker (capability ``network-services``): checks which of an
explicit, bounded list of TCP ports accept connections on an isolated lab
host. No banners are read and no payloads are sent — connect, record, close.

Same defense in depth as the HTTP baseline: only reachable through the
ToolExecutor's LAB_ACTIVE boundary, plus an independent
:func:`lightup.labeval.assert_lab_target` check before any socket is opened.
"""

from __future__ import annotations

import json
import socket
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
from ..lab_context import require_lab_worker_context
from ..labeval import assert_lab_target

TOOL_ID = "lab-service-inventory"
CAPABILITY_ID = "network-services"
MAX_PORTS = 32


def parse_ports(spec: str) -> tuple[int, ...]:
    ports: list[int] = []
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        port = int(part)
        if not 1 <= port <= 65535:
            raise ValueError(f"port {port} out of range")
        if port not in ports:
            ports.append(port)
    if not ports:
        raise ValueError("at least one port is required")
    if len(ports) > MAX_PORTS:
        raise ValueError(f"at most {MAX_PORTS} ports per call")
    return tuple(ports)


def inventory(host: str, ports: tuple[int, ...], timeout: float = 0.5) -> dict[int, bool]:
    """Connect-check each port on an already-validated lab host."""
    lab_host = assert_lab_target(host)
    results: dict[int, bool] = {}
    for port in ports:
        try:
            with socket.create_connection((lab_host, port), timeout=timeout):
                results[port] = True
        except OSError:
            results[port] = False
    return results


def run_service_inventory(context: RunContext, arguments: dict[str, Any]) -> ToolOutput:
    require_lab_worker_context(context)
    host = str(arguments["host"])
    ports = parse_ports(str(arguments["ports"]))
    results = inventory(host, ports)
    open_ports = sorted(port for port, is_open in results.items() if is_open)
    return ToolOutput(
        summary=f"service inventory on {host}: open {open_ports or 'none'} "
                f"of {len(results)} checked",
        evidence_kind="service-inventory-observation",
        evidence_payload=json.dumps(
            {"host": host, "results": {str(p): v for p, v in sorted(results.items())}},
            sort_keys=True,
        ).encode("utf-8"),
        metadata=(
            ("open_ports", ",".join(str(p) for p in open_ports)),
            ("checked_ports", ",".join(str(p) for p in sorted(results))),
        ),
    )


SERVICE_INVENTORY_TOOL = ToolDefinition(
    tool_id=TOOL_ID,
    capability_id=CAPABILITY_ID,
    interaction=InteractionKind.LAB_ACTIVE,
    min_risk=RiskLevel.LOW_IMPACT,
    description="Connect-check an explicit, bounded list of TCP ports on an "
                "isolated lab host. No banners, no payloads.",
    parameters=(
        ToolParameter("host", ParamKind.STRING, required=True,
                      description="Lab host (loopback/private)"),
        ToolParameter("ports", ParamKind.STRING, required=True,
                      description=f"Comma-separated TCP ports (max {MAX_PORTS})"),
    ),
)


def register(registry: ToolRegistry) -> None:
    registry.register(SERVICE_INVENTORY_TOOL, run_service_inventory)
