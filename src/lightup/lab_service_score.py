"""End-to-end lab scoring for the TCP service-inventory capability.

The command owns its entire fixture: a temporary TCP listener and a closed-port
control are allocated on 127.0.0.1. The target is never caller-selectable, and
both observations run through ToolExecutor and the durable evidence ledger.
"""

from __future__ import annotations

import argparse
import json
import socket
import time
from pathlib import Path
from .lab_socket_guard import PrivateLabArgumentParser, fixed_loopback_socket_boundary

from .ai.orchestration import ToolCall, ToolExecutor, ToolRegistry
from .labeval import (
    EvaluationMetrics,
    ExpectedFinding,
    LabEvaluationHarness,
    LabScenario,
    score_findings,
)
from .models import Severity
from .state import StateStore
from .workers import service_inventory

LOOPBACK = "127.0.0.1"
SCENARIO_ID = "lab-service-inventory-loopback"
ENGINE_VERSION = "m1-service-inventory"


def _closed_control_port(excluded_port: int) -> int:
    """Return a currently closed loopback TCP port distinct from the listener."""
    for _ in range(32):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as candidate:
            candidate.bind((LOOPBACK, 0))
            port = int(candidate.getsockname()[1])
        if port == excluded_port:
            continue
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as probe:
            probe.settimeout(0.1)
            if probe.connect_ex((LOOPBACK, port)) != 0:
                return port
    raise RuntimeError("could not allocate a closed loopback control port")


def _open_ports(result) -> tuple[int, ...]:
    metadata = dict(result.metadata)
    raw = metadata.get("open_ports", "")
    return tuple(sorted(int(item) for item in raw.split(",") if item))


def _unprotected_run_lab_service_inventory_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Run two gated observations and persist their ground-truth score."""
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as listener:
        listener.bind((LOOPBACK, 0))
        listener.listen(8)
        open_port = int(listener.getsockname()[1])
        closed_port = _closed_control_port(open_port)

        scenario = LabScenario(
            scenario_id=SCENARIO_ID,
            name="TCP service inventory (owned loopback fixture)",
            targets=(LOOPBACK,),
            expected_findings=(
                ExpectedFinding(
                    identifier=f"tcp-port-open:{open_port}",
                    title="Known loopback listener accepts TCP connections",
                    capability_id=service_inventory.CAPABILITY_ID,
                    severity=Severity.INFO.value,
                ),
            ),
        )
        state = StateStore(state_path)
        registry = ToolRegistry()
        service_inventory.register(registry)
        executor = ToolExecutor(registry, state)
        harness = LabEvaluationHarness(engine_version=ENGINE_VERSION)
        context = harness.start_run(scenario)
        call = ToolCall(
            tool_id=service_inventory.TOOL_ID,
            asset=LOOPBACK,
            arguments=(("host", LOOPBACK), ("ports", f"{open_port},{closed_port}")),
        )

        started = time.monotonic()
        observations = (executor.execute(context, call), executor.execute(context, call))
        runtime = round(time.monotonic() - started, 4)

        first_ports = _open_ports(observations[0])
        second_ports = _open_ports(observations[1])
        found_ids = tuple(f"tcp-port-open:{port}" for port in first_ports)
        expected = scenario.expected_findings or ()
        valid, invalid, missed = score_findings(expected, found_ids)
        evidence_ids = tuple(item.evidence_id for item in observations)
        evidence_rows = tuple(state.get_evidence(item) for item in evidence_ids)
        evidence_ok = len(set(evidence_ids)) == 2 and all(
            row.run_id == context.run_id
            and row.capability_id == service_inventory.CAPABILITY_ID
            and row.kind == "service-inventory-observation"
            and row.source == service_inventory.TOOL_ID
            and dict(row.metadata).get("is_lab") == "true"
            for row in evidence_rows
        )
        repeat_stable = first_ports == second_ports

        metrics = EvaluationMetrics(
            valid_findings=valid,
            invalid_findings=invalid,
            missed_findings=missed,
            coverage_assessed=1,
            coverage_unknown=0,
            evidence_quality=1.0 if evidence_ok else 0.0,
            reproducibility=1.0 if repeat_stable else 0.0,
            scope_violations=0,
            policy_violations=0,
            human_interventions=0,
            tool_calls=len(observations),
            runtime_seconds=runtime,
        )
        record = harness.record(
            scenario,
            context,
            metrics,
            notes=(
                "Scored against an in-process loopback listener and a separately "
                "allocated closed-port control; two observations use the same "
                "lab run context."
            ),
            evidence_ids=evidence_ids,
        )
        record_id = state.add_lab_evaluation(record.to_dict())
        persisted = state.get_lab_evaluation(record_id)

        checks = {
            "known_open_port_detected": open_port in first_ports and open_port in second_ports,
            "closed_control_port_not_detected": closed_port not in first_ports
            and closed_port not in second_ports,
            "repeat_observation_matches": repeat_stable,
            "evidence_lineage_verified": evidence_ok,
            "persisted_record_readback": (
                persisted["record_id"] == record_id
                and persisted["run_id"] == context.run_id
                and persisted["evidence_ids"] == list(evidence_ids)
            ),
        }
        score = persisted["metrics"]
        passed = (
            all(checks.values())
            and score["valid_findings"] == 1
            and score["invalid_findings"] == 0
            and score["missed_findings"] == 0
            and score["reproducibility"] == 1.0
            and score["evidence_quality"] == 1.0
        )
        return {
            "passed": passed,
            "scenario_id": SCENARIO_ID,
            "run_id": context.run_id,
            "known_open_port": open_port,
            "closed_control_port": closed_port,
            "observed_open_ports": list(first_ports),
            "repeat_observed_open_ports": list(second_ports),
            "checks": checks,
            "evaluation_record_id": record_id,
            "evaluation": persisted,
        }



def run_lab_service_inventory_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Score one owned fixture with a strict in-process IPv4 loopback socket gate."""
    with fixed_loopback_socket_boundary():
        return _unprotected_run_lab_service_inventory_score(state_path)


def main(argv: list[str] | None = None) -> int:
    parser = PrivateLabArgumentParser(
        prog="lightup-lab-service-score",
        description="Score the service-inventory worker against an owned loopback fixture.",
    )
    parser.add_argument(
        "--db",
        default="lightup-lab.db",
        help="SQLite evidence/evaluation database path (default: lightup-lab.db)",
    )
    args = parser.parse_args(argv)
    try:
        result = run_lab_service_inventory_score(args.db)
    except (OSError, PermissionError, RuntimeError, ValueError):
        print(json.dumps({"passed": False, "error": "offline fixture denied or unavailable"}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
