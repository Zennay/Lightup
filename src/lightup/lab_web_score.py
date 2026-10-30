"""End-to-end labeval scoring for the HTTP security-header baseline worker.

The scorer owns two temporary HTTP fixtures on IPv4 loopback: one deliberately
weak response and one hardened control. Four observations run through the real
ToolExecutor and durable evidence ledger; no caller-selected target is accepted.
"""

from __future__ import annotations

import argparse
import json
import threading
import time
from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from .lab_socket_guard import PrivateLabArgumentParser, fixed_loopback_socket_boundary
from typing import Iterator

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
from .workers import http_baseline

LOOPBACK = "127.0.0.1"
SCENARIO_ID = "lab-web-baseline-security-headers-loopback"
ENGINE_VERSION = "m1-web-baseline"

# Hand-maintained ground truth stays independent from the worker's check table,
# so a worker regression cannot silently redefine what counts as correct.
EXPECTED_CHECKS: tuple[tuple[str, str, str], ...] = (
    (
        "missing-content-security-policy",
        "Missing Content-Security-Policy header",
        Severity.MEDIUM.value,
    ),
    (
        "missing-x-content-type-options",
        "Missing X-Content-Type-Options header",
        Severity.LOW.value,
    ),
    (
        "missing-x-frame-options",
        "Missing clickjacking protection",
        Severity.LOW.value,
    ),
    (
        "missing-referrer-policy",
        "Missing Referrer-Policy header",
        Severity.INFO.value,
    ),
    (
        "server-banner-disclosure",
        "Server software banner disclosed",
        Severity.INFO.value,
    ),
)


class _FixtureHandler(BaseHTTPRequestHandler):
    """Serve a fixed body and a class-declared set of response headers."""

    response_headers: tuple[tuple[str, str], ...] = ()
    server_version = "LightUpLabWeak/1.0"
    sys_version = ""
    body = b'{"fixture":"lightup-web-baseline","ok":true}\n'

    def version_string(self) -> str:
        return self.server_version

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.body)))
        for name, value in self.response_headers:
            self.send_header(name, value)
        self.end_headers()
        self.wfile.write(self.body)

    def log_message(self, _format: str, *_args: object) -> None:
        return


class _WeakHeadersHandler(_FixtureHandler):
    """Intentionally omits all four security headers and discloses a banner."""


class _HardenedHeadersHandler(_FixtureHandler):
    """Negative control with all expected security headers and no banner value."""

    response_headers = (
        ("Content-Security-Policy", "default-src 'self'; object-src 'none'; base-uri 'none'"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
    )

    def version_string(self) -> str:
        return ""


@contextmanager
def _serve(handler: type[BaseHTTPRequestHandler]) -> Iterator[tuple[str, str]]:
    """Serve a fixture on an OS-assigned IPv4 loopback port, then stop it."""
    server = ThreadingHTTPServer((LOOPBACK, 0), handler)
    server.daemon_threads = True
    thread = threading.Thread(
        target=server.serve_forever,
        kwargs={"poll_interval": 0.05},
        daemon=True,
    )
    thread.start()
    host, port = server.server_address[:2]
    try:
        if host != LOOPBACK:
            raise RuntimeError("HTTP scoring fixture did not bind exclusively to loopback")
        yield f"http://{host}:{port}/", host
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=3.0)
        if thread.is_alive():
            raise RuntimeError("HTTP scoring fixture did not stop cleanly")


def _issue_ids(result) -> tuple[str, ...]:
    metadata = dict(result.metadata)
    return tuple(item for item in metadata.get("issues", "").split(",") if item)


def _unprotected_run_lab_web_baseline_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Score the HTTP baseline against weak ground truth and a hardened control."""
    expected = tuple(
        ExpectedFinding(
            identifier=identifier,
            title=title,
            capability_id=http_baseline.CAPABILITY_ID,
            severity=severity,
        )
        for identifier, title, severity in EXPECTED_CHECKS
    )
    scenario = LabScenario(
        scenario_id=SCENARIO_ID,
        name="HTTP security-header baseline (owned loopback fixtures)",
        targets=(LOOPBACK,),
        expected_findings=expected,
    )
    state = StateStore(state_path)
    registry = ToolRegistry()
    http_baseline.register(registry)
    executor = ToolExecutor(registry, state)
    harness = LabEvaluationHarness(engine_version=ENGINE_VERSION)
    context = harness.start_run(scenario)

    with (
        _serve(_WeakHeadersHandler) as (weak_url, weak_host),
        _serve(_HardenedHeadersHandler) as (hardened_url, hardened_host),
    ):
        urls = (weak_url, weak_url, hardened_url, hardened_url)
        calls = tuple(
            ToolCall(
                tool_id=http_baseline.TOOL_ID,
                asset=LOOPBACK,
                arguments=(("url", url),),
            )
            for url in urls
        )
        started = time.monotonic()
        observations = tuple(executor.execute(context, call) for call in calls)
        runtime = round(time.monotonic() - started, 4)

    weak_first, weak_second, control_first, control_second = (
        _issue_ids(result) for result in observations
    )
    expected_ids = tuple(identifier for identifier, _title, _severity in EXPECTED_CHECKS)
    valid, invalid, missed = score_findings(expected, weak_first)
    # Any finding on either hardened-control observation is a false positive.
    invalid += len(control_first) + len(control_second)
    repeat_stable = weak_first == weak_second and control_first == control_second
    exact_weak_ground_truth = weak_first == expected_ids and weak_second == expected_ids
    control_clear = not control_first and not control_second

    evidence_ids = tuple(item.evidence_id for item in observations)
    evidence_rows = tuple(state.get_evidence(item) for item in evidence_ids)
    evidence_ok = len(set(evidence_ids)) == 4 and all(
        row.run_id == context.run_id
        and row.capability_id == http_baseline.CAPABILITY_ID
        and row.kind == "http-baseline-observation"
        and row.source == http_baseline.TOOL_ID
        and dict(row.metadata).get("is_lab") == "true"
        for row in evidence_rows
    )

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
            "Hand-maintained ground truth expects five findings on the deliberately "
            "weak loopback response and zero findings on the hardened control. "
            "Both fixtures bind only to 127.0.0.1; no external target is accepted."
        ),
        evidence_ids=evidence_ids,
    )
    record_id = state.add_lab_evaluation(record.to_dict())
    persisted = state.get_lab_evaluation(record_id)

    checks = {
        "fixtures_bound_to_ipv4_loopback": (
            weak_host == LOOPBACK
            and hardened_host == LOOPBACK
            and scenario.targets == (LOOPBACK,)
            and weak_url.startswith(f"http://{LOOPBACK}:")
            and hardened_url.startswith(f"http://{LOOPBACK}:")
        ),
        "weak_fixture_matches_hand_maintained_ground_truth": exact_weak_ground_truth,
        "hardened_control_has_no_findings": control_clear,
        "repeat_observations_match": repeat_stable,
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
        and score["valid_findings"] == len(EXPECTED_CHECKS)
        and score["invalid_findings"] == 0
        and score["missed_findings"] == 0
        and score["policy_violations"] == 0
        and score["reproducibility"] == 1.0
        and score["evidence_quality"] == 1.0
    )
    return {
        "passed": passed,
        "scenario_id": SCENARIO_ID,
        "run_id": context.run_id,
        "checks": checks,
        "evaluation_record_id": record_id,
        "evaluation": persisted,
    }



def run_lab_web_baseline_score(state_path: str | Path = "lightup-lab.db") -> dict:
    """Score one owned fixture with a strict in-process IPv4 loopback socket gate."""
    with fixed_loopback_socket_boundary():
        return _unprotected_run_lab_web_baseline_score(state_path)


def main(argv: list[str] | None = None) -> int:
    parser = PrivateLabArgumentParser(
        prog="lightup-lab-web-score",
        description="Score the HTTP security-header worker against owned loopback fixtures.",
    )
    parser.add_argument(
        "--db",
        default="lightup-lab.db",
        help="SQLite evidence/evaluation database path (default: lightup-lab.db)",
    )
    args = parser.parse_args(argv)
    try:
        result = run_lab_web_baseline_score(args.db)
    except (OSError, PermissionError, RuntimeError, ValueError):
        print(json.dumps({"passed": False, "error": "offline fixture denied or unavailable"}, indent=2))
        return 2
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["passed"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
