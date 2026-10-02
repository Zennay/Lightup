"""End-to-end lab baseline run — the only executable assessment path in M1.

This wires the whole chain together against an isolated lab target:

```text
LabScenario (lab-only targets)
  -> LabEvaluationHarness.start_run (lab RunContext)
  -> ToolExecutor (policy gate)
  -> lab-http-baseline worker (loopback/private http only)
  -> evidence ledger (StateStore)
  -> findings (Finding -> Impact -> Fix -> Retest)
  -> EvaluationRecord (benchmark metrics)
```

Real targets are rejected before any connection is attempted.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

from urllib.parse import urlparse

from .ai.gateway import ModelGateway, ModelRole, ScriptedProvider
from .ai.orchestration import ToolCall, ToolExecutor, ToolRegistry
from .ai.planner import execute_plan, request_plan
from .coverage import CoverageReport, CoverageStatus
from .labeval import (
    EvaluationMetrics,
    ExpectedFinding,
    LabEvaluationHarness,
    LabScenario,
    score_findings,
)
from .models import Finding, RetestStatus
from .reporting import render_markdown
from .state import StateStore
from .workers import http_baseline, service_inventory, tls_baseline

# Unified check catalog across workers: check_id -> (title, severity, impact,
# remediation). Workers report found check ids in their result metadata.
CHECK_CATALOG = {
    check_id: (title, severity, impact, remediation)
    for check_id, _header, title, severity, impact, remediation
    in http_baseline.BASELINE_CHECKS
}
CHECK_CATALOG.update(tls_baseline.TLS_CHECKS)


def full_lab_registry() -> ToolRegistry:
    """All lab-only capability workers, registered on one registry."""
    registry = ToolRegistry()
    http_baseline.register(registry)
    service_inventory.register(registry)
    tls_baseline.register(registry)
    return registry

# Ground truth for the stock lab fixture (lab/http_fixture.py): it discloses a
# Server banner and sends none of the defensive headers.
FIXTURE_EXPECTED: tuple[ExpectedFinding, ...] = tuple(
    ExpectedFinding(check_id, title, http_baseline.CAPABILITY_ID, severity.value)
    for check_id, _header, title, severity, _impact, _remediation
    in http_baseline.BASELINE_CHECKS
)


def run_lab_baseline(
    url: str,
    state_path: str | Path,
    expected: tuple[ExpectedFinding, ...] = (),
    engine_version: str = "m1-dev",
) -> dict:
    """Run the HTTP baseline against one lab URL and return a full result dict."""
    scenario = LabScenario(
        scenario_id="lab-http-baseline",
        name="HTTP security-header baseline (isolated lab)",
        targets=(url,),
        expected_findings=expected,
    )

    registry = ToolRegistry()
    http_baseline.register(registry)
    state = StateStore(state_path)
    executor = ToolExecutor(registry, state)
    harness = LabEvaluationHarness(engine_version=engine_version)
    context = harness.start_run(scenario)

    started = time.monotonic()
    result = executor.execute(
        context, ToolCall(http_baseline.TOOL_ID, asset=url, arguments=(("url", url),))
    )
    runtime = time.monotonic() - started

    result_meta = dict(result.metadata)
    status = int(result_meta.get("status", "0"))
    found_ids = tuple(i for i in result_meta.get("issues", "").split(",") if i)
    issues_by_id = {
        check_id: (title, severity, impact, remediation)
        for check_id, _header, title, severity, impact, remediation
        in http_baseline.BASELINE_CHECKS
    }
    findings = []
    for check_id in found_ids:
        title, severity, impact, remediation = issues_by_id[check_id]
        findings.append(
            Finding(
                finding_id=f"{context.run_id[:8]}-{check_id}",
                title=title,
                severity=severity,
                target=url,
                evidence=[f"evidence:{result.evidence_id}"],
                remediation=remediation,
                retest_status=RetestStatus.NOT_TESTED,
                metadata={"impact": impact, "check_id": check_id},
            )
        )
    if expected:
        valid, invalid, missed = score_findings(expected, found_ids)
        notes = "scored against scenario ground truth"
    else:
        valid = invalid = missed = 0
        notes = "no ground truth supplied; finding counts are unscored"

    coverage = CoverageReport.build({http_baseline.CAPABILITY_ID: CoverageStatus.ASSESSED})
    coverage_counts = coverage.counts()
    metrics = EvaluationMetrics(
        valid_findings=valid,
        invalid_findings=invalid,
        missed_findings=missed,
        coverage_assessed=coverage_counts[CoverageStatus.ASSESSED.value],
        coverage_unknown=coverage_counts[CoverageStatus.UNKNOWN.value],
        evidence_quality=1.0 if findings else 0.0,
        reproducibility=1.0,
        scope_violations=0,
        policy_violations=0,
        human_interventions=0,
        tool_calls=1,
        runtime_seconds=round(runtime, 4),
    )
    record = harness.record(scenario, context, metrics, notes=notes)

    return {
        "run_id": context.run_id,
        "scenario_id": scenario.scenario_id,
        "target": url,
        "evidence_id": result.evidence_id,
        "policy_reason": result.policy_reason,
        "status": status,
        "findings": [
            {
                "finding": f.title,
                "severity": f.severity.value,
                "impact": f.metadata["impact"],
                "fix": f.remediation,
                "retest": f.retest_status.value,
                "check_id": f.metadata["check_id"],
            }
            for f in findings
        ],
        "coverage": coverage.to_dict(),
        "evaluation": record.to_dict(),
        "report_markdown": render_markdown(findings),
    }


def scripted_demo_gateway(endpoints: tuple[str, ...]) -> ModelGateway:
    """Deterministic offline gateway for demos and CI.

    The planner response is a scripted plan derived from the given lab
    http(s) endpoints (header baseline + service inventory, plus TLS baseline
    for https); the review roles fall back to the ScriptedProvider's echo.
    Swap in a real gateway via ``lightup lab-assess --gateway-config`` — the
    policy gate is identical either way. Assets are the lab-validated hosts,
    matching the normalized targets of a scenario built from the same
    endpoints.
    """
    from .labeval import assert_lab_target

    calls: list[dict] = []
    for endpoint in endpoints:
        parsed = urlparse(endpoint)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            continue
        asset = assert_lab_target(endpoint)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        if parsed.scheme == "http":
            calls.append({"tool_id": http_baseline.TOOL_ID, "asset": asset,
                          "arguments": {"url": endpoint}})
        calls.append({"tool_id": service_inventory.TOOL_ID, "asset": asset,
                      "arguments": {"host": asset, "ports": str(port)}})
        if parsed.scheme == "https":
            calls.append({"tool_id": tls_baseline.TOOL_ID, "asset": asset,
                          "arguments": {"host": asset, "port": port}})
    if not calls:
        raise ValueError("no plannable lab http(s) endpoints given")

    gateway = ModelGateway()
    gateway.register_provider(
        ScriptedProvider("scripted", {ModelRole.PLANNER: [json.dumps(calls)]}))
    for role in (ModelRole.PLANNER, ModelRole.VERIFIER,
                 ModelRole.REMEDIATION_ADVISOR, ModelRole.REPORT_SYNTHESIZER):
        gateway.bind_role(role, "scripted", "scripted-demo")
    return gateway


def run_planned_assessment(
    gateway: ModelGateway,
    scenario: LabScenario,
    state_path: str | Path,
    registry: ToolRegistry | None = None,
    engine_version: str = "m1-dev",
) -> dict:
    """Planner-driven multi-lane lab assessment.

    The PLANNER role proposes a typed plan over the lab tool catalog; every
    call is executed behind the full policy gate. Denials become policy
    violation metrics, elevation needs are surfaced for humans, and coverage
    reflects only the capabilities that actually ran.
    """
    registry = registry or full_lab_registry()
    plan = request_plan(gateway, registry, scenario)

    state = StateStore(state_path)
    executor = ToolExecutor(registry, state)
    harness = LabEvaluationHarness(engine_version=engine_version)
    context = harness.start_run(scenario)

    started = time.monotonic()
    execution = execute_plan(executor, context, plan)
    runtime = time.monotonic() - started

    findings = []
    for call, result in execution.results:
        meta = dict(result.metadata)
        arguments = dict(call.arguments)
        # Prefer the concrete endpoint (URL) over the bare asset so automated
        # retests can re-observe exactly what was tested.
        target = str(arguments.get("url") or call.asset)
        for check_id in (c for c in meta.get("issues", "").split(",") if c):
            title, severity, impact, remediation = CHECK_CATALOG[check_id]
            findings.append(
                Finding(
                    finding_id=f"{context.run_id[:8]}-{check_id}",
                    title=title,
                    severity=severity,
                    target=target,
                    evidence=[f"evidence:{result.evidence_id}"],
                    remediation=remediation,
                    retest_status=RetestStatus.NOT_TESTED,
                    metadata={"impact": impact, "check_id": check_id,
                              "capability_id": result.capability_id},
                )
            )

    assessed = {capability: CoverageStatus.ASSESSED
                for capability in execution.assessed_capabilities()}
    coverage = CoverageReport.build(assessed)
    counts = coverage.counts()

    found_ids = tuple(f.metadata["check_id"] for f in findings)
    if scenario.expected_findings:
        valid, invalid, missed = score_findings(scenario.expected_findings, found_ids)
        notes = "scored against scenario ground truth"
    else:
        valid = invalid = missed = 0
        notes = "no ground truth supplied; finding counts are unscored"

    metrics = EvaluationMetrics(
        valid_findings=valid,
        invalid_findings=invalid,
        missed_findings=missed,
        coverage_assessed=counts[CoverageStatus.ASSESSED.value],
        coverage_unknown=counts[CoverageStatus.UNKNOWN.value],
        evidence_quality=1.0 if findings else 0.0,
        reproducibility=1.0,
        scope_violations=0,
        policy_violations=execution.policy_violations,
        human_interventions=len(execution.elevation_requests),
        tool_calls=len(plan),
        runtime_seconds=round(runtime, 4),
    )
    record = harness.record(scenario, context, metrics, notes=notes)

    return {
        "run_id": context.run_id,
        "scenario_id": scenario.scenario_id,
        "targets": list(scenario.targets),
        "plan": [{"tool_id": c.tool_id, "asset": c.asset,
                  "arguments": dict(c.arguments)} for c in plan],
        "denied": [{"tool_id": tool_id, "reason": reason}
                   for tool_id, reason in execution.denied],
        "elevation_requests": list(execution.elevation_requests),
        "findings": [
            {"finding": f.title, "severity": f.severity.value,
             "impact": f.metadata["impact"], "fix": f.remediation,
             "retest": f.retest_status.value, "check_id": f.metadata["check_id"],
             "capability_id": f.metadata["capability_id"], "target": f.target,
             "evidence_ids": list(f.evidence)}
            for f in findings
        ],
        "coverage": coverage.to_dict(),
        "evaluation": record.to_dict(),
        "report_markdown": render_markdown(findings),
    }


def main_assess(argv: list[str] | None = None) -> int:
    """CLI: planner-driven lab assessment with optional real gateway config."""
    import argparse

    from .ai.config import load_gateway
    from .ai.gateway import GatewayConfigurationError
    from .ai.pipeline import AssessmentReviewPipeline
    from .ai.planner import PlanRejected
    from .labfixtures import PROFILES, expected_findings

    parser = argparse.ArgumentParser(prog="lightup-labassess")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:18080/")
    parser.add_argument("--db", default="lightup-lab.db")
    parser.add_argument("--gateway-config",
                        help="JSON gateway config (see config/gateway.example.json); "
                             "omit for the deterministic scripted demo gateway")
    parser.add_argument("--profile", choices=sorted(PROFILES),
                        help="score against this lab fixture profile's planted "
                             "ground truth (see lab/vuln_fixture.py)")
    parser.add_argument("--no-review", action="store_true",
                        help="skip the verifier/remediation/report review pass")
    args = parser.parse_args(argv)

    expected = expected_findings(PROFILES[args.profile]) if args.profile else ()
    try:
        scenario = LabScenario(
            scenario_id="lab-assess",
            name="Planner-driven lab assessment",
            targets=(args.url,),
            expected_findings=expected,
        )
        gateway = (load_gateway(args.gateway_config) if args.gateway_config
                   else scripted_demo_gateway((args.url,)))
        result = run_planned_assessment(gateway, scenario, args.db)
    except (GatewayConfigurationError, PlanRejected, PermissionError, ValueError) as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2

    if not args.no_review:
        from .ai.providers.anthropic_provider import ModelProviderError

        try:
            result["review"] = AssessmentReviewPipeline(gateway).review(result).to_dict()
        except (GatewayConfigurationError, ModelProviderError) as exc:
            # A failed review never hides the gated assessment result.
            result["review_skipped"] = str(exc)
    print(json.dumps(result, indent=2))
    return 0


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="lightup-labrun")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:18080/")
    parser.add_argument("--db", default="lightup-lab.db")
    parser.add_argument("--expect-fixture", action="store_true",
                        help="score against the stock fixture's ground truth")
    args = parser.parse_args(argv)

    expected = FIXTURE_EXPECTED if args.expect_fixture else ()
    try:
        result = run_lab_baseline(args.url, args.db, expected=expected)
    except PermissionError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
