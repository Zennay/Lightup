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

from .ai.orchestration import ToolCall, ToolExecutor, ToolRegistry
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
from .workers import http_baseline

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

    metrics = EvaluationMetrics(
        valid_findings=valid,
        invalid_findings=invalid,
        missed_findings=missed,
        coverage_assessed=1,
        coverage_unknown=0,
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
        "evaluation": record.to_dict(),
        "report_markdown": render_markdown(findings),
    }


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
