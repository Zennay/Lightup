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
    expected: tuple[ExpectedFinding, ...] | None = None,
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
    if expected is not None:
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
                "evidence_summary": result.summary,
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

    verifier_slots = max(1, len(calls) * max(1, len(CHECK_CATALOG)))
    verifier_script = [
        "UNCERTAIN scripted demo review does not independently re-observe evidence"
    ] * verifier_slots

    gateway = ModelGateway()
    gateway.register_provider(
        ScriptedProvider(
            "scripted",
            {
                ModelRole.PLANNER: [json.dumps(calls)],
                ModelRole.VERIFIER: verifier_script,
            },
        )
    )
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
    include_benchmark_case: bool = False,
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
    # Preserve evidence alongside each *occurrence* rather than indexing by
    # a check ID: different lab endpoints can legitimately yield the same check.
    finding_evidence_summaries: list[str] = []
    used_finding_ids: set[str] = set()
    for call, result in execution.results:
        meta = dict(result.metadata)
        arguments = dict(call.arguments)
        # Prefer the concrete endpoint (URL) over the bare asset so automated
        # retests can re-observe exactly what was tested.
        target = str(arguments.get("url") or call.asset)
        for check_id in (c for c in meta.get("issues", "").split(",") if c):
            title, severity, impact, remediation = CHECK_CATALOG[check_id]
            # Keep the historical first ID; disambiguate later occurrences
            # without conflating different endpoints in the rendered report.
            base_id = f"{context.run_id[:8]}-{check_id}"
            finding_id = base_id
            ordinal = 2
            while finding_id in used_finding_ids:
                finding_id = f"{base_id}~{ordinal}"
                ordinal += 1
            used_finding_ids.add(finding_id)
            finding = Finding(
                finding_id=finding_id,
                title=title,
                severity=severity,
                target=target,
                evidence=[f"evidence:{result.evidence_id}"],
                remediation=remediation,
                retest_status=RetestStatus.NOT_TESTED,
                metadata={"impact": impact, "check_id": check_id,
                          "capability_id": result.capability_id},
            )
            findings.append(finding)
            finding_evidence_summaries.append(result.summary)

    assessed = {capability: CoverageStatus.ASSESSED
                for capability in execution.assessed_capabilities()}
    coverage = CoverageReport.build(assessed)
    counts = coverage.counts()

    found_ids = tuple(f.metadata["check_id"] for f in findings)
    if scenario.expected_findings is not None:
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

    assessment_output = {
        "run_id": context.run_id,
        "scenario_id": scenario.scenario_id,
        "targets": list(scenario.targets),
        "plan": [{"tool_id": c.tool_id, "asset": c.asset,
                  "arguments": dict(c.arguments)} for c in plan],
        "denied": [{"tool_id": tool_id, "reason": reason}
                   for tool_id, reason in execution.denied],
        "elevation_requests": list(execution.elevation_requests),
        "findings": [
            {"finding": f.title, "finding_id": f.finding_id,
             "severity": f.severity.value,
             "impact": f.metadata["impact"], "fix": f.remediation,
             "retest": f.retest_status.value, "check_id": f.metadata["check_id"],
             "capability_id": f.metadata["capability_id"], "target": f.target,
             "evidence_ids": list(f.evidence),
             "evidence_summary": evidence_summary}
            for f, evidence_summary in zip(findings, finding_evidence_summaries, strict=True)
        ],
        "coverage": coverage.to_dict(),
        "evaluation": record.to_dict(),
        "report_markdown": render_markdown(findings),
    }
    if include_benchmark_case:
        # Original #1513 read-only comparator's exact record/context envelope.
        # The wrapper is unsigned source material, not provenance/consent.
        if context.is_lab is not True or context.authorization is not None:
            raise ValueError("only ungranted original lab records can be exported")
        assessment_output["benchmark_case"] = {
            "record": record.to_dict(),
            "context": {
                "run_id": context.run_id,
                "client_id": context.client_id,
                "engagement_id": context.engagement_id,
                "mode": context.mode.value,
                "approved_risk": context.approved_risk.value,
                "authorization": context.authorization,
                "is_lab": context.is_lab,
                "created_at": context.created_at.isoformat(),
            },
        }
    return assessment_output


def _admit_private_output_path(output: str | None) -> None:
    """Reject unavailable private artifact destinations before model dispatch.

    This is a read-only early check; the final O_EXCL/O_NOFOLLOW open still
    decides atomically whether the completed artifact can be published.
    """
    if output is None:
        return
    if type(output) is not str or not output or "\x00" in output:
        raise ValueError("private output destination is invalid")
    destination = Path(output)
    if destination.suffix != ".json" or destination.is_symlink() or destination.exists():
        raise ValueError("private output destination is unavailable")
    if not destination.parent.is_dir():
        raise ValueError("private output directory does not exist")
    # Reject aliases through symlinked ancestor directories in the user
    # selected path; a 0600 result should not silently leave the expected tree.
    if any(parent.is_symlink() for parent in destination.parents):
        raise ValueError("private output directory is ambiguous")


def _deliver_lab_result(payload: dict, output: str | None) -> None:
    """Publish a complete lab artifact without overwriting any existing data.

    Never emit a source-rich report to the terminal when a private file was
    requested. A fingerprint of the saved JSON is intentionally not an
    authenticated evidence receipt or consent proof.
    """
    serialized = (json.dumps(payload, indent=2, ensure_ascii=True, allow_nan=False) + "\n").encode("utf-8")
    if len(serialized) > 8 * 1024 * 1024:
        raise ValueError("private lab result exceeds the export size limit")
    if output is None:
        print(serialized.decode("utf-8"), end="")
        return
    import os
    import tempfile
    target = Path(output)
    if target.suffix != ".json":
        raise ValueError("private output path must end in .json")
    # Write a fully flushed 0600 staging file in the SAME directory, then
    # make it visible under the requested destination with an exclusive
    # hard-link. Unlike rename(), link() cannot overwrite an existing name.
    # Incomplete/failed writes never appear as completed destination files.
    staging_fd, staging_name = tempfile.mkstemp(
        prefix=".lightup-private-pending-", dir=target.parent,
    )
    try:
        with os.fdopen(staging_fd, "wb") as stream:
            stream.write(serialized)
            stream.flush()
            os.fsync(stream.fileno())
        # A concurrent file or symlink at target always produces FileExistsError.
        os.link(staging_name, target, follow_symlinks=False)
    finally:
        try:
            os.unlink(staging_name)
        except FileNotFoundError:
            pass
    print(json.dumps({
        "mode": "PRIVATE_LAB_ARTIFACT_CREATED",
        "output_written": True,
        "source_authenticated": False,
        "authorization_granted": False,
        "release_allowed": False,
    }, indent=2))



def _admit_explicit_lab_url(value: str) -> str:
    """Narrow the user-facing lab URL contract before any provider or tool.

    The original LabScenario / scope gate is mandatory *in addition* to this
    syntactic fence. Never resolve DNS or include rejected values in errors.
    """
    from urllib.parse import urlsplit
    if (type(value) is not str or not 1 <= len(value) <= 2048
            or value != value.strip()
            or any(ord(char) < 33 or ord(char) == 127 for char in value)):
        raise ValueError("lab URL must be bounded printable text")
    try:
        url = urlsplit(value)
        if (url.scheme not in ("http", "https") or not url.netloc
                or not url.hostname or url.username is not None
                or url.password is not None or url.fragment):
            raise ValueError("invalid lab URL")
        # Reading port forces detection of invalid/out-of-range port strings;
        # an explicit empty ':' is not a canonical optional port.
        port = url.port
        if url.netloc.endswith(":") and port is None:
            raise ValueError("invalid lab URL port")
        if port is not None and not 1 <= port <= 65535:
            raise ValueError("invalid lab URL port")
    except ValueError:
        raise ValueError("lab URL was not admitted") from None
    return value


def _read_lab_targets_file(filename: str) -> list[str]:
    """Read only one explicitly chosen small regular local file, never a pipe."""
    import os
    import stat
    fd = -1
    try:
        flags = os.O_RDONLY | getattr(os, "O_NONBLOCK", 0)
        flags |= getattr(os, "O_NOFOLLOW", 0)
        fd = os.open(filename, flags)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or not 0 <= info.st_size <= 16_384:
            raise ValueError("lab targets manifest is not a bounded regular file")
        with os.fdopen(fd, "rb") as source:
            fd = -1
            raw = source.read(16_385)
        if len(raw) > 16_384:
            raise ValueError("lab targets manifest exceeds 16 KiB")
        decoded = raw.decode("utf-8")
        if "\x00" in decoded:
            raise ValueError("lab targets manifest contains NUL bytes")
        return [
            line.strip() for line in decoded.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    except (OSError, UnicodeError, ValueError) as exc:
        raise ValueError("local lab targets manifest was not admitted") from None
    finally:
        if fd >= 0:
            os.close(fd)


def main_assess(argv: list[str] | None = None) -> int:
    """CLI: planner-driven lab assessment with optional real gateway config."""
    import argparse

    from .ai.config import load_gateway
    from .ai.gateway import GatewayConfigurationError
    from .ai.pipeline import AssessmentReviewPipeline
    from .ai.planner import PlanRejected
    from .ai.providers.anthropic_provider import ModelProviderError
    from .labfixtures import PROFILES, expected_findings

    parser = argparse.ArgumentParser(prog="lightup-labassess")
    parser.add_argument(
        "url", nargs="?", default=None,
        help="one isolated lab HTTP(S) URL; uses the loopback default only with no other target options",
    )
    parser.add_argument(
        "--target", action="append", default=[], metavar="LAB_URL",
        help="another isolated lab HTTP(S) URL; repeat for multiple lab endpoints",
    )
    parser.add_argument(
        "--targets-file", metavar="PATH",
        help="local UTF-8 text file with one isolated lab URL per line (# comments allowed)",
    )
    parser.add_argument(
        "--catalog-file", metavar="PRIVATE_STUDIO_JSON",
        help="PRIVATE Lab Scenario Studio v1 catalog (untrusted design only)",
    )
    parser.add_argument(
        "--scenario-id", metavar="ID",
        help="exact scenario ID in --catalog-file; all endpoint URLs must be separately supplied",
    )
    parser.add_argument("--db", default="lightup-lab.db")
    parser.add_argument(
        "--output", metavar="NEW_PRIVATE_JSON",
        help="write complete offline lab results into a NEW owner-only JSON file (0600)",
    )
    parser.add_argument(
        "--artifact-format", choices=("assessment", "benchmark-case"),
        default="assessment",
        help="private export format: complete assessment or exact #1513 offline record/context envelope",
    )
    parser.add_argument("--gateway-config",
                        help="JSON gateway config (see config/gateway.example.json); "
                             "omit for the deterministic scripted demo gateway")
    parser.add_argument("--profile", choices=sorted(PROFILES),
                        help="score against this lab fixture profile's planted "
                             "ground truth (see lab/vuln_fixture.py)")
    parser.add_argument("--no-review", action="store_true",
                        help="skip the verifier/remediation/report review pass")
    parser.add_argument(
        "--preview-only", action="store_true",
        help="validate lab inputs and show normalized hosts without planning, models or network calls",
    )
    args = parser.parse_args(argv)

    expected = expected_findings(PROFILES[args.profile]) if args.profile else None
    try:
        endpoints = ([args.url] if args.url is not None else []) + list(args.target)
        if args.targets_file is not None:
            endpoints.extend(_read_lab_targets_file(args.targets_file))
        if not endpoints and args.targets_file is None and args.catalog_file is None:
            endpoints = ["http://127.0.0.1:18080/"]
        if not endpoints or len(endpoints) > 16:
            raise ValueError("lab assessment requires 1–16 explicit lab URLs")
        endpoints = [_admit_explicit_lab_url(endpoint) for endpoint in endpoints]
        if len(set(endpoints)) != len(endpoints):
            raise ValueError("duplicate lab endpoint is not allowed")
        if args.profile and len(endpoints) != 1:
            raise ValueError("--profile ground truth applies only to one lab endpoint")
        if args.artifact_format == "benchmark-case" and (args.output is None or args.preview_only):
            raise ValueError("benchmark-case export requires --output and a completed lab run")
        _admit_private_output_path(args.output)
        if (args.catalog_file is None) != (args.scenario_id is None):
            raise ValueError("--catalog-file and --scenario-id must be supplied together")
        if args.catalog_file is not None and not args.catalog_file.strip():
            raise ValueError("--catalog-file requires a non-empty path")
        if args.catalog_file is not None and args.profile:
            raise ValueError("a private Studio catalog cannot authenticate a fixture profile")
        catalog = None
        if args.catalog_file is not None:
            from .lab_catalog import read_selected_lab_design
            from ipaddress import ip_address
            from urllib.parse import urlsplit
            catalog = read_selected_lab_design(args.catalog_file, args.scenario_id)
            # A draft Studio address is not a runnable endpoint. Require one
            # independently entered numeric URL per declared private lab IP.
            bound_ips: list[str] = []
            for endpoint in endpoints:
                try:
                    url = urlsplit(endpoint)
                    host = url.hostname
                    if (url.scheme not in ("http", "https") or not host
                            or url.username is not None or url.password is not None
                            or url.fragment or url.port is None):
                        raise ValueError("unbound endpoint")
                    bound_ips.append(str(ip_address(host)))
                except (ValueError, TypeError):
                    raise ValueError("lab endpoint does not match the private Studio scenario") from None
            if (len(bound_ips) != len(catalog["targets"])
                    or len(set(bound_ips)) != len(bound_ips)
                    or set(bound_ips) != set(catalog["targets"])):
                raise ValueError("explicit lab endpoints do not exactly match selected Studio targets")
        scenario = LabScenario(
            scenario_id=catalog["scenario_id"] if catalog else "lab-assess",
            name=catalog["name"] if catalog else "Planner-driven lab assessment",
            description=catalog["description"] if catalog else "",
            targets=tuple(endpoints),
            # A locally authored draft is NOT authenticated ground truth:
            # the existing explicit --profile is the only scoring path.
            expected_findings=None if catalog else expected,
        )
        if args.preview_only:
            # Input review is non-authorizing. Avoid echoing URLs (which can
            # contain credentials/query details) or the contents of a manifest.
            preview = {
                "mode": "LAB_INPUT_PREVIEW_ONLY",
                "lab_host_candidates": list(scenario.targets),
                "endpoint_count": len(scenario.endpoints),
                "plan_created": False,
                "model_called": False,
                "target_interaction_performed": False,
                "authorization_granted": False,
            }
            if catalog is not None:
                preview["lab_design_source"] = {
                    key: catalog[key] for key in ("schema", "scenario_id",
                        "catalog_sha256", "declared_expected_count",
                        "source_authenticated", "declared_ground_truth_used",
                        "authorization_granted")
                }
            try:
                _deliver_lab_result(preview, args.output)
            except (OSError, ValueError):
                print(json.dumps({"error": "private lab preview could not be created; no existing file was replaced"}, indent=2))
                return 2
            return 0
        gateway = (load_gateway(args.gateway_config) if args.gateway_config
                   else scripted_demo_gateway(tuple(endpoints)))
        result = run_planned_assessment(
            gateway, scenario, args.db,
            include_benchmark_case=args.artifact_format == "benchmark-case",
        )
        if catalog is not None:
            result["lab_design_source"] = {
                key: catalog[key] for key in ("schema", "scenario_id",
                    "catalog_sha256", "declared_expected_count",
                    "source_authenticated", "declared_ground_truth_used",
                    "authorization_granted")
            }
    except (OSError, UnicodeError, GatewayConfigurationError, ModelProviderError,
            PlanRejected, PermissionError, ValueError):
        # Exception text may contain original URLs, provider credentials,
        # filesystem paths or private catalog identities. Do not echo it.
        print(json.dumps({"error": "isolated lab assessment was not admitted or could not complete"}, indent=2))
        return 2

    exit_code = 0
    if not args.no_review:
        try:
            result["review"] = AssessmentReviewPipeline(gateway).review(result).to_dict()
        except (GatewayConfigurationError, ModelProviderError, ValueError):
            # No provider/model exception or untrusted URL leaks into results.
            # A failed review never masquerades as completed verification.
            result["review_skipped"] = "model review incomplete; no verified verdict produced"
            exit_code = 2
    if exit_code != 0 and args.output:
        # Never persist a partial/failed review as a successful completed
        # evidence source. It can still be inspected in original stdout form.
        print(json.dumps({"error": "lab review did not complete; private output was not created"}, indent=2))
        return exit_code
    try:
        export_payload = (result.pop("benchmark_case")
                          if args.artifact_format == "benchmark-case" else result)
        _deliver_lab_result(export_payload, args.output)
    except (OSError, ValueError):
        print(json.dumps({"error": "private lab report could not be created; no existing file was replaced"}, indent=2))
        return 2
    return exit_code


def main(argv: list[str] | None = None) -> int:
    import argparse

    parser = argparse.ArgumentParser(prog="lightup-labrun")
    parser.add_argument("url", nargs="?", default="http://127.0.0.1:18080/")
    parser.add_argument("--db", default="lightup-lab.db")
    parser.add_argument("--expect-fixture", action="store_true",
                        help="score against the stock fixture's ground truth")
    args = parser.parse_args(argv)

    expected = FIXTURE_EXPECTED if args.expect_fixture else None
    try:
        result = run_lab_baseline(args.url, args.db, expected=expected)
    except PermissionError as exc:
        print(json.dumps({"error": str(exc)}, indent=2))
        return 2
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
