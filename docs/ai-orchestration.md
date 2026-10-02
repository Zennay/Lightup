# AI layer: model gateway, orchestration contracts, lab evaluation

## Model gateway (`lightup.ai.gateway`)

Provider-neutral routing of *roles* to configured providers:

- roles: planner, surface analyst, security analyst, verifier, remediation
  advisor, report synthesizer;
- providers implement one interface (`ModelProvider.complete`);
- role→provider/model bindings are configuration (`ModelGateway.bind_role`),
  never business logic;
- `ScriptedProvider` is the deterministic stub used by tests and lab runs.

The gateway is **not** a security boundary. Whatever a model plans, execution
still passes the policy gate below.

## Orchestration contracts (`lightup.ai.orchestration`)

```text
ModelGateway (plans)
   -> ToolCall (typed)
   -> ToolExecutor
        1. typed argument validation (ToolDefinition)
        2. mode boundary: passive/analysis runs never reach active tools
        3. lab boundary: lab tools only in lab runs, target tools never in labs
        4. risk ceiling: above approved_risk -> RiskElevationRequired (no exec)
        5. ExecutionPolicy.decide (authorization, scope, capability, risk)
        6. handler runs; must return ToolOutput
        7. evidence recorded in the StateStore ledger (mandatory)
```

Key invariants, each covered by `tests/test_orchestration.py`:

- `RunContext` is frozen; a run cannot raise its own risk ceiling — elevation
  is a human decision that produces a **new** context;
- unauthorized active execution is impossible (no grant → `ToolDenied`);
- passive Discovery cannot invoke active capabilities, even if an
  authorization object is attached to the run;
- every tool result is linked to evidence (`ToolOutput` contract + ledger).

## Lab evaluation foundation (`lightup.labeval`)

- `LabScenario` rejects any non-loopback/non-private target at construction;
- `LabEvaluationHarness` is the only way to start evaluation runs and only
  produces lab contexts;
- `EvaluationMetrics` is the benchmark schema: valid/invalid/missed findings,
  false-positive rate, coverage assessed/unknown, evidence quality,
  reproducibility, scope/policy violations, human interventions, tool calls,
  runtime, compute cost, remediation quality, retest correctness.

The lab engine is benchmarked here before large-scale prospect discovery, so
Discovery later learns which public signals actually correlate with real
problems.

## First capability worker (`lightup.workers.http_baseline`)

`lab-http-baseline` is the first worker to run the whole chain end-to-end
(`lightup.labrun`, CLI: `lightup lab-baseline [--expect-fixture]`):

- one HTTP GET against an isolated lab fixture, evaluated for defensive
  response headers (CSP, nosniff, clickjacking, referrer policy, banner);
- reachable only through the `ToolExecutor` (LAB_ACTIVE interaction), and the
  handler independently re-validates the target with `assert_lab_target`, so
  neither a mis-wired registry nor a direct call can point it at the internet;
- evidence lands in the ledger, findings come out as Finding → Impact → Fix →
  Retest, and the run is scored into an `EvaluationRecord` (against the stock
  fixture's ground truth with `--expect-fixture`).

A second worker, `lab-service-inventory` (`lightup.workers.service_inventory`,
capability `network-services`), connect-checks a bounded, explicit list of TCP
ports on a lab host — no banners, no payloads — with the same double lab gate.

## Review pipeline (`lightup.ai.pipeline`)

`AssessmentReviewPipeline` is the first consumer of the Model Gateway: per
finding the **verifier** role issues a verdict and the **remediation advisor**
refines the fix; the **report synthesizer** writes the client-facing summary
(always stating when coverage is materially unknown). All three roles must be
bound before a review runs (fail-closed), and the pipeline only shapes text —
it cannot execute tools or widen scope/risk.

## Lab findings in the product (`lightup.labsync`)

`persist_lab_findings` turns a lab run's results into regular domain findings
(visible in dashboard and portal, with evidence references), and
`retest_finding` re-observes the lab target with honest semantics: issue gone
→ `fixed`; still present → `fix_pending`; back after a `fixed` verdict →
`regression`. Retests reuse the lab-only baseline worker, so they fail closed
on any non-lab asset.

## Coverage tracking (`lightup.coverage`)

`CoverageReport` maps every registered capability to
`assessed / partially_assessed / not_applicable / not_authorized / unknown`
(default unknown). Lab runs attach it to their results, and when unknown
domains outnumber assessed ones the report explicitly states that zero
findings must not be read as a clean bill of health.
