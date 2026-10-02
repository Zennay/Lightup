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
