# ToolExecutor authorization-boundary integrity pack v5

Issue: #947  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This tests/docs-only composition keeps seven independent fail-closed executor authority contracts adjacent:

- #779 — constructor policy admission accepts only omitted/None or an exact `ExecutionPolicy`;
- #935 — a retained exact `ExecutionPolicy` cannot be rewired by instance-level `decide` shadowing;
- #938 — the live authorization resolver selected at construction cannot be replaced to revive stale/revoked authority;
- #940 — constructor registry admission requires an exact `ToolRegistry`, and that registry remains bound for executor lifetime;
- #942 — the `executor.policy` reference itself remains bound for executor lifetime;
- #944 — `ToolExecutor.execute()` accepts only an exact immutable outer `RunContext`;
- #946 — `ToolExecutor.execute()` accepts only an exact immutable outer `ToolCall`.

## Ownership

- PR #107 keeps `ToolExecutor` and live authorization-revalidation production ownership.
- PR #100 keeps `src/lightup/execution_policy.py` production ownership.
- PR #156 keeps ToolRegistry definition/schema admission production ownership.
- Field-level request/grant/tool-call contracts and durable resolver families remain independent.
- This composition changes no production source.

## Combined invariant

A ToolExecutor must begin with canonical authority components, retain those components for its full lifetime, and consume canonical immutable execution inputs.

Neither constructor substitution, post-construction replacement/shadowing nor outer context/call polymorphism may alter policy decisions, live grant resolution, registry selection, argument extraction, asset binding, interaction classification, capability identity, risk metadata, tenant lineage or handler selection. Rejected paths invoke no handler and write no evidence.

## Safety

All regressions are local/offline with test-only handlers and documentation hostnames. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
