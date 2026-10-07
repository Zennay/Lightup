# ToolExecutor authorization-boundary integrity pack v2

Issue: #941  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This tests/docs-only composition keeps four independent fail-closed executor authority contracts adjacent:

- #779 — constructor policy admission accepts only omitted/None or an exact `ExecutionPolicy`;
- #935 — a retained exact `ExecutionPolicy` cannot be rewired after construction;
- #938 — the live authorization resolver selected at construction cannot be replaced to revive stale/revoked authority;
- #940 — constructor registry admission requires an exact `ToolRegistry`, and that registry remains bound for executor lifetime.

## Ownership

- PR #107 keeps `ToolExecutor` and live authorization-revalidation production ownership.
- PR #100 keeps `src/lightup/execution_policy.py` production ownership.
- PR #156 keeps ToolRegistry definition/schema admission production ownership.
- Durable resolver state-integrity families remain independent.
- This composition changes no production source.

## Combined invariant

The executor must begin with canonical authority components and retain those same components for its full lifetime.

Caller-controlled object substitution or post-construction replacement must not alter policy decisions, live grant resolution, tool interaction classification, capability identity, risk metadata or handler selection. Rejected paths invoke no handler and write no evidence.

## Safety

All regressions are local/offline with test-only handlers and documentation hostnames. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
