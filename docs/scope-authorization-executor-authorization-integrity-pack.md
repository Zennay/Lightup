# ToolExecutor authorization-boundary integrity pack

Issue: #939  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This tests/docs-only composition keeps three independent fail-closed executor-boundary contracts adjacent:

- #779 — constructor policy admission accepts only omitted/None or an exact `ExecutionPolicy`;
- #935 — a retained exact `ExecutionPolicy` cannot be rewired after construction by instance-level `decide` shadowing;
- #938 — the live authorization resolver selected at construction cannot be replaced after construction to revive stale/revoked authority.

## Ownership

- PR #107 keeps `ToolExecutor` and live authorization-revalidation production ownership.
- PR #100 keeps `src/lightup/execution_policy.py` production ownership.
- Durable resolver correctness/state-integrity families remain independent.
- This composition changes no production source.

## Combined invariant

The executor must preserve both of its central pre-handler authority boundaries for its full lifetime: the canonical execution policy and the authoritative live-grant resolver.

Neither outer object substitution nor post-construction attribute replacement may convert a denied TARGET_ACTIVE call into handler execution. Denied paths write no evidence.

## Safety

All regressions are local/offline with test-only handlers and documentation hostnames. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
