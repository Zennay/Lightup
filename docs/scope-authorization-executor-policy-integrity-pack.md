# ToolExecutor policy integrity pack

Issue: #937  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This tests/docs-only composition keeps two independent fail-closed policy-boundary contracts adjacent for source-owner absorption:

- #779 — constructor admission accepts only omitted/None or an exact `ExecutionPolicy`; duck objects and subclasses cannot replace the central policy object.
- #935 — an exact retained `ExecutionPolicy` cannot be rewired after construction by shadowing `decide` on the instance.

## Ownership

- PR #107 keeps `ToolExecutor` and live authorization-revalidation production ownership.
- PR #100 keeps `src/lightup/execution_policy.py` production ownership.
- This composition changes no `src/` path and does not modify either standalone acceptance branch.

## Combined invariant

The executor must both start with and continue using the canonical policy boundary. Exact object identity cannot become an authority bypass either at construction time or through post-construction mutation.

Rejected/bypassed attempts must not invoke a handler or write evidence.

## Safety

All evidence is local/offline. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
