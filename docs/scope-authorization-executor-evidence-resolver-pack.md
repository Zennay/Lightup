# ToolExecutor evidence/resolver integrity pack

Issue: #950  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This tests/docs-only composition keeps two independent fail-closed ToolExecutor integrity contracts adjacent without modifying the parallel executor v5 pack:

- #948 — constructor admission accepts only an exact `StateStore`, and the accepted evidence ledger remains bound for executor lifetime;
- #949 — live authorization resolver output is either `None` or an exact `AuthorizationGrant` before policy evaluation.

## Combined invariant

Tool execution may proceed only while both downstream trust anchors remain canonical:

1. evidence cannot be redirected, suppressed or fabricated by a duck/subclass/replaced ledger;
2. live authorization cannot be widened by a duck/subclass grant object that preserves only the snapshot grant id.

Rejected paths invoke no handler, write no evidence and do not mutate execution state. Canonical exact objects retain their existing behavior.

## Ownership

- PR #107 retains `ToolExecutor` and live authorization-revalidation production ownership.
- #170 and active `StateStore` source owners remain untouched.
- #947 / `chatgpt/scope-authorization-executor-authorization-integrity-pack-v5-20261007` remains unchanged.
- This branch adds tests/docs only and intentionally remains expected RED until the production owner absorbs the contracts.

## Safety

All regressions are local/offline with temporary SQLite and inert test handlers. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
