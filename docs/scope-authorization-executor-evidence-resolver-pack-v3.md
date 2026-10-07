# ToolExecutor evidence/resolver integrity pack v3

Issue: #954  
Pinned parent composition: #952 exact head `ddcaf70e6323cdc8d25fd02a5bf002858767ac5d`  
Pinned production owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This successor composes four fail-closed ToolExecutor/live-authorization contracts:

- #948 — canonical, lifetime-bound `StateStore` evidence ledger;
- #949 — exact canonical `AuthorizationGrant` resolver output;
- #951 — same-id live grants may narrow but never widen asset/exclusion/capability/max-risk authority;
- #953 — same-id live grants may narrow but never widen the run snapshot validity window.

## Combined invariant

Live revalidation is withdrawal-oriented, never an escalation mechanism for an already-created run. The executor may observe less authority than the run snapshot, but no replacement ledger, polymorphic live grant, broader scope/risk, earlier validity start, or later validity expiry may increase what that run can do.

Canonical exact objects and calls inside the intersection remain valid. Rejected paths invoke no handler, write no evidence, and leave caller-owned objects unchanged.

## Ownership

- PR #107 retains all `ToolExecutor` and live-revalidation production ownership.
- #170 / active `StateStore` source owners remain untouched.
- Parallel executor composition #947 remains unchanged.
- This branch adds tests/docs only and intentionally remains expected RED until the production owner absorbs the contracts.

## Safety

All regressions are local/offline with temporary SQLite and inert handlers. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
