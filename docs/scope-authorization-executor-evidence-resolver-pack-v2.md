# ToolExecutor evidence/resolver integrity pack v2

Issue: #952  
Pinned parent composition: #950 exact head `b06ce020227878e9659248c53d8653949bea8a34`  
Pinned production owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

This successor keeps three independent fail-closed contracts adjacent:

- #948 — only an exact `StateStore` may serve as the executor evidence ledger, and the accepted ledger remains lifetime-bound;
- #949 — live resolver output is either `None` or an exact `AuthorizationGrant`;
- #951 — same-id live grant revalidation is monotonic: live authority may narrow the run snapshot, never widen it.

## Combined invariant

An existing run cannot gain authority by changing either side of its live execution boundary.

- The evidence sink cannot be replaced/faked.
- The live authorization object cannot be replaced with a polymorphic/duck authority object.
- Even an exact live grant cannot add assets, remove snapshot exclusions, add capabilities, or raise max-risk beyond the immutable run snapshot.

Canonical live narrowing remains allowed. Rejected paths invoke no handler, write no evidence and leave caller objects unchanged.

## Ownership

- PR #107 keeps all production ownership for `ToolExecutor` and live authorization revalidation.
- #170 / active `StateStore` source owners remain untouched.
- Parallel executor pack #947 remains unchanged.
- This branch is tests/docs only and intentionally expected RED until the production owner absorbs the contracts.

## Safety

All regressions are local/offline with temporary SQLite and inert handlers. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
