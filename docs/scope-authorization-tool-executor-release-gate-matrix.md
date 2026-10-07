# ToolExecutor authorization release-gate matrix (offline)

Status: **acceptance specification, not a passing test receipt**. This is a separate documentation-only branch based on the exact production-owner PR #107 head `c37ee27d922a7dd400eee1db39268f4a6269e431`. Do not merge this as evidence that the implementation is fixed.

## Ownership and order

- PR #107 owns ToolExecutor/live-authorization production code. Do not edit it from this branch.
- #948 and #949 cover exact StateStore identity/lifetime and exact live-grant resolver output, respectively.
- #951 and #953 cover same-grant authority and temporal monotonicity.
- #954 composes the above as a tests/docs-only pack at `5ac0e6f0b900e5b7cef2d92f7917cabfb1321086`. Preserve that head and its test sources.
- The executor v5 pack #947 and separate policy/registry owners remain independent.
- Promote only after the production owner absorbs tests, executes them on the precise resulting commit and records an immutable runner receipt. Red acceptance tests are findings, **not** successful gates.

## Required rejection gates

All checks are offline, using an inert handler and isolated temporary SQLite. For a rejected case, assert **zero handler invocations, zero newly persisted evidence, unchanged grant/run snapshot objects**, and a fail-closed decision.

| ID | Mutation at revalidation | Required result |
| --- | --- | --- |
| L1 | Construct executor with a duck-typed evidence store | Reject at construction |
| L2 | Construct executor with a subclass of StateStore | Reject at construction |
| L3 | Replace executor's retained evidence store after construction | Reject before dispatch |
| G1 | Live resolver returns a duck object with same grant_id | Reject before policy/dispatch |
| G2 | Live resolver returns subclass of AuthorizationGrant with same grant_id | Reject before policy/dispatch |
| G3 | Live resolver returns grant with different grant_id | Reject before policy/dispatch |
| S1 | Same-id live grant adds an asset | Reject widening |
| S2 | Same-id live grant removes a formerly excluded asset | Reject widening |
| S3 | Same-id live grant adds a capability | Reject widening |
| S4 | Same-id live grant raises maximum risk | Reject widening |
| T1 | Live valid_from earlier than immutable run grant | Reject temporal widening |
| T2 | Live valid_until later than immutable run grant | Reject temporal widening |
| T3 | Expired run snapshot revived by live extension | Reject |
| T4 | Future-dated run snapshot activated by live earlier start | Reject |

## Positive controls

- An **exact** canonical StateStore and immutable binding must still persist evidence when a permitted inert operation completes.
- Exact same-id AuthorizationGrant returned by the live resolver must still undergo all normal policy checks.
- Live grants may narrow asset/capability/risk authority, add exclusions, move start later or move expiry earlier, provided the chosen inert test action remains authorized.
- The live grant must still be currently valid; monotonicity never substitutes for revocation, approval, request-bound scope, or expiry checks.
- A rejected call must not convert a previous rejection into an executable run upon retry with a widened same-id grant.

## Promotion checklist

1. Confirm #107 and #954 exact heads at review time; rebase/recompose only when ownership approves.
2. Run all matrix cases locally/offline and pin Python versions, commit SHA, runner identity and exit codes.
3. Distinguish expected RED on the unpatched source from GREEN only **after** the source owner's changes.
4. Verify changed paths exclude network/target interactions and exclude unrelated production sources.
5. Publish one immutable success receipt for the exact promoted head; a queued or stale workflow does not count.
6. Require explicit client authorization and scope approval for any later active target work. This checklist itself never grants authority.

**Safety:** no DNS/network I/O, scanning, target contact, exploitation, capability execution, remediation/retest execution, deployment or verdict creation.
