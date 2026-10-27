# Scope revocation temporal ordering — offline reference contract

This is a **test-only, non-production** reference oracle. It does not import or validate the production ToolExecutor, does not certify any authorization source, and must not be interpreted as permission to run a capability.

## Final-dispatch invariant

A previously valid queued approval is insufficient to execute. A new live, trusted, issuer-owned grant must be checked at the dispatch boundary. Fail closed if it is absent, revoked, tenant/target mismatched, or has changed revision. A later reapproval cannot retroactively validate the stale queued snapshot. All comparisons must reject type confusion, notably boolean-as-integer revisions and truthy non-boolean active flags.

## Scope and limitations

The isolated test enumerates event ordering examples and stale retries, plus tenant/target rebinding. The positive reference outcome means *conditionally eligible within this toy oracle*; it is **not** a production authorization decision. There is no proof of linearizable storage, issuer lineage, time-of-check/time-of-use race safety, in-flight cancellation, signed approvals, audit persistence, or process boundaries. Production owner PR #107 must supply independent integration and real fail-closed behavior; #983/#989 own adjacent revocation matrices/models and #982 owns release receipts.

No real targets, DNS, networking, subprocesses, security scans or active-capability dispatch are used. Remain in M7/ST5 plan/lab-only posture. Do not merge or promote based only on these tests. Require exact-head hosted and permanent-VPS evidence with owner review.
