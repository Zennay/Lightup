# Risk-5 lab approval: revocation during isolation check (issue #1173)

This is **tests-only, opt-in, offline** acceptance stacked on draft PR #1172 at `292e13fb7de08d7c6be625ef71749c8eaffa702e`. It neither issues approvals nor connects to any target. The only handler writes an in-memory marker.

A current operator approval can be revoked or changed after the approval resolver returns and before the isolation verifier returns. The optional wrapper currently checks the approval only once; an isolation callback can therefore invalidate the record before the handler runs. Two `unittest.expectedFailure` tests preserve this **RED safety gap** without treating it as repaired. The green control proves already-revoked records deny without invoking isolation or the handler.

Acceptance requires a trusted, durable, transactional approval/dispatch boundary, real isolation and egress fencing, owner integration across every risk-5 dispatch path, and removal of `expectedFailure` only after a genuine handler-noninvocation proof. Synthetic `True` from an isolation callback is NOT actual isolation attestation.

**DRAFT/HOLD. No production integration, no authorization, no active scan, no merge or deployment.**

## Additional acceptance boundaries (2026-10-12)

Before approving a risk-5 lab dispatch, the operator-owned approval must remain valid at the actual dispatch boundary, not merely before isolation verification. A replacement approval with the same tenant and target identifiers is not automatically the same approval record. Missing, revoked, expired or tenant-substituted approvals must all deny before invoking a handler. These are acceptance requirements, not implemented guarantees.

A passing synthetic isolation callback is never evidence of network egress fencing. This draft must remain unmerged until the executor owner integrates a transactionally coordinated approval/dispatch boundary, validates real lab isolation, and demonstrates exact-commit CI on the canonical runner.
