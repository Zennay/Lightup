# Live authorization resolver grant-object integrity

Issue: #949  
Production owner: draft PR #107  
Pinned owner head: `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

PR #107 makes TARGET_ACTIVE dispatch re-read authorization through a live resolver. The executor currently checks only that the resolver returns a non-`None` object whose `grant_id` equals the run snapshot.

That is not sufficient to establish that the returned authority object is canonical. A duck object or `AuthorizationGrant` subclass can preserve the grant id while supplying different `scope` or `is_current()` behavior. The substituted object then reaches `ExecutionPolicy` as if it were authoritative live state.

## Acceptance contract

For TARGET_ACTIVE execution:

1. resolver output is either `None` or an exact `AuthorizationGrant`;
2. duck grant objects fail closed before policy evaluation and handler dispatch;
3. `AuthorizationGrant` subclasses fail closed before policy evaluation and handler dispatch;
4. an exact resolver-returned grant with the same id remains subject to the existing policy checks;
5. rejected output cannot widen assets, capabilities, risk, validity or tenant lineage;
6. rejection writes no evidence and leaves execution state unchanged.

This is intentionally tests/docs only. PR #107 retains `ToolExecutor` production ownership. #938 separately owns resolver lifetime binding; #567/#743/#873 and related families separately own field-level grant/request identity integrity.

## Safety

The regression uses temporary SQLite state and an inert in-process handler. It performs no DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
