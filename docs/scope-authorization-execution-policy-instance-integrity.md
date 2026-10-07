# ExecutionPolicy instance integrity

Issue: #935  
Pinned integration parent: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

The central execution policy must remain authoritative for the lifetime of a `ToolExecutor`.

Issue #779 separately requires constructor input to be either omitted or an exact `ExecutionPolicy`. Exact type identity is necessary but not sufficient while an exact policy instance still has writable per-instance attributes: caller code can shadow `decide` after construction and preserve the same exact object identity.

That turns a retained canonical object into a post-construction policy replacement channel.

## Acceptance contract

- an exact `ExecutionPolicy` instance remains valid constructor input, preserving #779;
- caller code cannot assign/shadow `decide` on a canonical policy instance;
- attempted instance rewiring cannot convert an out-of-scope TARGET_ACTIVE call into an allow;
- the denied call invokes no handler and writes no evidence;
- no new policy extension point is introduced.

A minimal production repair belongs on the active execution-policy source owner (PR #100 lineage). PR #107 keeps `ToolExecutor` and live authorization-revalidation ownership. This branch is tests/docs only and does not modify either owner.

## Expected proof posture

The regression is intentionally RED on the pinned source because `ExecutionPolicy` currently permits instance-level method shadowing. The integrated test demonstrates the consequence entirely offline with an out-of-scope documentation hostname and a test-only handler.

## Safety

No DNS resolution, socket use, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
