# ToolExecutor live authorization resolver binding integrity

Issue: #938  
Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

PR #107 makes TARGET_ACTIVE dispatch depend on a live authorization resolver. That guarantee must survive for the full lifetime of a `ToolExecutor`.

Keeping the resolver in a writable public instance attribute leaves a post-construction bypass: caller code can replace the authoritative resolver with a lambda returning the stale RunContext grant. Durable revocation, closure or deletion then stops being authoritative even though the executor was originally constructed correctly.

## Acceptance contract

- construction binds the resolver used for the executor lifetime;
- caller code cannot replace or shadow `authorization_resolver` after construction;
- a resolver that reports a grant absent/revoked continues to deny after a replacement attempt;
- denial occurs before the handler and before evidence persistence;
- no new resolver extension or fallback path is introduced.

This branch is tests/docs only. PR #107 retains all `ToolExecutor` and live-revalidation source ownership. Durable resolver correctness (#553/#554/#562 families) remains separate.

## Expected proof posture

The canonical first denial is expected GREEN. Post-construction resolver replacement is intentionally expected RED on the pinned source because the assignment currently succeeds and the stale grant can then reach the handler.

## Safety

All behavior is exercised with in-memory/test-only objects and a local StateStore. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
