# ToolExecutor ToolCall object identity

Issue: #946  
Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

`ToolCall` is the immutable request object consumed by `ToolExecutor.execute()` for registry selection, argument extraction and asset binding.

The current boundary trusts the outer object by annotation only. A duck object or subclass can therefore supply caller-controlled attribute or method dispatch before the executor has established that the call shape itself is canonical.

## Acceptance contract

- `ToolExecutor.execute()` accepts only `type(call) is ToolCall`;
- exact canonical calls preserve existing behavior;
- `ToolCall` subclasses fail closed before handler invocation;
- structurally compatible duck calls fail closed before handler invocation;
- rejected calls produce no evidence and are not normalized or repaired.

Field-level tool ID, asset and argument contracts remain separate; this contract establishes only the outer immutable call identity.

## Expected proof posture

The exact-call ANALYSIS control is expected GREEN. Subclass and duck-call rejection are intentionally expected RED on the pinned source.

## Ownership and safety

PR #107 retains ToolExecutor/live-revalidation production ownership. PR #156 retains ToolRegistry schema/registration source ownership. This branch is tests/docs only.

All regressions are local and use a test-only ANALYSIS handler. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
