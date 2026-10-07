# ToolExecutor RunContext object identity

Issue: #944  
Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

`RunContext` is the immutable execution snapshot carrying mode, approved risk, tenant lineage, lab state and authorization into `ToolExecutor.execute()`.

The current boundary trusts the outer object by annotation only. A duck object or subclass can therefore supply caller-controlled attribute behavior before mode/risk/authorization checks have established that the immutable context itself is canonical.

## Acceptance contract

- `ToolExecutor.execute()` accepts only `type(context) is RunContext`;
- exact canonical contexts preserve existing behavior;
- `RunContext` subclasses fail closed before handler invocation;
- structurally compatible duck contexts fail closed before handler invocation;
- rejected contexts produce no evidence and are not normalized or repaired.

Field-level execution lineage, risk, mode and grant contracts remain separate; this contract establishes only the outer immutable context identity.

## Expected proof posture

The exact-context analysis control is expected GREEN. Subclass and duck-context rejection are intentionally expected RED on the pinned source.

## Ownership and safety

PR #107 retains ToolExecutor/live-revalidation production ownership. This branch is tests/docs only.

All regressions are local and use a test-only ANALYSIS handler. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
