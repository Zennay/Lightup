# ToolExecutor policy lifetime binding

Issue: #942  
Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

`ToolExecutor` must keep using the policy admitted at construction for its full lifetime.

#779 separately constrains which policy object may enter the constructor. #935 separately prevents instance-level `decide` shadowing on an exact `ExecutionPolicy`. Neither contract prevents replacing `executor.policy` itself after construction.

That replacement channel can swap a canonical deny-capable policy for an allow-all object immediately before dispatch.

## Acceptance contract

- the policy selected during construction remains bound for the executor lifetime;
- post-construction assignment to `executor.policy` fails closed;
- an attempted replacement cannot convert an out-of-scope TARGET_ACTIVE request into execution;
- denial occurs before handler invocation and before evidence persistence;
- #779 and #935 remain independent, unchanged contracts.

This branch is tests/docs only. PR #107 retains all ToolExecutor source ownership; PR #100 retains ExecutionPolicy source ownership.

## Expected proof posture

The initial canonical out-of-scope denial is expected GREEN. Policy-attribute replacement and the second denial are intentionally expected RED on the pinned source.

## Safety

The regression uses only local state, documentation hostnames and a test-only handler. No DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation occurs.
