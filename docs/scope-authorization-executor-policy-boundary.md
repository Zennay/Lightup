# ToolExecutor policy construction boundary

Issue: #779

Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`.

## Contract

`ToolExecutor` is the product's central pre-handler policy gate. That boundary must not be replaceable through an annotation-only constructor argument.

The accepted construction forms are:

- omit `policy` / pass `None` and receive a canonical exact `ExecutionPolicy`;
- pass an exact `ExecutionPolicy` instance.

The following are non-canonical and must fail closed at construction:

- duck-typed objects exposing `decide()`;
- `ExecutionPolicy` subclasses that can override `decide()`.

This prevents a constructed executor from preserving the surrounding orchestration/live-resolver machinery while silently swapping out asset, capability, risk, or authorization policy.

## Ownership and non-overlap

This branch is tests/docs only.

- PR #107 keeps `ToolExecutor` and live authorization revalidation source ownership.
- PR #100 keeps the central execution-policy source chain.
- #771 owns canonical `ExecutionRequest` object identity.
- #567, #575, and #576 own request lineage, target asset, and capability identity typing.
- Durable grant/scope integrity families remain separate.

If extensibility is needed later, it should be represented by an explicit trusted policy-extension contract rather than arbitrary object substitution.

## Expected proof posture

The two canonical construction controls are expected GREEN on the pinned source. Duck-object and subclass rejection are intentionally expected RED until the active owner absorbs a minimal constructor guard.

## Safety

Constructor-integrity acceptance only. No network I/O, target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
