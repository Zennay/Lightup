# ToolExecutor registry identity and lifetime binding

Issue: #940  
Pinned source owner: PR #107 exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`

## Boundary

`ToolExecutor` relies on registry metadata to decide which mode, risk level and capability a handler belongs to. The registry is therefore part of the pre-handler authorization boundary.

Annotation-only constructor trust permits a duck registry to bypass `ToolRegistry.register()` entirely. Keeping the registry in a writable executor attribute also permits post-construction replacement, allowing caller code to change a tool from TARGET_ACTIVE to ANALYSIS (or otherwise change authorization-relevant metadata) without reconstructing the executor.

## Acceptance contract

- constructor admission accepts only `type(registry) is ToolRegistry`;
- duck registries and `ToolRegistry` subclasses fail closed before execution;
- an exact registry remains accepted;
- the registry selected at construction is immutable for the executor lifetime;
- replacement cannot reclassify an active tool into an analysis/passive path;
- denial invokes no handler and persists no evidence.

This contract is distinct from ToolRegistry's own definition/schema admission family (#907/#908/#911/#913), which remains owned by PR #156. PR #107 retains all ToolExecutor source ownership.

## Expected proof posture

Exact-registry construction and the initial mode denial are expected GREEN. Duck/subclass constructor rejection and lifetime binding are intentionally expected RED on the pinned source.

## Safety

The regression uses test-only handlers and local state. It performs no DNS/network I/O, target interaction, scanning, real capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
