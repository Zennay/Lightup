# Scope authorization: pre-authorization engagement lifecycle gate

Issue: #651  
Source owner: draft PR #554  
Exact parent head: `4c8d5651fc0e23f94514daae56b4e5fe0549de37`

## Boundary

The target-active authorization resolver already re-reads the durable engagement row before returning a live grant. Draft #554 rejects malformed lifecycle text and `closed`, but it currently accepts every other canonical `EngagementStatus`.

That means a previously persisted/current grant can still resolve while its engagement is only `draft` or `authorization_pending`.

This is deliberately separate from #177. #177 owns issuance provenance: an authorization grant must eventually be bound to an approved assessment request. #651 is defense in depth at execution time: even when a legacy or otherwise invalid grant row already exists, pre-authorization engagement state must not produce target-active authority.

## Contract

The resolver must return no executable grant while durable lifecycle is:

- `draft`;
- `authorization_pending`;
- `closed` (existing invariant).

A canonical current grant remains resolvable in the unambiguous active controls:

- `authorized`;
- `running`.

Resolution must not update, normalize, or otherwise rewrite the engagement row.

This slice intentionally leaves `remediation` and `retest` semantics undecided. Their target-active policy belongs to the lifecycle/activation owner rather than being guessed here.

## Expected RED on #554

At exact #554 head the resolver parses the durable enum and only rejects:

```python
if engagement_status is EngagementStatus.CLOSED:
    return None
```

So canonical `DRAFT` and `AUTHORIZATION_PENDING` currently survive resolution. The first acceptance test is therefore expected RED until the source-owning composition adds an explicit pre-authorization lifecycle denial.

The inherited #550 regression used `DRAFT` as a generic "canonical non-closed" control while proving malformed enum handling. When #651 is absorbed, that control must be narrowed to an actually executable canonical lifecycle state such as `AUTHORIZED`; #550's malformed-enum invariant itself remains unchanged.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_pre_authorization_lifecycle.py`;
- `docs/scope-authorization-pre-authorization-lifecycle.md`.

There are **0 production/source changes**. Do not edit `src/lightup/domain.py` here; draft #554 retains resolver ownership. Do not implement #177 request→grant provenance, activation transitions, orchestration, handlers, target interaction, scanning, remediation/retest execution, deployment, verdict creation, or attack-path mutation.

The proof uses temporary SQLite state only and performs no network I/O.
