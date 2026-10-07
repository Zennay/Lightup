# TARGET_ACTIVE execution lineage identity type contract

This branch pins a narrow authorization-boundary invariant above exact #554 head
`4c8d5651fc0e23f94514daae56b4e5fe0549de37`.

## Why this matters

The target-active path re-resolves the real durable `AuthorizationGrant`, then
binds it to `RunContext.client_id` and `RunContext.engagement_id` through
`ExecutionPolicy`.

Those two context fields are Python type hints, not runtime guards. A `str`
subclass can carry a different underlying tenant/engagement identity while
overriding equality and inequality so a value comparison reports a match.
Even a subclass whose underlying text exactly matches the durable identifier is
still a non-canonical runtime identity object and must not cross an
authorization boundary.

That is different from stale-grant or resolver substitution: the resolver still
returns the correct real durable grant. The type-confused context identity is
what crosses the lineage check and is then handed to the target-active handler.

## Required behavior

TARGET_ACTIVE execution must preserve all of these properties:

- matching exact built-in client + engagement strings remain executable;
- a plain mismatched client string remains denied;
- a plain mismatched engagement string remains denied;
- a `str` subclass carrying another client identity cannot equality-spoof the
  live grant binding;
- a `str` subclass carrying another engagement identity cannot equality-spoof
  the live grant binding;
- a `str` subclass is rejected even when its underlying text exactly matches
  the live client identity;
- a `str` subclass is rejected even when its underlying text exactly matches
  the live engagement identity;
- malformed lineage identities are denied before handler dispatch.

The dedicated acceptance module uses the real `DomainStore` live resolver and
an inert in-process target-active handler. It therefore exercises the composed
resolver → execution-policy → handler boundary rather than only a standalone
value comparison.

## Expected state

`tests/test_scope_authorization_execution_lineage_identity_types.py` contains
three canonical green controls and four polymorphic identity rejection cases.

Against the pinned #554 source, all four polymorphic cases are expected RED:
the equality-spoofing string subclass can make the current
`grant.client_id != request.client_id` or
`grant.engagement_id != request.engagement_id` comparison report no mismatch.
The matching-text cases additionally prove that value equality alone is
insufficient: authorization lineage identifiers themselves must be exact
built-in strings.

## Collision boundary

Tests and documentation only. This branch deliberately does not edit
`src/lightup/execution_policy.py`, `src/lightup/ai/orchestration.py`, domain
source, or existing tests.

Source ownership stays with the active execution-policy/orchestration lineage
(#112/#121/#163). This contract is separate from:

- #497 legacy `Target` object/value typing;
- #499 activation-reference typing;
- #116 run-mode coherence;
- #554 durable execution-resolver integrity;
- #562 persisted revocation tuple coherence.

The narrow eventual repair is to reject non-canonical execution lineage
identity types before value equality can participate in authorization.

## Queue policy

Keep this slice branch-only initially. It intentionally does not open another
LightUp PR while the permanent self-hosted lane already contains queued scope
authorization work.

## Safety

Offline/in-process authorization narrowing only. Temporary SQLite state and an
inert test handler are used. No DNS/network I/O, target interaction, scanning,
exploit behavior, remediation/retest execution, deployment, verdict creation,
or attack-path mutation occurs.
