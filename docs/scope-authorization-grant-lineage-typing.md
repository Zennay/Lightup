# Scope authorization: direct-grant lineage typing

This acceptance slice is pinned directly above active PR #100 exact head
`ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Invariant

Before a `TARGET_ACTIVE` request may inherit authority from an in-memory
`AuthorizationGrant`, both grant lineage identifiers must be canonical runtime
identities:

- `type(grant.client_id) is str`;
- `type(grant.engagement_id) is str`;
- both are non-empty;
- foreign `str` subclasses cannot spoof equality with canonical request
  lineage;
- same-text `str` subclasses are still non-canonical and denied;
- exact built-in string matches remain allowed;
- exact built-in mismatches remain denied.

The rejection boundary is pure and in-memory. It must not rewrite the request,
grant, scope, or durable state.

## Why this is an acceptance-only branch

PR #100 retains production-source ownership for the direct authorization policy.
This branch intentionally changes no production code. It captures the missing
fail-closed contract as executable regression proof so the active owner can
absorb it without conflicting edits.

## Expected result on the pinned parent

The canonical controls are expected green.

The subclass cases are intentionally expected red on the pinned parent because
`ExecutionPolicy.decide()` currently compares grant lineage by value only.
A `str` subclass can therefore override equality/inequality and make foreign
lineage appear equal.

## Collision boundary

Only:

- `tests/test_execution_policy_grant_lineage_typing.py`;
- `docs/scope-authorization-grant-lineage-typing.md`.

No edits to execution policy, engagement/domain state, activation,
orchestration, target-capable handlers, evidence-remediation, deployment,
verdict, or attack-path code.

## Safety

Authorization narrowing proof only. No DNS/network I/O, target interaction,
scanning, capability execution, remediation/retest execution, deployment, or
authority widening.
