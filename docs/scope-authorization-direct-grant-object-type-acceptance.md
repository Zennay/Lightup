# Direct authorization-grant object identity acceptance

Tracked by #741.

## Boundary

`ExecutionPolicy.decide()` must not trust arbitrary objects merely because they expose the same attributes as `AuthorizationGrant`.

The outer authorization object itself is a security boundary. A subclass can override `is_current()`; a duck object can provide matching lineage, a canonical-looking scope and an always-true validity method.

## Required behavior

Canonical controls:

- an exact current `AuthorizationGrant` with matching lineage/scope remains allowed;
- an exact expired `AuthorizationGrant` remains denied.

Hardening acceptance:

- an expired `AuthorizationGrant` subclass whose `is_current()` always returns true is denied;
- a duck-typed grant with matching fields and always-current behavior is denied;
- rejection leaves the supplied object state unchanged.

Current PR #100 policy source is expected RED for exactly the two non-canonical outer grant-object cases because it does not require `type(request.authorization) is AuthorizationGrant`.

## Non-overlap

- #740 owns the nested direct `grant.scope` object;
- #734/#735/#737/#738 own fields and semantics inside a canonical grant;
- #106 owns authoritative re-resolution in the canonical target-dispatch path.

This branch is tests/docs only and is pinned to PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Safety

Deterministic in-memory policy proof only. No handler invocation, DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment or authority widening.
