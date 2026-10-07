# Durable grant validity datetime exact-type acceptance

Tracked by #738.

## Boundary

`AuthorizationGrant.is_current()` must not let polymorphic objects stored in `valid_from` or `valid_until` participate in authorization-window comparisons.

The canonical issuance path is separately hardened by #647. This acceptance covers a directly constructed in-memory `AuthorizationGrant`, including the object form that `ExecutionPolicy` can receive directly.

## Required behavior

- an exact built-in future `valid_from` remains non-current;
- an exact built-in expired `valid_until` remains non-current;
- a `datetime` subclass in `valid_from` is rejected before it can override the lower-bound comparison;
- a `datetime` subclass in `valid_until` is rejected before reflected comparison can override the upper bound;
- rejection does not mutate the grant.

Current PR #100 source is expected RED for the two polymorphic stored-boundary methods because `AuthorizationGrant.is_current()` does not require exact built-in validity datetime types.

## Non-overlap

- #647 owns issuance/persistence exact datetime typing;
- #734 owns the caller-supplied `now=` datetime subtype;
- #731 owns the equivalent legacy `models.Authorization` stored-boundary contract.

This branch is tests/docs only and is pinned to PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Safety

Authorization narrowing only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
