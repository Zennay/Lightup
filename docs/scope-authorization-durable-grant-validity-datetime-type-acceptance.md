# Durable grant validity datetime exact-type acceptance

Tracked by #738.

## Boundary

`AuthorizationGrant.is_current()` must validate the stored `valid_from` / `valid_until` objects before they participate in authorization-window comparisons.

The canonical issuance path is separately hardened by #647. This acceptance covers a directly constructed in-memory `AuthorizationGrant`, including the object form that `ExecutionPolicy` can receive directly.

## Required behavior

Canonical controls:

- an exact built-in aware future `valid_from` remains non-current;
- an exact built-in aware expired `valid_until` remains non-current.

Malformed stored boundaries must be rejected through a controlled `ValueError` before comparison:

- a `datetime` subclass in `valid_from`;
- a `datetime` subclass in `valid_until`;
- a timezone-naive exact `datetime` in `valid_from`;
- a timezone-naive exact `datetime` in `valid_until`;
- an ordinary non-datetime `valid_from`;
- an ordinary non-datetime `valid_until`.

Current PR #100 source is expected RED for exactly **6** malformed-boundary methods: subtype comparisons can spoof authority, while naive/non-datetime boundaries currently reach incidental comparison errors instead of the explicit authorization validation boundary.

## Non-overlap

- #647 owns issuance/persistence exact datetime typing;
- #734/#735 own the caller-supplied `now=` boundary;
- #731 owns the equivalent legacy `models.Authorization` stored-boundary contract.

This branch is tests/docs only and is pinned to PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Safety

Authorization narrowing only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
