# Durable grant revocation-coherence acceptance

Tracked by #737.

## Boundary

Draft PR #100 adds revocation state to `AuthorizationGrant`. The direct in-memory object must fail closed when revocation provenance is internally inconsistent.

A grant with `revoked_by` and/or `revocation_reason` but no `revoked_at` cannot be treated as an ordinary unrevoked authorization merely because the timestamp is absent.

## Required behavior

- canonical all-`None` revocation state may remain current when the time window is current;
- canonical revoked state with an aware `revoked_at` is non-current;
- actor-only stale revocation provenance is non-current;
- reason-only stale revocation provenance is non-current;
- actor + reason without a revocation timestamp is non-current;
- rejection does not mutate or normalize the frozen grant.

Current PR #100 source is expected RED for the three stale-provenance cases because `AuthorizationGrant.is_current()` denies only when `revoked_at is not None`.

## Non-overlap

- #722 owns the equivalent legacy `models.Authorization` boundary;
- #560/#562 own persisted durable-grant reconstruction/coherence;
- #347/#734/#735 own durable grant time-evaluation semantics.

This branch is tests/docs only and is pinned directly to PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Safety

Authorization narrowing only. No DNS/network I/O, target interaction, scanning, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
