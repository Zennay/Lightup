# Legacy Authorization revocation-coherence acceptance

Tracking: #722  
Pinned source owner: draft PR #100 at `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`

## Contract

The legacy public-scope `lightup.models.Authorization` object has one canonical unrevoked state:

- `revoked_at is None`
- `revoked_by is None`
- `revocation_reason is None`

If audit provenance says a revocation actor and/or reason exists while `revoked_at` is absent, the authorization must fail closed before it can authorize a public host or network.

A canonical revoked tuple with timestamp + actor + reason remains denied as revoked. A canonical all-None unrevoked tuple remains usable when its time and asset checks pass.

## Expected RED on the pinned source owner

PR #100 currently implements `Authorization.is_revoked` as `revoked_at is not None`. Therefore all three stale-provenance shapes below remain apparently unrevoked and can authorize an explicitly scoped public asset:

1. actor only;
2. reason only;
3. actor + reason.

Those are three expected failing acceptance methods. The canonical unrevoked and canonical revoked controls remain green.

## Distinction from durable grants

#560/#562 constrain persisted `authorization_grants` at execution-time reconstruction. #722 is specifically the legacy in-memory/public-scope `models.Authorization` boundary owned by PR #100.

## Collision boundary

Tests and documentation only. No edits to `src/lightup/models.py`, durable grant/session resolvers, #560/#562, #719, activation/execution-policy source, target-capable workers, evidence-remediation, deployment, verdict or attack-path code.

## Safety

Authorization narrowing only. Offline/in-process proof; no DNS/network I/O, target interaction, scanning, exploit behavior, authority widening, remediation/retest execution, deployment, verdict creation or attack-path mutation.
