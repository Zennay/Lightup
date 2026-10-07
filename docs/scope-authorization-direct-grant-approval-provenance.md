# Direct grant approval provenance boundary

Issue: #777

Pinned source owner: PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Contract

A directly supplied `AuthorizationGrant` may authorize `TARGET_ACTIVE` work only when its approval provenance is producer-canonical:

- `approved_by` is an exact built-in `str`, non-empty after trimming, and already trimmed;
- `reference` is an exact built-in `str`, non-empty after trimming, and already trimmed;
- callers do not gain authorization by supplying blank, whitespace-only, padded, or polymorphic provenance;
- malformed direct provenance fails closed without normalization or mutation;
- canonical grants keep existing policy behavior.

The acceptance module intentionally exercises the standalone `ExecutionPolicy` boundary with an otherwise valid exact `AuthorizationGrant`. On the pinned #100 source head, the malformed cases are expected RED because approval provenance is not consulted before the allow decision.

## Ownership and non-overlap

This branch is tests/docs only and changes no production source.

Separate ownership remains:

- #649 — issuance-time provenance input typing and normalization;
- #475/#554 — persisted provenance integrity during live durable resolution;
- #737 — revocation provenance coherence;
- #743/#744 — direct grant client/engagement lineage typing;
- #740/#741 — direct scope/grant outer object identity;
- #773/#775/#776 — direct `ScopeDefinition` risk/collection integrity;
- PR #100 — all production implementation for the active authorization chain.

## Safety

This is a pure in-memory fail-closed authorization acceptance contract. It performs no DNS or network I/O, target interaction, scanning, capability/handler execution, remediation, retest, deployment, verdict creation, or attack-path mutation.

## Promotion posture

Keep this acceptance branch PR-less while the LightUp self-hosted queue is saturated. The source owner can absorb the minimal invariant later and prove it on its canonical exact head.
