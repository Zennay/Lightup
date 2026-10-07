# Direct grant approval provenance boundary

Issue: #777  
Composition owner: #778

Pinned production source owner: PR #100 exact head `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`.

## Contract

A directly supplied `AuthorizationGrant` may authorize `TARGET_ACTIVE` work only when `approved_by` and `reference` are exact built-in strings, non-empty after trimming, and already stored in canonical trimmed form.

Blank, whitespace-only, padded, and polymorphic string provenance must fail closed without normalization or mutation. Canonical direct grants retain their existing policy behavior.

## Ownership

#649 owns issuance-time provenance typing and normalization. #475/#554 own persisted provenance revalidation. #737 owns revocation provenance coherence. #743/#744 own direct client/engagement lineage typing and the earlier direct-grant pack. PR #100 keeps all production source.

This file and its paired test are copied into #778 solely to compose #777 above the #744 acceptance head.

## Safety

Pure in-memory authorization narrowing. No target interaction, scanning, handler execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation.
