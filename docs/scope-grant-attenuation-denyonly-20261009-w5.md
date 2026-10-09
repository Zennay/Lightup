# LightUp M7/ST5 — deny-only grant attenuation review (2026-10-09)

## Purpose

This owner-safe implementation is a **comparison primitive**, not an approval, grant,
trust anchor, policy replacement, or dispatch authorization. It answers only whether
a *proposed snapshot* is no more permissive than an existing *snapshot*. It never
contacts a target, reads the network or durable grant store, rotates sessions,
issues a permit, or mutates an approved authorization. Both inputs can be forged:
a positive result must **never** be interpreted as consent.

## Restriction contract

`compare_grant_attenuation(approved, proposal)` requires exact built-in
`AuthorizationGrant` and `ScopeDefinition` shapes and exact `RiskLevel`
instances. Missing or polymorphic identities, bad flags, invalid calendar windows,
duplicated/invalid scope members or unbounded collections reject. Both time\nvalues must be native `datetime` with a built-in fixed-offset `timezone`; custom\n`tzinfo` implementations are denied before their callbacks can run.

A proposal cannot change grant/client/engagement/operator/reference identities;
add assets; remove exclusions; increase maximum risk; extend authorization
earlier/later; expand capabilities; or enable previously disabled recurring retests.
It may reduce assets and capabilities, add exclusions, lower risk, shorten the
validity window and remove recurring-retest privileges.

**Important:** Under production `ScopeDefinition.allows_capability`, an
empty `allowed_capabilities` tuple means **unrestricted**, not **none**. A
finite allowlist may narrow from an unrestricted original but must not become
empty. Asset matching follows the real `strip().lower()` policy, while
capability IDs remain exact and case-sensitive.

## Integration boundary (HOLD)

- `nonexpanding=true` means only a safe *relative scope comparison*.
- A **fresh trusted** source must authenticate the approved baseline and proposed
  revision, validate issuer/operator/tenant/engagement provenance, approval and
  consent, enforce revocation and strict authorized run/asset/capability binding
  atomically at dispatch. Explicit per-action step-up remains independent.
- Never use this checker to create a grant, authorize a task, lower a live
  scope restriction or reactivate a revoked grant.
- Source-owner integration belongs to existing #107 (executor and trusted
  pre-I/O consent/revocation); #1174 owns strict execution-request typing;
  #1172 owns destructive lab step-up. This branch changes none of their files.
- Keep **DRAFT/HOLD** until exact-head host + permanent VPS validation, independent
  source-owner review, shared composition and real zero-I/O denial proofs.
- All regression fixtures are synthetic: no public DNS, scans, active targets,
  production database, credential keys or deployment authority.

## Test

```bash
PYTHONPATH=src python -m unittest tests.test_scope_grant_attenuation_20261009_w5 -v
```

Follow with the existing canonical LightUp offline/CI suite on the identical
immutable PR head. Pending or unrelated earlier heads are not proof.
