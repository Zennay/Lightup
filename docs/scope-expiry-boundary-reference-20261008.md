# Scope authorization — expiry boundary reference (offline)

**Phase:** LightUp M7/ST5, PLAN/LAB ONLY. This is a proposal and independent test oracle, **not** integrated authorization enforcement.

## Proposed contract
- An injected, trusted integer UTC epoch second `now` is required. Do not silently fall back to host/local time, parse dates with permissive coercion, or accept Boolean-as-integer.
- Grant interval is `not_before <= now < expires_at`. Issuance must not postdate `not_before`; zero-duration, reversed and malformed intervals are denied.
- Tenant, engagement and grant identifiers bind by exact nonempty string equality. Extra/missing fields or invalid revocation markers deny in the offline strict schema.
- Revalidate grant at the last possible point before any target-active dispatch, and require the production owner to establish the trusted time source and persistence semantics.
- **Clock rollback hazard:** this stateless reference returns eligible after a clock rewinds below expiry. Production needs a trusted monotonic persisted high-water mark or equivalent rollback denial; tests intentionally expose this limitation instead of suggesting safety.
- Explicit consent, provenance, effective scope, non-revocation, capability safety and durable policy enforcement remain separate obligations. A passing reference test cannot authorize a target.

## Execute (offline)
`python -m unittest discover -s tests -p 'test_scope_expiry_boundary_reference_20261008.py' -v`

## Integration gate
PR #107 retains production-executor ownership; release evidence requires exact-head hosted CI, permanent VPS runner verification, source-owner review, and integrated deny-before-handler tests. This branch adds only synthetic offline reference tests and documentation. No real target, DNS, socket, scanning, handler dispatch, or deployment.
