# Scope authorization: membership-first review (2026-10-12)

Status: independent documentation-only review; no production authorization change.

## Safety invariant
A grant proves permission for an already-declared target; it must never establish target membership. For every target, validate canonical identity, then explicit hostname/CIDR membership, then current, asset-bound authorization, then execution admission. Missing or malformed target identity is invalid regardless of grant. A public host outside the allowlist and a public address outside every declared CIDR remain out of scope even when the grant is current or public-authorization checks are disabled.

## Review checklist
- [ ] Exact target identity validation rejects empty, malformed and polymorphic values before grant evaluation.
- [ ] Explicit host membership cannot be minted by legacy Authorization.
- [ ] Explicit CIDR membership cannot be minted by legacy Authorization.
- [ ] Public authorization opt-out does not widen declared target membership.
- [ ] Authorization asset scope is immutable, exact and revocable; validity timestamps and provenance are checked.
- [ ] Decision remains offline and deterministic without DNS, socket or HTTP calls.
- [ ] Integration owner confirms tests against the current source-owner PR and permanent self-hosted CI.

## Ownership
Existing issue #364 owns the focused membership regression; PR #100 and related authorization branches own production changes. This review intentionally adds no tests duplicating #364 and changes no source, activation, web, execution, state, or scanning code. Do not merge/deploy without owner review and exact-head CI evidence.
