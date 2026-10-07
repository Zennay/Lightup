# ST5 revised-plan review-request exact metadata types

## Scope

This acceptance slice is a tests/docs-only child of revised implementation-plan independent review request #517.

- exact parent head: `f8de987ad069a784751a9e38ce258f6a118cea11`
- acceptance issue: #526
- source owner: #517

It does not modify #517 source, #519 strict persisted review-request handoff, #525 builder atomicity, #521 revised-plan sequence hardening, or any scope-authorization lane.

## Invariant

The immutable review-request artifact must not accept polymorphic subclasses for fixed metadata whose meaning is defined by exact constants.

Canonical builder output must use exact built-in types for:

- `schema_version` — exact `str`;
- `required_checks` — exact `tuple`;
- `future_semantics` — exact `str`;
- `security_verdict` — exact `str`.

Direct construction must reject subclasses before equality-based validation.

## Expected RED at #517

The current source compares these fields by value equality. An adversarial `str` or `tuple` subclass can retain non-canonical stored content while overriding equality so the comparison appears canonical.

The request digest does not close this gap because the digest helper writes the fixed canonical constants for these fields rather than the polymorphic stored values supplied to direct construction.

The regression therefore expects four rejection tests to fail against the current #517 source while the exact-built-in control remains green.

## Required source-owner repair

The #517 owner should require exact built-in types before semantic equality checks, then preserve the existing fixed-value checks and deterministic digest behavior. Reject rather than normalize.

## Safety

This is in-memory metadata-integrity proof only. It invokes no model, performs no target interaction or scanning, creates no tool call, executes no remediation/retest, authorizes no deployment, creates no security verdict, and mutates no attack path.
