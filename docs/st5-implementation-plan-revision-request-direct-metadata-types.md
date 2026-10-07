# ST5 implementation-plan revision-request direct metadata types

## Scope

This acceptance slice is a tests/docs-only child of the bounded implementation-plan revision-request producer in #284.

- exact parent head: `c5fcb1d0d5f91d861010a1e06e6a764e2e917326`
- acceptance issue: #528
- source owner: #284

It does not modify #284 source, #486 builder atomicity, #501 strict persisted handoff, #510/#516/#522 persisted parser/type contracts, #507 live-validation atomicity, or scope-authorization work.

## Invariant

The typed revision-request artifact must reject polymorphic subclasses for fixed metadata before equality or iteration can influence validation.

Canonical direct construction must use exact built-in types for:

- `schema_version` — exact `str`;
- `required_revisions` — exact `tuple`;
- `source_review_decision` — exact `str`;
- `future_semantics` — exact `str`;
- `security_verdict` — exact `str`.

This slice intentionally leaves SHA and reviewer-provenance exactness to their separately isolated downstream persisted-consumer contracts.

## Expected RED at #284

The current dataclass validates fixed strings with value equality and validates `required_revisions` with `isinstance(value, tuple)`.

A `str` subclass can therefore store a non-canonical value while overriding equality to appear canonical. A tuple subclass containing the canonical revision check likewise passes the current container guard. Neither case should be admitted to the typed artifact.

The regression expects five rejection tests to fail against the current #284 source while the canonical exact-built-in control remains green.

## Required source-owner repair

The #284 owner should require exact built-in `str` for the four fixed string metadata fields and exact built-in `tuple` for `required_revisions` before semantic validation. Reject rather than normalize, and preserve all existing digest and planning-only authority semantics.

## Safety

Pure in-memory planning-metadata integrity proof only. No model invocation, target interaction, scanning, tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation.
