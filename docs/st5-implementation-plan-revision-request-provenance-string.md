# ST5 implementation-plan revision-request provenance string boundary

This tests/docs-only acceptance slice sits directly above the strict persisted
implementation-plan revision-request handoff in #501.

## Gap

Reviewer provider/model provenance currently passes through an
`isinstance(value, str)` check followed by `.strip()`. That admits subclasses
with storage semantics that differ from validation semantics.

The regression uses a `str` subclass whose underlying persisted text is one
blank character while its overridden `.strip()` returns non-blank text. The
revision-request digest is recomputed over the actual blank stored value, so
digest integrity alone cannot make this field canonical. Current code accepts
the subclass and lets blank underlying reviewer provenance enter the typed
artifact.

## Required contract

`reviewer_provider_id` and `reviewer_model_id` must be exact built-in
`str` values before non-blank/NUL/bounds validation. String subclasses fail
closed. Canonical exact strings remain accepted and the planning-only authority
stop line stays unchanged.

## Collision boundary

This is separate from #510's outer exact-`dict` boundary, #506 parser-input
purity, #507 live-validation atomicity and #486 builder atomicity. It adds one
regression module plus this document only and does not modify #501 source/tests/
docs or any scope-authorization/source-owner lane.

The branch is based on exact #501 head
`81cd78f074a777a0380672050082fd21616a447c`.

## Safety

Persisted metadata-integrity proof only. It does not invoke a model, interact
with a target, create tools or execution authority, execute remediation/retests,
deploy, create a security verdict, or mutate attack paths.
