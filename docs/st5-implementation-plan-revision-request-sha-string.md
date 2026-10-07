# ST5 implementation-plan revision-request exact SHA string boundary

This tests/docs-only acceptance slice sits directly above the strict persisted
implementation-plan revision-request handoff in #501.

## Gap

The persisted SHA validator currently combines `isinstance(value, str)` with
`len(value)` and character iteration. Those are polymorphic for a `str`
subclass.

The regression demonstrates lineage objects whose actual stored value is
`NOT-A-CANONICAL-SHA`, while overridden length and iteration make the validator
observe 64 lowercase hexadecimal characters. The outer revision-request digest
is recomputed over the actual stored value, so the current parser and dataclass
can admit noncanonical review, review-request, plan or implementation-request
lineage even while their validator reports canonical SHA shape.

A second regression requires the outer `revision_request_sha256` itself to be
an exact built-in string rather than a subclass, even when its underlying text
is otherwise canonical.

## Required contract

All five persisted SHA fields must be exact built-in `str` values containing
exactly 64 lowercase hexadecimal characters:

- `review_sha256`;
- `review_request_sha256`;
- `plan_sha256`;
- `implementation_request_sha256`;
- `revision_request_sha256`.

String subclasses fail closed before digest composition. Canonical exact
built-in strings remain accepted.

## Collision boundary

This slice is separate from #516 reviewer provenance string typing, #510 outer
mapping typing, #506 parser-input purity, #507 live-validation atomicity and
#486 builder atomicity. It adds one regression module plus this document only
and does not modify #501 source/tests/docs or any revised-plan/source-owner
lane.

The branch is based on exact #501 head
`81cd78f074a777a0380672050082fd21616a447c`.

## Safety

Persisted lineage-integrity proof only. It does not invoke a model, interact
with a target, create tools or execution authority, execute remediation/retests,
deploy, create a security verdict, or mutate attack paths.
