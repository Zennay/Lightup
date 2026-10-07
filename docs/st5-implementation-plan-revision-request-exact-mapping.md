# ST5 implementation-plan revision-request exact mapping boundary

This tests/docs-only acceptance slice sits directly above the strict persisted
implementation-plan revision-request handoff in #501.

## Gap

The direct dict parser currently accepts `dict` subclasses. A subclass can
retain one caller-visible persisted value while overriding `__getitem__` so
the parser validates a different value.

The regression demonstrates this with reviewer-model provenance: the underlying
mapping stores a blank reviewer model id, while polymorphic lookup presents the
canonical model id from the legitimate request. The current parser therefore
treats a caller-owned mapping with divergent storage/lookup semantics as if it
were a canonical persisted object.

## Required contract

`future_remediation_implementation_plan_revision_request_from_dict` must accept
only an exact built-in `dict`. Dict subclasses must fail closed before field
reads. A canonical exact built-in dict remains accepted and retains the
planning-only authority stop line.

## Collision boundary

This slice adds one regression module and this document only. It does not modify
#501 source/tests/docs, #506 parser-input-purity work, #507 live-validation work,
#486 builder atomicity, implementation-plan producer/reviewer ownership, scope
authorization, provider behavior, target-capable code, remediation execution or
retest execution.

The branch is based on exact #501 head
`81cd78f074a777a0380672050082fd21616a447c`.

## Safety

Persistence-integrity regression only. It does not invoke a model, touch a
target, create tools or execution authority, execute remediation/retests,
deploy, create a security verdict, or mutate attack paths.
