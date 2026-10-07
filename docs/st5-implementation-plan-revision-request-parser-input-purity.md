# ST5 implementation-plan revision-request strict parser input purity

This acceptance slice is a tests/docs-only child of the strict
implementation-plan revision-request handoff in #501.

## Invariant

`future_remediation_implementation_plan_revision_request_from_dict` must treat
caller-owned persisted dictionaries as read-only input.

The regression proves that:

- a canonical revision-request payload parses repeatedly to the same typed
  planning-only artifact;
- successful parsing leaves the caller dictionary value-identical to its deep
  snapshot and preserves the exact nested `required_revisions` container;
- exact-schema, canonical-digest, and nested revision-order rejection are
  deterministic across repeated calls;
- rejected dictionaries and their nested `required_revisions` container remain
  untouched;
- the parsed artifact stays revision-request-only: no revised implementation
  plan is created or accepted and every code/tool/execution/target/retest/
  deploy/attack-path authority flag remains false.

## Collision boundary

This slice adds one regression module and this document only. It does not modify
#501 parser/validator source or its existing tests/docs, #486 builder-atomicity
work, implementation-plan reviewer/revision producer ownership, scope
authorization, provider behavior, target-capable code, remediation execution or
retest execution.

The branch is based on the exact #501 head
`81cd78f074a777a0380672050082fd21616a447c`.

## Safety

Pure in-memory persisted-input integrity proof only. It does not touch
StateStore, invoke a model, interact with a target, execute remediation/retests,
deploy, create a security verdict, or mutate attack paths.
