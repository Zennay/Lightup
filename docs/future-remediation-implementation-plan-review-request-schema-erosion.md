# Implementation-plan review-request schema erosion contract

Issue: #306

## Purpose

The strict ST5 implementation-plan review-request handoff is planning-only persistence metadata. Its schema must fail closed under container erosion, primitive type confusion and malformed provenance instead of relying on Python annotations or truthiness.

This slice is tests/docs-only and remains separate from #303 snapshot isolation.

## Invariants

The dedicated regressions prove that:

- canonical JSON and programmatic dictionaries round-trip to the exact request;
- top-level JSON must decode to an object and direct persisted input must be a dictionary;
- missing or unexpected top-level fields fail closed;
- `required_checks` remains a list/tuple matching the complete fixed rubric exactly;
- missing, extra, reordered or type-confused rubric entries fail closed;
- planner provider/model provenance is string-typed, non-empty, NUL-free and bounded;
- `plan_item_count` is a positive exact integer and rejects bool/float/string/null confusion;
- every lineage digest remains a canonical lowercase SHA-256 value;
- `implementation_plan_review_requested` remains exact true;
- plan acceptance and all seven action-authority fields remain exact false, including integer-lookalike confusion;
- future semantics remain unresolved and the security verdict remains not evaluated.

## Collision boundary

This slice adds only:

- `tests/test_future_remediation_implementation_plan_review_request_schema_erosion.py`;
- `docs/future-remediation-implementation-plan-review-request-schema-erosion.md`.

It does not modify #278/#280 source/tests/docs, #303 snapshot-isolation files, or downstream implementation-plan review/revision work.

## Safety

Persistence/schema integrity only. No model invocation, target interaction, code/tool execution, remediation/retest execution, deployment, future-state resolution, verdict creation, or attack-path mutation is introduced.
