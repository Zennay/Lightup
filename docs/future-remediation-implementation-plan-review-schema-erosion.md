# Implementation-plan review schema erosion contract

Issue: #305

## Purpose

The strict ST5 implementation-plan review handoff is a persistence boundary. Exact schema validation must survive not only ordinary field tampering but also schema erosion and type-confused nested review-check shapes.

This slice is intentionally tests/docs-only. It does not modify the #281 reviewer, the #283 handoff implementation, or their existing owner tests.

## Invariants

The dedicated regressions prove that:

- canonical review JSON and programmatic dictionaries still round-trip exactly;
- top-level JSON must decode to an object and direct persisted input must be a dictionary;
- missing or unexpected top-level fields fail closed;
- `checks` must remain a list/tuple with the exact canonical count;
- every nested check must remain an object with exactly `check` and `result`;
- missing nested keys, unexpected nested keys and non-object substitutions fail closed;
- check results reject booleans, integers, nulls, non-canonical casing and empty strings;
- check names remain position-bound to the fixed review rubric;
- the decision remains a canonical review-decision value rather than a bool/int/null/string lookalike;
- valid `revision_required` and `insufficient_evidence` artifacts remain supported while every action-authority field stays false.

## Collision boundary

Only these files belong to this slice:

- `tests/test_future_remediation_implementation_plan_review_schema_erosion.py`;
- `docs/future-remediation-implementation-plan-review-schema-erosion.md`.

The existing #283 test module is not edited, including its separately owned tuple-reorder fixture. #284, #287 and #298 remain untouched.

## Safety

This is persistence/schema integrity only. No model invocation, target interaction, code/tool execution, remediation/retest execution, deployment, future-state resolution, security verdict creation, or attack-path mutation is introduced.
