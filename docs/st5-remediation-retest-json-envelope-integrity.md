# ST5 remediation/retest outer JSON envelope integrity

This contract closes the outermost persisted-input boundary for the strict ST5
remediation/retest plan handoff introduced by PR #190.

## Boundary

The JSON entry point must accept the canonical producer output, but it must not
coerce a different JSON root into a remediation/retest plan. JSON `null`,
arrays, booleans, numbers and strings therefore fail closed at the object
boundary.

Malformed transport text also remains fail closed. Empty input, whitespace-only
input, truncated JSON and valid JSON followed by trailing garbage cannot reach a
typed plan.

JSON object keys are compared after JSON escape decoding. An escaped spelling
such as `\u0070lan_complete` is the same key as `plan_complete`; if both
appear in the same top-level object, the duplicate-key hook rejects the payload
before ordinary last-value-wins decoding can collapse it.

## Relationship to sibling integrity work

This slice is intentionally narrow:

- issue #371 owns duplicate-key rejection inside nested remediation/retest items;
- issue #373 owns nested item schema and lineage-container integrity;
- #354/#355 own caller-input purity and parse-to-live-validation atomicity;
- this issue owns only the outer JSON envelope and decoded top-level key alias
  boundary.

No PR #190 implementation or existing test is modified.

## Safety stop line

This proof is persistence-only. It grants no evidence collection, target
interaction, tool execution, remediation, retest execution, deployment,
attack-path mutation, future-state resolution or security verdict.

The canonical typed plan remains fail closed:

- `execution_allowed=false`
- `deployment_authorized=false`
- `attack_path_mutation_allowed=false`
- `future_semantics=unresolved`
- `security_verdict=not_evaluated`
