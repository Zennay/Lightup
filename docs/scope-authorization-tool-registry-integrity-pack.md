# Typed ToolRegistry integrity acceptance pack v2

Issues: #909, #912

Pinned source owner: draft PR #156, exact head
`e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

This branch composes three expected-RED, tests/docs-only contracts without
changing production source.

## Included contracts

- #907 — registry admission accepts only exact `ToolDefinition` objects.
  Subclasses and duck objects fail before insertion so polymorphic
  `validate_arguments()` behavior cannot replace the typed argument boundary.
- #911 — `ToolDefinition.parameters` must be an exact tuple containing only
  exact `ToolParameter` objects. Mutable/custom containers and polymorphic
  parameter objects fail before insertion, preventing post-registration schema
  drift.
- #908 — every nested `ToolParameter.required` marker must be an exact built-in
  boolean. Truthy/falsy lookalikes fail before insertion rather than changing
  mandatory-argument semantics through Python truthiness.

## Intended source-owner absorption

PR #156 remains the sole production owner of the relevant
`src/lightup/ai/orchestration.py` ToolRegistry code. A future repair can absorb
all three narrow admission guards while preserving existing capability-state,
interaction and minimum-risk validation.

## Stop line

This pack grants no tool, target, network, remediation, retest, deployment,
security-verdict or attack-path authority. It only pins registry and typed-tool
schema integrity.
