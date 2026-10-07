# Typed ToolRegistry integrity acceptance pack

Issue: #909

Pinned source owner: draft PR #156, exact head
`e84f2cd74d24f143c02b38cc05cb1c4c64352966`.

This branch composes two expected-RED, tests/docs-only contracts without
changing production source.

## Included contracts

- #907 — registry admission accepts only exact `ToolDefinition` objects.
  Subclasses and duck objects must fail before insertion so polymorphic
  `validate_arguments()` behavior cannot replace the typed argument boundary.
- #908 — every nested `ToolParameter.required` marker must be an exact built-in
  boolean. Truthy/falsy lookalikes must fail before insertion rather than
  changing mandatory-argument semantics through Python truthiness.

## Intended source-owner absorption

PR #156 remains the sole production owner of the relevant
`src/lightup/ai/orchestration.py` ToolRegistry code. A future repair can absorb
both narrow admission guards while preserving all existing capability-state,
interaction and minimum-risk validation.

## Stop line

This pack grants no tool, target, network, remediation, retest, deployment,
security-verdict or attack-path authority. It only pins registry metadata
integrity.
