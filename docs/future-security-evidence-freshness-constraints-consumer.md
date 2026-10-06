# Persisted evidence-freshness constraints consumer

The strict ST5 freshness-constraints parser proves that a persisted object is
canonical and internally self-consistent. That is not enough to prove the
constraints are still valid against current evidence state.

`load_and_validate_future_security_evidence_freshness_constraints` therefore
composes persistence integrity with live validation:

1. JSON text rejects duplicate object keys before normalization;
2. JSON/object input passes through the existing exact constraints parser; and
3. the parsed constraints are immediately rebuilt against the live evidence
   collection request, remediation lineage and StateStore.

A successful return means the persisted constraints are both serialization-valid
and equal to the current live-validated constraints.

## Fail-closed JSON boundary

Duplicate-key rejection applies recursively to nested freshness items and prior
evidence objects. This prevents ordinary JSON last-key-wins behavior from
choosing one of two conflicting values before the strict schema boundary sees
the payload.

Malformed JSON, non-object values, digest drift and any existing strict parser
violation continue to fail closed.

## Safety semantics

This consumer does not authorize collection, select a capability or tool,
create a tool call, interact with a target, author remediation, authorize a
future-state retest, deploy, classify an outcome, or mutate attack paths.

It performs no target interaction and adds no execution authority.
