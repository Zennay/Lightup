# Persisted evidence-freshness admission consumer

A freshness admission proves only that already-existing candidate evidence is
fresh relative to an unresolved evidence gap. The strict serialized handoff and
the live admission validator are both required before persisted admission data
is used.

`load_and_validate_future_security_evidence_freshness_admission` composes those
boundaries:

1. duplicate JSON object keys are rejected recursively before normalization;
2. JSON/object input passes through the exact strict admission parser; and
3. the typed admission is immediately rebuilt against live candidate evidence,
   freshness constraints, source lineage and StateStore.

A successful return therefore means the persisted admission is canonical and
still matches current live evidence.

## Safety semantics

Freshness does not establish evidence suitability or sufficiency. This consumer
does not select a classification, create a transition resolution, authorize
collection or a tool call, interact with a target, author remediation, run a
future-state retest, deploy, or mutate attack paths.

It performs no target interaction and introduces no execution authority.
