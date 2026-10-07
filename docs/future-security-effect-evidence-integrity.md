# Future security effect evidence integrity

Issue #860 narrows the ST3 `FutureSecurityEffect` typed-object boundary.

## Gap

A future security effect is only valid when it is backed by materialization evidence. Before this change, `validate()` required evidence to be present and unique but trusted the Python container and member types.

That was unsafe because `_effect_facts()` later emits Security Twin evidence references with:

```python
f"evidence:{item}"
```

A non-string item could therefore be stringified into an apparently normal evidence reference.

## Canonical contract

`FutureSecurityEffect.evidence_ids` now requires:

- an exact built-in `tuple`;
- at least one member;
- exact built-in `str` members only;
- non-blank members;
- unique members.

Validation does not trim, sort, stringify, deduplicate or otherwise repair caller input.

The existing materialization-lineage checks remain unchanged: every effect evidence ID must still be a subset of the exact materialization evidence IDs before facts are added to the future twin.

## Non-overlap

This slice does not change:

- materialization admission or capability coverage;
- effect application/idempotency;
- Security Twin primitive validation (#858/#859);
- remediation/retest planning or review;
- any target-capable or deployment path.

## Safety

Immutable evidence-lineage narrowing only. No target interaction, evidence collection, capability execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
