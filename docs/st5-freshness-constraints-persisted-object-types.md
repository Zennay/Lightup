# ST5 freshness-constraints persisted object exact types

Issue: #612  
Pinned source owner: #68 at `04cd3ee9da331e29f602bcdc45b7045774b3a42c`

## Contract

`FutureSecurityEvidenceFreshnessConstraints.to_json()` serializes through JSON, so the direct persisted-object parser must only accept runtime shapes JSON decoding can actually produce. Equivalent-content Python subclasses are not canonical persisted data and must fail closed rather than be normalized into typed state.

The acceptance boundary requires exact built-in runtime types for:

- top-level, freshness-item, and prior-evidence `dict` mappings;
- top-level, freshness-item, and prior-evidence schema keys as exact `str`;
- `items`, lineage arrays, and `prior_evidence` as exact `list` containers;
- identifier, SHA-256, schema/fixed metadata, and nested lineage values as exact `str`;
- `current_twin_version`, `twin_version`, and `freshness_item_count` as exact `int`.

Existing authority booleans already use identity checks and are intentionally not duplicated here.

## Expected RED

At the pinned #68 head the parser uses broad `isinstance` checks, set/value equality, and identifier/SHA helpers that admit subclasses. The new regression module therefore remains expected RED until the #68 source owner absorbs exact built-in type guards.

The canonical control is always `json.loads(constraints.to_json())` and must stay green.

## Collision boundary

This branch changes only:

- `tests/test_future_security_evidence_freshness_persisted_object_types.py`
- `docs/st5-freshness-constraints-persisted-object-types.md`

It does not modify #68 source, #131 persisted-consumer/live-validation work, #323/#329 parser-purity work, #611 evidence-collection exactness, freshness-admission #72, scope authorization, or target-capable code.

## Safety

This is persistence-integrity acceptance only. It adds no network or target interaction, collection execution, capability/tool selection, remediation/retest execution, deployment, security verdict, future-state resolution, or attack-path mutation.
