# ST5 remediation/retest nested schema integrity

Issue: #373  
Base: exact draft PR #190 head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

## Contract

The strict persisted handoff for `FutureSecurityRemediationRetestPlan` must fail closed when a nested plan item loses required schema, gains undeclared schema, changes from an object into another JSON shape, or weakens the persisted lineage-list contract.

The regression locks these boundaries:

- missing nested item fields are rejected;
- unknown nested item fields are rejected;
- non-object item substitutions are rejected;
- current-path, effect, evidence and capability lineage remain persisted JSON lists;
- lineage members remain non-empty strings, including rejection of bool/int/null type confusion;
- duplicate lineage members fail closed rather than being normalized or silently deduplicated.

Canonical producer JSON and JSON-derived dictionaries must continue to round-trip to the exact typed plan.

## Boundary

This package is tests/docs only and does not change the #190 parser or validator. It does not modify evidence collection, remediation authoring, retest execution, deployment, scope authorization, security verdicts, or attack-path state.

Schema and lineage-shape rejection cannot create or widen execution, target-interaction, remediation, retest, deployment, or attack-path authority.
