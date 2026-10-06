# ST5 remediation/retest nested JSON duplicate-key integrity

Issue: #371  
Base: exact draft PR #190 head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

## Contract

The raw JSON handoff for `FutureSecurityRemediationRetestPlan` must reject duplicate object keys recursively before normal JSON last-value-wins behavior can erase the ambiguity.

The existing #190 handoff already installs its duplicate-key hook at JSON decode time. This regression locks that behavior specifically inside nested remediation/retest plan items.

The proof covers duplicate nested keys that could otherwise rewrite:

- item identity (`change_node_id`);
- classification/action routing semantics (`classification`);
- remediation/retest requirement state (`remediation_required`);
- evidence/capability lineage containers (`capability_ids`).

Canonical producer JSON must still round-trip to the exact typed plan.

## Boundary

This package is tests/docs only. It does not modify the #190 parser or validator, producer code, StateStore, evidence collection, remediation authoring, retest execution, deployment, scope authorization, security verdicts, or attack-path state.

A rejected duplicate-key payload grants no execution, target-interaction, remediation, retest, deployment, or attack-path authority.
