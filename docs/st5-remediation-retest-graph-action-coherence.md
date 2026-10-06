# ST5 remediation/retest graph-action coherence

Issue: #375  
Base: exact draft PR #190 head `c554baaa0c6570f2e7b5affd9e7d68e2c9c22c13`

## Gap closed

The strict remediation/retest persisted parser already required a valid `AttackPathGraphDiffAction` enum and canonical digest, but the semantic tuple checked only `next_action` plus remediation/retest/evidence requirement flags.

Because the plan digest is an integrity checksum rather than a secret authenticator, a caller could replace `graph_diff_action` with another valid enum and recompute `plan_sha256`. The later live-lineage validator would reject the forged plan, but the strict parser itself could return an internally contradictory typed object.

## Contract

The persisted parser now binds each classification to the same graph-diff action mapping used by the ST4 graph-diff producer:

- `introduced` → `add_path_hypothesis`;
- `worsened` → `modify_existing_path_risk_up`;
- `improved` → `modify_existing_path_risk_down`;
- `removed` → `remove_existing_path_candidate`;
- `insufficient_evidence` → `no_graph_change_claim`.

Dedicated regressions recompute a matching digest after substituting a different valid action for every classification. Rejection therefore proves semantic enforcement independently of stale-digest rejection.

## Boundary

This child changes only the strict #190 parser semantic check plus one dedicated regression module and this document. It does not change the plan producer, live validator, StateStore, target interaction, evidence collection, remediation/retest execution, deployment, future-state semantics, security verdicts, or attack-path mutation authority.
