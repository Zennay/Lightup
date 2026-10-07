# ST5 implementation-plan review-request model-ID normalization

This acceptance slice pins early parser canonicality for the implementation-plan review-request handoff.

## Contract

The #278 producer builds `planner_model_id` directly from the strict live implementation plan. That plan model identity comes from the model gateway role binding and is canonical trimmed text. A persisted review request therefore cannot legitimately add surrounding whitespace to the planner model identity.

The strict #280 dictionary parser must reject such producer-impossible model IDs even when the caller recomputes a matching `review_request_sha256`. The regression deliberately recalculates that digest, so stale-digest rejection cannot satisfy the contract.

The full live loader already rebuilds #278 from the strict live plan and rejects the forged object by equality. This slice narrows the earlier structural boundary so invalid provenance fails before the expensive lineage rebuild rather than relying on downstream comparison.

## Collision boundary

Separate from #602 mapping-subclass exactness, #604 scalar-subclass exactness, review-request parser-purity/live-validation owners, and #667's later verifier model identity. No provider-ID normalization claim is made.

Acceptance-only above exact #280 head `08dc953ed7fa9e38976be7d7f66a3ec381ae6124`. Exactly one regression module and one contract document; zero production/source changes.

No model invocation, target interaction, scanning, code/tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation.
