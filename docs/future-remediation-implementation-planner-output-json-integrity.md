# ST5 implementation-planner model-output JSON integrity

Issue: #276

This tests/docs-only contract sits above exact #237 head `f8da50cae174d372be20ccef4a203a766db63618`, where the #235 bounded implementation-plan producer is present.

## Invariant

The implementation planner consumes untrusted model output. Its duplicate-key-safe JSON decoder must reject ambiguity recursively before last-value-wins behavior can influence the bounded plan.

The dedicated regressions prove:

- canonical planner JSON still creates a bounded non-executable plan;
- a duplicate top-level `summary` fails closed;
- duplicate nested `plan_item_id`, `change_area`, `intent`, `verification_intent`, and `rollback_intent` keys fail closed;
- duplicate-key rejection happens after exactly one in-memory provider response and before a plan object is accepted;
- the planning-only authority stop line remains unchanged.

## Collision and safety boundary

Only `tests/test_future_remediation_implementation_planner_output_json_integrity.py` and this document are added.

No #235 producer source, #272 direct-constructor source, #273 chain-gate files, #275 persisted-JSON gate, remediation-text sibling work, scope authorization, external model/network calls, target interaction, scanning, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation is changed.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
