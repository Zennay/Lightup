# ST5 implementation-plan nested JSON integrity

Issue: #275

This tests/docs-only invariant sits above exact #237 handoff head `f8da50cae174d372be20ccef4a203a766db63618`.

## Invariant

The strict persisted implementation-plan handoff uses a duplicate-key-safe JSON decoder. That protection must remain recursive: duplicate keys inside a nested `plan_items` object may not fall through normal JSON last-value-wins behavior.

The dedicated regressions prove:

- canonical implementation-plan JSON still round-trips to the exact source plan;
- a duplicate nested `intent` fails closed;
- a duplicate nested `change_area` fails closed;
- a duplicate nested `verification_intent` fails closed;
- a duplicate nested `rollback_intent` fails closed;
- a duplicate nested `plan_item_id` fails at duplicate-key decoding before identity checks can observe a collapsed value.

## Collision and safety boundary

Only `tests/test_future_remediation_implementation_plan_nested_json_integrity.py` and this document are added.

No #226/#230/#235/#237 source, active #272 producer hardening, #273 chain-gate files, remediation-text siblings, scope authorization, model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation is changed.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
