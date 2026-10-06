# ST5 implementation-planner output bounds

Issue: #277

This tests/docs-only contract sits above exact #237 head `f8da50cae174d372be20ccef4a203a766db63618`.

## Invariant

The untrusted implementation-planner response must stay structurally bounded before it can become a persisted plan.

The regressions prove:

- canonical output still produces a bounded planning-only artifact with every action-authority flag false;
- summary text rejects empty/whitespace-only values, NUL characters, and lengths above 4,000 characters;
- `plan_items` must contain at least one item and no more than 20;
- plan-item IDs reject empty values and lengths above 128 characters;
- intent, verification-intent, and rollback-intent text reject NUL characters and lengths above 1,200 characters;
- assumptions and unresolved questions must be lists with at most 20 entries;
- assumption/question text rejects empty/whitespace-only values, NUL characters and lengths above 800 characters;
- surrounding whitespace is canonicalized before hashing, so semantically identical padded output yields the same plan content and plan digest.

## Collision and safety boundary

Only `tests/test_future_remediation_implementation_planner_output_bounds.py` and this document are added.

No #235 producer source, #272 direct-constructor source, #273 chain gate, #275 persisted JSON gate, #276 duplicate-key gate, remediation-text siblings, scope authorization, external model/network calls, target interaction, scanning, tool execution, remediation/retest execution, deployment, verdict creation, or attack-path mutation is changed.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
