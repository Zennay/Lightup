# ST5 revised-plan review-request builder atomicity

## Scope

This acceptance slice is a tests/docs-only child of the revised implementation-plan independent-review request in draft #517.

- parent branch: `chatgpt/st5-revised-implementation-plan-review-request-20261007`
- exact parent head: `f8de987ad069a784751a9e38ce258f6a118cea11`
- acceptance issue: #523

The child does not modify #517 source, #514 revised-plan consumer validation, #511 strict handoff source, #521 revised-plan type-hardening work, or any scope-authorization lane.

## Invariant

`build_future_remediation_implementation_plan_revision_review_request` must remain a deterministic, read-only metadata builder over the strict live revised-plan lineage.

For canonical inputs:

- repeated builds return the exact canonical review request;
- caller-owned persisted dictionaries remain unchanged;
- the typed request/revised-plan/revision/review/evidence lineage remains unchanged;
- the referenced live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease`, `StateStore.add_evidence` and `ModelGateway.complete` are forbidden during the build.

For deliberate live evidence SHA drift:

- repeated builds fail closed;
- rejection is deterministic;
- persisted payloads and typed lineage remain unchanged;
- stale live evidence is not repaired or rewritten.

## Authority stop line

A successful build may only request another independent review:

- `implementation_plan_revision_review_requested=true`;
- `revised_implementation_plan_accepted=false`;
- all code, tool, execution, target, future-retest, deployment and attack-path authority flags remain false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No model invocation, target interaction, scanning, remediation/retest execution, deployment, verdict creation or attack-path mutation is added.

## Collision boundary

Exactly two new files belong to this child:

- `tests/test_future_remediation_implementation_plan_revision_review_request_builder_atomicity.py`;
- `docs/st5-revised-plan-review-request-builder-atomicity.md`.

#517 retains source ownership. Any source fix belongs upstream rather than this acceptance branch.

## Promotion gate

Keep this child draft until its exact final head has hosted/offline Python 3.11 + 3.14 proof. A permanent VPS proof must bind the exact final head and cover the dedicated builder atomicity regression, #517 controls, compile checks and safety canaries.
