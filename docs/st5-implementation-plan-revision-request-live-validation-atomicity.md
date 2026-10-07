# ST5 implementation-plan revision-request live-validation atomicity

## Scope

This acceptance slice is a tests/docs-only child of the strict persisted implementation-plan revision-request handoff in draft #501.

- parent branch: `chatgpt/st5-implementation-plan-revision-request-handoff-20261007`
- exact parent head: `81cd78f074a777a0380672050082fd21616a447c`
- acceptance issue: #505

The child does not modify #501 production source, #486 builder-atomicity work, #483 reviewer-producer work, #493 review-consumer work, or any scope-authorization lane.

## Invariant

`load_and_validate_future_remediation_implementation_plan_revision_request` must behave as a repeatable, read-only persisted-consumer boundary over the real review/evidence lineage.

For a canonical revision-required implementation-plan review:

- repeated strict live validation returns the exact canonical revision request;
- all caller-owned persisted dictionaries remain byte-semantically unchanged;
- the typed revision/review/planning/remediation/evidence lineage remains unchanged;
- the live evidence row remains unchanged;
- validation must not create runs, acquire leases, or add evidence;
- authority remains planning-only.

For deliberate live evidence SHA drift:

- repeated validation fails closed;
- failure is deterministic;
- caller-owned payloads and typed lineage remain unchanged;
- stale evidence is neither repaired nor rewritten by validation.

## Authority stop line

Successful validation preserves only the request for a later bounded implementation-plan revision:

- `implementation_plan_revision_requested=true`;
- `revised_implementation_plan_created=false`;
- `implementation_plan_accepted=false`;
- all code, tool, execution, target, future-retest, deployment, and attack-path authority flags remain false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

This slice adds no model invocation, code/config generation, target interaction, scanning, remediation/retest execution, deployment, verdict creation, or attack-path mutation.

## Collision boundary

Exactly two new files belong to this child:

- `tests/test_future_remediation_implementation_plan_revision_request_live_validation_atomicity.py`;
- `docs/st5-implementation-plan-revision-request-live-validation-atomicity.md`.

#501 retains source ownership. Any implementation fix belongs upstream to that owner rather than this acceptance branch.

## Promotion gate

Keep this child draft until exact-head hosted/offline Python 3.11 + 3.14 proof is green. Canonical permanent-VPS proof should bind the exact final head and include the dedicated regression, #501 handoff controls, its parent review/revision chain, compile checks, and safety canaries.
