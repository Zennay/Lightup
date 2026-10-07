# ST5 revised implementation-plan live-validation atomicity

## Scope

This acceptance slice is a tests/docs-only child of the strict revised implementation-plan persisted handoff in draft #511.

- parent branch: `chatgpt/st5-revised-implementation-plan-handoff-20261007`
- exact parent head: `f3948422929bb9d6525cb2df263c008c763de3f1`
- acceptance issue: #513

The child does not modify #511 production source, #503 revised-plan producer source, the prior #507 revision-request consumer slice, #506/#510 revision-request parser/type work, or any scope-authorization lane.

## Invariant

`load_and_validate_future_remediation_implementation_plan_revision_proposal` must be a repeatable, read-only persisted-consumer boundary over the real revision/review/evidence lineage.

For a canonical persisted revised plan:

- repeated strict live validation returns the exact canonical revised plan;
- caller-owned persisted revised-plan, revision-request, review, prior-plan, planning-request, remediation-review, review-request and proposal dictionaries remain unchanged;
- the corresponding typed lineage remains unchanged;
- the referenced live evidence row remains unchanged;
- `StateStore.create_run`, `StateStore.acquire_lease` and `StateStore.add_evidence` are forbidden during validation.

For deliberate live evidence SHA drift:

- repeated validation fails closed;
- rejection is deterministic;
- persisted payloads and typed lineage remain unchanged;
- stale live evidence is not repaired or rewritten by validation.

## Authority stop line

Successful validation preserves only revised planning text:

- `revised_implementation_plan_created=true`;
- `implementation_plan_accepted=false`;
- all code, tool, execution, target, future-retest, deployment and attack-path authority flags remain false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

No model invocation, code/config application, target interaction, scanning, remediation/retest execution, deployment, verdict creation or attack-path mutation is added.

## Collision boundary

Exactly two new files belong to this child:

- `tests/test_future_remediation_implementation_plan_revision_proposal_live_validation_atomicity.py`;
- `docs/st5-revised-implementation-plan-live-validation-atomicity.md`.

#511 retains strict handoff source ownership. Any source fix belongs to that owner rather than this acceptance branch.

## Promotion gate

Keep this child draft until its exact final head has hosted/offline Python 3.11 + 3.14 proof. Permanent VPS proof must bind the exact final head and cover the dedicated atomicity regression, #511 handoff controls, compile checks and safety canaries.
