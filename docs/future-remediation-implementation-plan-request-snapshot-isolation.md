# ST5 implementation-planning request snapshot-isolation contract

Issue: #271

This tests/docs-only child sits above draft PR #230 and treats that PR's exact head as a read-only parent.

## Invariant

A `FutureRemediationImplementationPlanRequest` can only request later planning. A caller receiving an `as_dict()` serialization snapshot must not gain a mutable path back into the canonical request or its fail-closed stop line.

The regression contract proves:

- repeated `to_json()` calls are byte-for-byte deterministic and use canonical compact/sorted JSON;
- mutating lifecycle, item-count, future-state, verdict or all seven authority fields on a returned snapshot leaves the source request and later JSON unchanged;
- reserialized snapshots that claim a created plan, disable the canonical requested marker, widen authority, resolve future semantics or claim a verdict fail closed in the strict handoff;
- canonical-shape lineage drift is rejected by digest recomputation;
- executable-looking top-level additions such as `tool_arguments` fail the exact schema;
- independent snapshots do not alias each other;
- untouched JSON and dict snapshots still parse to the exact source request.

## Collision and safety boundary

Parent: exact #230 head `365774588d5d340d4c2ed41e78478e62e1fcf455`.

Branch: `chatgpt/st5-implementation-planning-request-snapshot-isolation-20261006`.

Only this dedicated regression module and document are added. #226/#230 production-owned source remains untouched. No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation is introduced.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
