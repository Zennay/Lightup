# ST5 implementation-planning request direct-construction contract

Issue: #274

This child hardens the in-process construction boundary of `FutureRemediationImplementationPlanRequest` above exact draft PR #230 head `365774588d5d340d4c2ed41e78478e62e1fcf455`.

## Direct-construction invariant

A request object must be just as fail-closed when created directly in process as when it crosses the strict persisted handoff.

Direct construction now requires:

- exact schema version `st5.remediation_implementation_plan_request.v1`;
- canonical lowercase SHA-256 values for review, review-request, proposal, content and implementation-request digests;
- non-empty reviewer provider/model provenance;
- a positive exact integer `item_count`, excluding booleans and other number-like values;
- `implementation_planning_requested=True` and `implementation_plan_created=False`;
- every code/tool/execution/target/retest/deploy/attack-path authority flag exact `False`;
- `future_semantics=unresolved` and `security_verdict=not_evaluated`;
- exact canonical implementation-request digest recomputation from the request lineage and provenance.

Dedicated regressions exercise direct reconstruction, `dataclasses.replace()` lifecycle/authority widening, bool/int confusion, malformed/noncanonical digests, provenance/item-count drift and stale-but-canonical digest mismatch.

## Collision and safety boundary

Changed production file: `src/lightup/future_remediation_implementation_plan_request.py`.

Dedicated test: `tests/test_future_remediation_implementation_plan_request_direct_construction.py`.

No #230 handoff source, #235/#237 implementation-plan source, remediation-text sibling work, scope authorization, model invocation, target interaction, tools, remediation/retest execution, deployment, verdict creation or attack-path mutation is changed.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted and canonical self-hosted proof before promotion.
