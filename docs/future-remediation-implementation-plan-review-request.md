# ST5 implementation-plan review request

Issue: #278

This stage advances a strict live-valid bounded remediation implementation plan into immutable metadata requesting independent review. It does not perform that review and does not grant any execution or change authority.

## Contract

The review request binds:

- exact implementation-planning request SHA-256;
- exact accepted remediation-review, remediation proposal, and proposal-content SHA-256 lineage;
- exact implementation-plan SHA-256;
- exact planner provider/model provenance;
- exact plan-item count;
- a fixed review rubric:
  - evidence alignment;
  - least privilege;
  - verification separation;
  - rollback sufficiency;
  - non-executable scope;
- a deterministic review-request SHA-256.

The stage advances only `implementation_plan_review_requested=true`.

`implementation_plan_accepted` stays false. Code-change, tool-call, execution, target-interaction, future-state-retest, deployment, and attack-path-mutation authority all remain exact false. Future semantics remain unresolved and the security verdict remains not evaluated.

## Live dependency boundary

The builder consumes only `load_and_validate_future_remediation_implementation_plan(...)`. A structurally valid but stale plan is therefore not enough: the full accepted remediation-review, planning-request, proposal, evidence, and state lineage must still validate live.

The review-request artifact contains lineage/provenance metadata and the fixed rubric only. It does not contain the implementation-plan summary, plan-item intent text, patches, commands, tool/target arguments, credentials, source, metadata, or authorization material.

## Direct-construction boundary

The request dataclass validates its own exact schema, canonical digests, planner provenance, positive exact-int plan-item count, fixed rubric, lifecycle markers, authority stop line, future semantics/verdict, and canonical request digest. Direct `dataclasses.replace()` widening therefore fails closed without requiring a persistence round trip.

## Collision and safety boundary

Branch: `chatgpt/st5-implementation-plan-review-request-20261006`.

Parent: exact #237 head `f8da50cae174d372be20ccef4a203a766db63618`.

Only the new review-request module, dedicated tests, and this document are added. Existing #226/#230/#235/#237 source, active #272 direct-constructor work, #273/#275/#276/#277 siblings, and scope authorization remain untouched.

No verifier/model invocation occurs in this stage. No network/target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation, future-state resolution, or attack-path mutation is introduced.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
