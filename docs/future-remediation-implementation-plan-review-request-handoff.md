# ST5 strict implementation-plan review-request handoff

Issue: #280

This stage persists and reloads #278's bounded implementation-plan review request through an exact fail-closed consumer boundary.

## Persisted contract

The handoff requires:

- exact top-level schema;
- duplicate-key-safe JSON decoding;
- canonical lowercase SHA-256 lineage and review-request digest;
- bounded non-empty planner provider/model provenance;
- positive exact-int plan-item count;
- exact fixed review-rubric ordering;
- exact review-request lifecycle markers;
- implementation plan remains unaccepted;
- all code/tool/execution/target/retest/deploy/attack-path authority stays exact false;
- future semantics remain unresolved;
- security verdict remains not evaluated.

Both canonical JSON and programmatic `as_dict()` representations are accepted without relaxing the schema.

## Live validation boundary

Structural parsing is not sufficient for reuse. After parsing, the handoff immediately calls `build_future_remediation_implementation_plan_review_request(...)`, which itself consumes the strict live #237 implementation-plan handoff.

The parsed request must equal the freshly rebuilt request exactly. Evidence drift, stale/tampered implementation plans, changed planner provenance, changed plan-item count, lineage changes, rubric changes, or authority widening therefore invalidate reuse.

## Safety boundary

No verifier/model invocation occurs here. No target interaction, scanning, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation, or attack-path mutation is introduced.

Branch: `chatgpt/st5-implementation-plan-review-request-handoff-20261006`.

Parent: exact #278 head `7d8c7c6cf072fcc90d943bb2e48f781d6d38b225`.

Only the new strict handoff module, dedicated tests, and this document are added; #278 producer source and all #226/#230/#235/#237 source remain untouched.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
