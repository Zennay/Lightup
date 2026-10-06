# ST5 independent implementation-plan review

Issue: #281

This stage performs an independent verifier decision over the strict live bounded implementation plan. It remains a planning/review layer only: approval means the plan text passed review, not that any change may be executed.

## Inputs and live gate

The reviewer first consumes:

- the strict persisted implementation-plan review request from #280;
- the strict live implementation plan from #237;
- the full underlying accepted remediation/evidence lineage required by those boundaries.

Both the review-request digest and implementation-plan digest must match the same current lineage before the verifier is invoked. Evidence drift therefore fails before any verifier request is sent.

## Reviewer contract

The stage uses the existing provider-neutral `ModelRole.VERIFIER`. All plan text, assumptions, unresolved questions, provenance and identifiers are explicitly treated as untrusted data rather than instructions.

The verifier must return exactly one JSON object with:

- `decision`: `approved`, `revision_required`, or `insufficient_evidence`;
- `check_results`: exactly the five #278 rubric checks, each `pass`, `fail`, or `unclear`;
- bounded canonical `summary`.

Duplicate JSON keys are rejected recursively.

Decision coherence is fail-closed:

- `approved` requires every check to pass;
- `revision_required` requires at least one non-pass result;
- `insufficient_evidence` requires at least one unclear result.

## Review artifact

The immutable review binds:

- exact review-request SHA-256;
- exact implementation-plan SHA-256;
- exact implementation-request SHA-256;
- reviewer provider/model provenance;
- ordered typed check results;
- bounded summary;
- deterministic review SHA-256.

Only `implementation_plan_review_completed=true` advances. `implementation_plan_accepted=true` is permitted only for an approved decision and means **reviewed planning text only**.

Code-change, tool-call, execution, target-interaction, future-state-retest, deployment and attack-path-mutation authority remain exact false. Future semantics remain unresolved and the security verdict remains not evaluated.

## Safety and collision boundary

Branch: `chatgpt/st5-implementation-plan-review-20261006`.

Parent: exact #280 head `08dc953ed7fa9e38976be7d7f66a3ec381ae6124`.

Only the new reviewer module, dedicated tests and this document are added. #278/#280 and all #226/#230/#235/#237 source remain unchanged, as do #272/#273/#275/#276/#277 and scope authorization.

Tests use the existing in-memory recording provider. No external model/network call, target interaction, scanning, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation or attack-path mutation is introduced.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
