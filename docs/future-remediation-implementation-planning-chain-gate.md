# ST5 implementation-planning request-to-plan chain gate

Issue: #273

This tests/docs-only integration gate composes the existing strict implementation-planning request and implementation-plan boundaries without changing their production source.

## Chain invariant

The accepted-review chain may advance from a bounded implementation-planning request to a bounded implementation plan, but that advancement must not create action authority or a security verdict.

The regression contract proves:

- the canonical request and plan both round-trip through their strict persisted parsers;
- `implementation_request_sha256`, `review_sha256`, `proposal_sha256` and `content_sha256` remain exact across the request-to-plan boundary;
- lifecycle advances only from `implementation_planning_requested=true` / `implementation_plan_created=false` to a created plan;
- all seven action-authority flags remain false in both artifacts;
- `future_semantics` remains `unresolved` and `security_verdict` remains `not_evaluated`;
- serialized structures remain free of credentials, target/tool arguments, commands, patches/diffs and authorization material;
- canonical request-lineage and plan-to-request lineage tampering are independently rejected by strict digest validation.

## Collision and safety boundary

Parent: exact #237 handoff head `f8da50cae174d372be20ccef4a203a766db63618`.

Branch: `chatgpt/st5-implementation-planning-chain-gate-20261006`.

Only the dedicated integration regression and this document are added. #226/#230/#235/#237 production-owned source is untouched. Direct-constructor hardening is separately routed in #272.

The test uses the repository's existing in-memory/fake planning fixture. It performs no external model or network call, target interaction, scanning, tool execution, remediation/retest execution, deployment, security-verdict creation or attack-path mutation.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
