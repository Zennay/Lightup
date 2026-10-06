# ST5 strict implementation-plan review handoff

Issue: #283

This stage persists and reloads #281's independent implementation-plan review without re-running the verifier. A persisted approval records only that bounded planning text passed review; it never grants action authority.

## Persisted contract

The parser requires:

- exact top-level review schema;
- exact nested review-check schema;
- recursive duplicate-key-safe JSON decoding;
- canonical lowercase review-request, implementation-plan, implementation-request, and review SHA-256 values;
- bounded non-empty reviewer provider/model provenance;
- the exact five-check rubric in canonical order;
- check results limited to `pass`, `fail`, or `unclear`;
- fail-closed decision/check coherence;
- a bounded, already canonical-trimmed review summary;
- `implementation_plan_review_completed=true`;
- acceptance exactly coherent with an approved decision;
- every code/tool/execution/target/retest/deploy/attack-path authority flag exact false;
- unresolved future semantics and a not-evaluated security verdict;
- exact review-digest recomputation.

Programmatic `as_dict()` and canonical JSON forms are supported without schema relaxation. Nested duplicate keys fail before JSON last-value-wins behavior can collapse them.

## Live lineage boundary

Structural parsing is intentionally separate from live validity. After parsing, the loader validates:

- the strict #280 persisted review request;
- the strict #237 persisted implementation plan;
- the complete accepted remediation/evidence lineage required by those boundaries.

The persisted review must reference the exact live review-request SHA-256, plan SHA-256 and implementation-request SHA-256. Evidence drift or plan tampering invalidates reuse without re-invoking the verifier.

## Safety and collision boundary

Branch: `chatgpt/st5-implementation-plan-review-handoff-20261006`.

Parent: exact #281 head `ef2dd5d534d0d0e67f73aa2546d4b190d432f63c`.

Only the new handoff module, dedicated tests and this document are added. #281 reviewer source, #278/#280 and upstream #226/#230/#235/#237 source remain unchanged.

No model invocation, target interaction, scanning, tool execution, remediation/retest execution, deployment, future-state resolution, security-verdict creation or attack-path mutation is introduced.

## Promotion

Keep branch-only while canonical self-hosted LightUp CI remains stalled. Require exact-head hosted proof and canonical self-hosted proof before promotion.
