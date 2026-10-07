# Future remediation implementation-plan revision-request handoff

This boundary persists and reloads the planning-only request produced after an
independent implementation-plan review requires revision.

## Strict integrity

The handoff requires the exact persisted schema, canonical lowercase SHA-256
lineage values, bounded reviewer provider/model provenance, and a non-empty set
of known required revision checks in the fixed implementation-plan review-rubric
order. Serialized JSON rejects duplicate keys before normal decoding.

The source review decision must remain `revision_required`.
`implementation_plan_revision_requested` remains true, while
`revised_implementation_plan_created`, `implementation_plan_accepted`, and
all code, tool, execution, target, future-retest, deployment and attack-path
authority flags remain false. Future semantics stay unresolved and the security
verdict stays `not_evaluated`.

## Live lineage

A structurally valid persisted request is not sufficient. Before later reuse,
the handoff rebuilds the revision request through
`build_future_remediation_implementation_plan_revision_request`, which in turn
requires the strict live persisted implementation-plan review chain.

The rebuilt request must equal the persisted request exactly. Review
substitution, plan/review-request drift, remediation-lineage drift, evidence
drift, provenance drift or revision-check drift therefore invalidates the
persisted request before a later consumer can use it.

The handoff does not invoke a verifier or remediation-advisor model itself.

## Stop line

This artifact authorizes only a later bounded revision of planning text. It does
not create a revised plan and does not authorize code/config generation or
application, tool calls, target interaction, remediation execution,
future-state retesting, deployment, attack-path mutation or a security verdict.
