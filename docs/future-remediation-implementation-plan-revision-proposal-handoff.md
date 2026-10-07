# Strict revised implementation-plan handoff

This boundary persists and reloads the revised bounded implementation plan
created after an independent review requested changes.

## Structural integrity

The persisted artifact must keep the exact revised-plan schema and canonical
lowercase SHA-256 lineage for:

- the implementation-plan revision request;
- the prior independent review;
- the prior implementation plan;
- the original implementation-planning request;
- the revised-plan artifact itself.

Provider/model provenance, summary text, every plan-item text field, assumptions
and unresolved questions must already be canonical trimmed strings. The handoff
rejects normalization-at-read time so persisted bytes cannot gain validity by
being silently stripped or coerced.

Plan items remain bounded to:

- `plan_item_id`;
- `change_area`;
- `intent`;
- `verification_intent`;
- `rollback_intent`.

IDs must be unique and change areas stay within the original bounded planning
allowlist. Duplicate JSON keys fail before ordinary JSON decoding can apply
last-value-wins semantics.

## Live lineage

Structural validity alone does not permit reuse. The consumer independently
revalidates:

1. the strict implementation-plan revision request;
2. the strict independent implementation-plan review;
3. the strict prior implementation plan;
4. every upstream evidence/remediation object those validators depend on.

The persisted revised plan must bind the exact live revision-request, review,
prior-plan and implementation-request digests.

The handoff never invokes the remediation-advisor model. Model execution belongs
only to the producer stage; persisted-consumer validation is deterministic and
read-only.

## Stop line

A valid handoff preserves `revised_implementation_plan_created=true` but
`implementation_plan_accepted=false`.

Every code-change, tool-call, execution, target-interaction, future-state-retest,
deployment and attack-path authority flag remains false. Future semantics remain
unresolved and the security verdict remains `not_evaluated`.

A later independent review may accept the revised planning text, but acceptance
still cannot grant execution authority.
