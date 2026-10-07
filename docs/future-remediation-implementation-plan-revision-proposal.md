# Future remediation implementation-plan revision proposal

This stage creates a revised **planning artifact only** after an independent
review has rejected the prior bounded implementation plan with
`revision_required`.

## Preconditions and lineage

The producer consumes the strict persisted implementation-plan revision-request
handoff and separately revalidates the referenced implementation-plan review and
prior implementation plan.

The following lineage must remain exact:

- revision request -> independent review digest;
- revision request -> prior plan digest;
- review -> prior plan digest;
- revision request -> implementation-planning request digest;
- reviewer provider/model provenance.

Any evidence, proposal, review, review-request, planning-request or prior-plan
drift is rejected by the composed strict live validators before the revision
model can be invoked.

## Model boundary

The existing provider-neutral `ModelRole.REMEDIATION_ADVISOR` is reused.
The prompt contains only:

- bounded lineage identifiers;
- the canonical required revision checks;
- the independent review summary;
- the bounded prior implementation-plan structure.

StateStore source/metadata, credentials, target arguments and authorization
material are not added to the model payload.

The response must use the same bounded structured planning shape as the initial
implementation plan: summary, plan items, assumptions and unresolved questions.
Unexpected executable keys, duplicate plan-item IDs and unsupported change areas
fail closed.

## Stop line

`revised_implementation_plan_created=true` means revised planning text exists.
It does **not** mean the plan is accepted.

`implementation_plan_accepted` remains false and all code-change, tool-call,
execution, target-interaction, future-state-retest, deployment and attack-path
authority flags remain false. Future semantics stay unresolved and the security
verdict stays `not_evaluated`.

A later independent review boundary is required before any revised planning text
can be accepted, and even acceptance must not grant action authority.
