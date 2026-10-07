# Revised implementation-plan independent review request

This stage turns a strict live-valid revised remediation implementation plan
into immutable metadata requesting a second independent review.

## Input gate

The request builder consumes only the strict persisted revised-plan handoff.
That consumer has already validated the revised artifact's exact schema and
digest and revalidated the live implementation-plan revision request,
independent prior review, prior plan and complete upstream evidence-remediation
lineage.

Any live evidence or lineage drift therefore fails before this review request
can be created.

## Request contents

The request binds only bounded metadata:

- revised-plan digest;
- implementation-plan revision-request digest;
- prior independent-review digest;
- prior implementation-plan digest;
- original implementation-planning request digest;
- revised-plan provider/model provenance;
- revised plan-item count;
- the fixed five-check implementation-plan review rubric.

The revised plan body, plan-item prose, patches, commands, tool or target
arguments, credentials and arbitrary evidence payload are not copied into the
review request.

The review rubric remains:

1. evidence alignment;
2. least privilege;
3. verification separation;
4. rollback sufficiency;
5. non-executable scope.

## Stop line

`implementation_plan_revision_review_requested=true` only requests another
independent decision. The revised plan remains unaccepted.

All code-change, tool-call, execution, target-interaction, future-state-retest,
deployment and attack-path authority flags stay false. Future semantics remain
unresolved and the security verdict stays `not_evaluated`.

This stage makes no model call and cannot execute remediation.
