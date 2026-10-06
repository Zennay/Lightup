# Independent classification-reviewer preflight

Issue: #322

## Purpose

ST5 reaches classification review only after fresh evidence has passed metadata review and an operator has explicitly attested that the evidence is sufficient and the existing classification claim is justified.

That still does not make the prior sufficiency operator the classification decision-maker. This preflight binds a **second, distinct operator identity** to the later classification review before any classification can be selected.

## Boundary

The preflight consumes the persisted classification-review request only through the strict/live classification-review request consumer. That consumer revalidates the full upstream evidence-remediation lineage before this stage may inspect the request.

A valid preflight records only:

- exact classification-review request and upstream evidence lineage digests;
- exact candidate run/evidence/capability/classification-claim lineage;
- the prior sufficiency-verifier user ID;
- a distinct classification-reviewer user ID;
- `classification_reviewer_role=operator`;
- `independent_reviewer_verified=true`;
- `eligible_for_classification_review=true`;
- a deterministic preflight SHA-256.

The reviewer user ID is canonical, bounded and must differ from the sufficiency verifier recorded by the live-valid classification request.

## Stop line

This artifact does **not** perform classification review.

It keeps:

- `classification_decision_created=false`;
- `classification_selected=false`;
- `transition_resolution_created=false`;
- collection/tool/target/execution/remediation/retest/deployment/attack-path authority false;
- `future_semantics=unresolved`;
- `security_verdict=not_evaluated`.

Client-admin and client-member contexts fail closed. Reusing the same operator that made the sufficiency attestation also fails closed, preserving explicit reviewer independence.

## Validation

The live validator rebuilds the entire preflight from:

1. the persisted strict classification-review request;
2. the complete current evidence-remediation lineage;
3. the original sufficiency-verifier context; and
4. the classification-reviewer context.

Any lineage drift, reviewer substitution, eligibility change, forged decision/classification/transition field, authority widening, resolved future semantics or security verdict makes the persisted preflight unequal to the live rebuild and fails closed.

## Safety

This is authorization/preflight metadata only. It performs no evidence collection, model invocation, classification decision, transition resolution, target interaction, tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.
