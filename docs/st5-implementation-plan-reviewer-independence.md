# Implementation-plan reviewer model independence

Issue: #813

## Purpose

The remediation implementation-plan review is an independent verification step.
The plan already records the `provider_id` and `model_id` that authored it,
so independence can be enforced before any verifier call.

A verifier role bound to the exact same provider/model pair as the plan author
must not be allowed to approve that plan.

## Required contract

`review_future_remediation_implementation_plan()` must:

- preserve the existing successful distinct-reviewer path;
- compare the live verifier binding against the validated implementation plan's
  author `(provider_id, model_id)`;
- reject an exact pair match before `gateway.complete()`;
- make no reviewer request when self-review is rejected;
- preserve #327's independent provenance bounds;
- leave same-provider/different-model policy outside this narrow contract.

## Acceptance proof

`tests/test_future_remediation_implementation_plan_reviewer_independence.py`
provides:

- a green control using the existing implementation-plan reviewer fixture;
- an expected-RED exact verifier/plan-author binding;
- a provider-request assertion requiring rejection before model invocation.

The branch is pinned directly to active PR #327 exact head
`11d6583e24cccfd6393d24d59f00521f090b3e94`.

## Collision boundary

Tests and documentation only. PR #327 retains production ownership of the
implementation-plan review source and #304 retains provenance-bounds ownership.

#810/#811/#812 cover the earlier remediation-text review boundaries. Existing
implementation-plan handoff, persisted-integrity and atomicity lanes remain
separate.

## Safety

Deterministic in-memory provenance-separation validation only. No external model
or network call, target interaction, scanning, code/config application,
remediation/retest execution, deployment, security verdict or attack-path
mutation.
