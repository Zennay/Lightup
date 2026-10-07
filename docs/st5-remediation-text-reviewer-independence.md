# ST5 remediation reviewer model-identity independence

Issue: #810

## Purpose

The first-pass remediation-text review is described as independent. Role
separation alone is insufficient if the VERIFIER role is bound to the exact
same `(provider_id, model_id)` pair that authored the proposal.

## Acceptance contract

This tests/docs-only child is pinned directly above source-owner PR #217 head
`d7e3c1e5f21726a2dfd6bd9133e3823a06402160`.

The regression proves:

- the existing path with a distinct reviewer provider/model pair stays green;
- the exact proposal-author `(provider_id, model_id)` pair cannot review its
  own remediation text;
- self-review fails before reviewer provider invocation;
- same-provider/different-model policy is intentionally outside this narrow
  contract;
- remediation acceptance still carries no code/tool/execution/target/retest/
  deployment/attack-path authority.

## Expected pre-fix result

The distinct-reviewer control is green. The exact author/reviewer identity case
is intentionally RED on the pinned #217 implementation because it verifies the
VERIFIER role binding but does not compare that binding to the proposal's
recorded author identity.

## Ownership and collision boundary

This branch adds only one regression module and this contract document. It does
not modify `src/lightup/future_remediation_text_review.py` or any production
source. PR #217 retains source ownership.

The source-owner fix should compare the live VERIFIER binding to the persisted,
strictly live-validated proposal author identity before calling
`gateway.complete(...)`.

## Safety

Repository-only provenance hardening. No target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
