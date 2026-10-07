# ST5 revised-remediation reviewer model-identity independence

Issue: #811

## Purpose

The revised-remediation review is described as independent. A separate VERIFIER
role does not provide independence if it is bound to the exact same
`(provider_id, model_id)` pair that authored the revised proposal.

## Acceptance contract

This tests/docs-only child is pinned directly above source-owner PR #246 head
`d995cf57e20f99956fe20b9b8b05d41b64e02765`.

The regression proves:

- the existing path with a distinct revised-text reviewer pair stays green;
- the exact revised-proposal author `(provider_id, model_id)` pair cannot
  review its own revised text;
- self-review fails before reviewer provider invocation;
- same-provider/different-model policy is intentionally outside this narrow
  contract;
- remediation acceptance still carries no code/tool/execution/target/retest/
  deployment/attack-path authority.

## Expected pre-fix result

The distinct-reviewer control is green. The exact author/reviewer identity case
is intentionally RED on the pinned #246 implementation because it validates the
VERIFIER binding without comparing it to the revised proposal's recorded author
identity.

## Ownership and collision boundary

This branch adds only one regression module and this contract document. It does
not modify `src/lightup/future_remediation_text_revision_review.py` or any
production source. PR #246 retains source ownership.

The source-owner fix should compare the live VERIFIER binding to the strict,
live-validated revised proposal author identity before calling
`gateway.complete(...)`.

## Safety

Repository-only provenance hardening. No target interaction, tool execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation is introduced.
