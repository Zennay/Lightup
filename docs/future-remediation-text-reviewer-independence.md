# Remediation reviewer model independence

Issue: #810

## Purpose

ST5 calls the remediation-text review independent. A role label alone does not
establish that independence: the gateway can bind `ModelRole.VERIFIER` to the
same provider/model pair that authored the remediation proposal.

The narrow provenance invariant is therefore that the exact reviewer
`(provider_id, model_id)` pair must differ from the proposal author's pair
before reviewer invocation.

## Required contract

`review_future_remediation_text()` must:

- preserve the existing successful path for a distinct verifier binding;
- compare the live verifier binding with the validated proposal's
  `provider_id` and `model_id`;
- fail closed when both identities are identical;
- reject before `gateway.complete()`, so the proposal author is never asked to
  approve its own text;
- leave same-provider/different-model policy outside this narrow acceptance
  slice.

This contract does not grant or exercise remediation authority. An accepted
review remains planning metadata only.

## Acceptance proof

`tests/test_future_remediation_text_reviewer_independence.py` contains:

- a green control using the existing distinct `reviewer/verifier-model-v1`
  fixture;
- an expected-RED self-review case that binds the verifier role to the exact
  `(provider_id, model_id)` pair recorded on the proposal;
- a provider-request assertion proving rejection must happen before model
  invocation.

The branch is pinned directly to active PR #217 exact head
`d7e3c1e5f21726a2dfd6bd9133e3823a06402160`.

## Collision boundary

Tests and documentation only. PR #217 keeps production ownership of
`review_future_remediation_text()`.

#432 owns reviewer model normalization, #453 producer input atomicity, #623
persisted review object exactness, #789 outer persisted-consumer typing, and
#716 persisted producer-canonicality composition. Revised-remediation review is
a separate downstream boundary.

## Safety

Deterministic in-memory model-fixture validation only. No external model or
network call, target interaction, scanning, code/config application,
remediation/retest execution, deployment, security verdict or attack-path
mutation.
