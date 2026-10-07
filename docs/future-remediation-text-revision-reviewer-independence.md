# Revised-remediation reviewer model independence

Issue: #811

## Purpose

The revised-remediation review is described as independent. The validated
revision proposal already records the `provider_id` and `model_id` that
authored the revised text, so the verifier can enforce a concrete separation
boundary before asking any model to review it.

A `VERIFIER` role label is insufficient when it is bound to the exact same
provider/model pair as the revision author.

## Required contract

`review_future_remediation_text_revision()` must:

- preserve the existing successful path for a distinct revision verifier;
- compare the live verifier binding with the validated revised proposal author
  `(provider_id, model_id)`;
- reject an exact pair match before `gateway.complete()`;
- produce no review request/response when self-review is rejected;
- leave same-provider/different-model policy outside this narrow contract.

The review remains non-executable planning metadata regardless of outcome.

## Acceptance proof

`tests/test_future_remediation_text_revision_reviewer_independence.py`
contains:

- a green control with the existing distinct revision reviewer;
- an expected-RED verifier binding equal to the exact revised proposal author;
- a provider-request assertion requiring pre-invocation rejection.

The branch is pinned directly to active PR #246 exact head
`d995cf57e20f99956fe20b9b8b05d41b64e02765`.

## Collision boundary

Tests and documentation only. PR #246 retains production ownership of
`review_future_remediation_text_revision()`.

#810 owns the first-pass reviewer boundary. Existing revised-review persisted
typing, canonicality, parser/snapshot and producer-atomicity lanes remain
separate.

## Safety

Deterministic in-memory provenance-separation validation only. No external model
or network call, target interaction, scanning, code/config application,
remediation/retest execution, deployment, security verdict or attack-path
mutation.
