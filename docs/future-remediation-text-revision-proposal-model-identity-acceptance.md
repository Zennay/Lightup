# ST5 remediation revision-proposal model identity acceptance

Issue #435 is a tests/docs-only child of exact active #238 head
`ef38622caf8c63be34785f971d0526e85740b55d`.

The shared gateway stores the REMEDIATION_ADVISOR role binding using
`model_id.strip()`. The revision-proposal producer then requires response
`model_id` to equal that exact binding before persisting it. Outer whitespace
is therefore producer-impossible.

The #238 strict parser currently accepts any nonblank persisted `model_id`.
Because `revision_proposal_sha256` is deterministic and public, a caller can
forge outer whitespace and recompute a matching digest.

Acceptance: the real producer control stays green; leading-space, trailing-space
and tab-wrapped model IDs fail closed with matching recomputed digests; persisted
input is rejected rather than normalized.

`provider_id` is deliberately out of scope because provider registration does
not establish the same normalization invariant.

This contract changes no production/source files, does not overlap the active
cross-item work at #194/#198, and grants no code/tool/target/execution/retest/
deployment/attack-path authority. Expected pre-fix: exactly 3 RED cases per
Python interpreter; post-fix: 3 RED -> 0 RED.
