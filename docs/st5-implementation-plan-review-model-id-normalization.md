# ST5 implementation-plan review model-ID normalization

This acceptance slice pins producer-to-persistence coherence for verifier model identity at the strict implementation-plan review handoff.

## Contract

The shared model gateway stores a role binding using canonical trimmed `model_id` text. The implementation-plan reviewer requires the returned response model ID to equal that exact binding before creating the review artifact. A canonical producer review therefore cannot contain leading, trailing, tab, or newline whitespace in `reviewer_model_id`.

The persisted #283 handoff must preserve that invariant independently. A caller must not be able to add surrounding whitespace to `reviewer_model_id`, recompute a matching public `review_sha256`, and reload typed review state that the producer path cannot emit.

The regression deliberately recomputes the review digest over the forged model identity so stale-digest rejection cannot satisfy the contract. The real producer artifact and exact gateway binding are the green control.

## Collision boundary

This is separate from #304/#327, which bound reviewer provider/model provenance to non-empty, NUL-free, at most 256 characters, and from #605 scalar-subclass exactness. It does not claim provider-ID normalization because provider registration does not establish the same trimmed role-binding invariant.

Acceptance-only against exact #283 head `996fa91daac86136caf2dc0c900c2edd84a0703b`. Exactly one regression module and one contract document; zero production/source changes.

No target interaction, scanning, code/tool/remediation/retest execution, deployment, verdict creation, or attack-path mutation.
