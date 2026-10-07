# ST5 revised-remediation review model identity acceptance

Issue #437 is a tests/docs-only child of exact active #248 head
`546716d6117918dbbb12a0720f7659b6a59ff002`.

The shared gateway stores the VERIFIER binding using `model_id.strip()`. The
revised-remediation review producer rejects any response whose `model_id`
differs from that exact binding before persisting it as
`reviewer_model_id`. Outer whitespace is therefore producer-impossible.

The strict #248 parser currently accepts any nonblank reviewer model identity.
A persisted caller can add outer whitespace and recompute the deterministic
public `review_sha256`.

Acceptance keeps the real approved producer review green and requires
leading-space, trailing-space and tab-wrapped `reviewer_model_id` to fail
closed with matching recomputed digests. Input is rejected, never normalized.

No equivalent `reviewer_provider_id` claim is made because provider
registration lacks the same normalization guarantee.

Exactly two tests/docs files; 0 production/source changes; no overlap with the
#194/#198 cross-item lineage workers; no target/tool/execution/remediation/
retest/deploy/attack-path authority. Expected pre-fix: exactly 3 RED cases per
Python interpreter; post-fix: 3 RED -> 0 RED.
