# ST5 remediation-text review model identity acceptance

Issue #432 isolates a narrow persisted-integrity mismatch above exact active
#220 head `82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Producer invariant

The shared model gateway stores role bindings using `model_id.strip()`. The
remediation-text review producer obtains the VERIFIER binding and rejects any
response whose `model_id` differs from that exact bound identity before
persisting it as `reviewer_model_id`.

Therefore the producer cannot emit a review whose reviewer model identity has
leading or trailing whitespace.

The strict #220 persisted parser currently accepts any nonblank
`reviewer_model_id`. A persisted caller can add outer whitespace, recompute
the public `review_sha256`, and reconstruct provenance the producer cannot
emit.

## Acceptance

The regression requires:

1. an untouched real approved producer review still round-trips;
2. leading-space reviewer model identity fails closed;
3. trailing-space reviewer model identity fails closed;
4. tab-wrapped reviewer model identity fails closed;
5. every forged case carries matching recomputed `review_sha256`;
6. the parser rejects rather than silently strips persisted provenance.

## Deliberate non-claim

No equivalent normalization rule is asserted for `reviewer_provider_id`:
provider registration currently lacks the same producer guarantee.

## Collision and safety boundary

Tests/documentation only. No #220/#217 source or existing tests are modified.
This does not overlap #429/#430 or #431, which concern cross-item lineage at
earlier #194/#198 boundaries.

No scope/activation changes, target interaction, code/config application, tool
execution, remediation/retest execution, deployment, security verdict or
attack-path mutation is introduced.

Expected pre-fix state: canonical producer control green + exactly 3 RED
reviewer-model whitespace cases per interpreter. Post-fix target: 3 RED -> 0 RED.
