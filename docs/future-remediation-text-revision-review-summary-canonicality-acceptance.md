# ST5 revised-remediation review summary canonicality acceptance

Issue #445 isolates a narrow persisted-integrity mismatch above exact active
#248 head `546716d6117918dbbb12a0720f7659b6a59ff002`.

## Producer invariant

The revised-remediation review producer requires a non-empty verifier summary,
then executes `summary = summary.strip()` before computing `review_sha256`
and persisting the review.

Producer-created revised reviews therefore cannot contain leading or trailing
whitespace in `summary`.

## Persisted-boundary gap

The strict #248 handoff also strips persisted `summary` before constructing
the typed review and verifying `review_sha256`.

A persisted caller can therefore add outer whitespace while keeping the
producer's original digest. The parser silently normalizes those bytes back to
the canonical producer value and accepts them.

## Acceptance contract

1. an untouched real approved revised-review producer control still round-trips;
2. leading-space persisted summary fails closed;
3. trailing-space persisted summary fails closed;
4. tab-wrapped persisted summary fails closed;
5. forged cases keep the original producer `review_sha256`;
6. the parser rejects noncanonical bytes rather than silently stripping them.

The expected source-owner fix is deliberately narrow: require persisted
`summary == summary.strip()` before typed construction. Existing NUL, length,
decision/check coherence and digest checks remain unchanged.

## Collision and safety boundary

Tests/documentation only. No #248 source or existing tests are modified. This is
independent of #437/#438 revised-review model identity.

No scope/activation changes, target interaction, code/config application, tool
execution, remediation/retest execution, deployment, security verdict or
attack-path mutation is introduced.

Expected pre-fix state: canonical producer control green + exactly 3 RED summary
whitespace cases per interpreter. Post-fix target: 3 RED -> 0 RED.
