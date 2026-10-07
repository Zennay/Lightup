# ST5 remediation-text review summary canonicality acceptance

Issue #441 isolates a narrow persisted-integrity mismatch above exact active
#220 head `82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Producer invariant

The #217 remediation-text review producer parses the verifier JSON, requires a
non-empty string, then executes `summary = summary.strip()` before computing
`review_sha256` and persisting the review.

Therefore a producer-created review cannot contain leading or trailing
whitespace in `summary`.

## Persisted-boundary gap

The strict #220 handoff currently also strips persisted `summary` before
constructing the parsed review and verifying `review_sha256`.

That means persisted bytes such as `" summary"`, `"summary "` or a
tab-wrapped summary can be silently normalized back to the producer's canonical
summary and accepted under the original producer digest. The digest therefore
does not currently authenticate the exact persisted summary bytes.

## Acceptance contract

The regression requires:

1. an untouched real approved producer review still round-trips;
2. leading-space persisted summary fails closed;
3. trailing-space persisted summary fails closed;
4. tab-wrapped persisted summary fails closed;
5. forged cases keep the original producer `review_sha256`;
6. the parser rejects noncanonical bytes rather than silently stripping them.

The expected source-owner fix is deliberately narrow: require persisted
`summary == summary.strip()` before constructing the typed review. Existing
NUL and length checks remain unchanged.

## Collision and safety boundary

Tests/documentation only. No #220/#217 source or existing tests are modified.
This is independent of #432/#434 reviewer-model identity and #439/#440 proposal
content canonicalization.

No scope/activation changes, target interaction, code/config application, tool
execution, remediation/retest execution, deployment, security verdict or
attack-path mutation is introduced.

Expected pre-fix state: canonical producer control green + exactly 3 RED summary
whitespace cases per interpreter. Post-fix target: 3 RED -> 0 RED.
