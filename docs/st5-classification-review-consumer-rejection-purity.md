# ST5 classification-review consumer rejection purity

Issue: #332

This contract proves failure atomicity at the composed persisted classification-
review consumer boundary from PR #109. It is intentionally separate from the
direct strict-parser rejection-purity proof in #329/#330.

## Boundary

Base: exact PR #109 head
`ad7f54c7a94467eefbc1f9ef9582ac849cb08175`.

The consumer first decodes/strictly parses a persisted classification-review
request and then immediately validates it against the current live
evidence-remediation lineage. A caller must not observe mutation of its input
object regardless of which stage rejects the request.

## Rejection paths

The regression uses real producer artifacts and a caller-owned JSON-decoded
dictionary, then proves two distinct failures:

1. a canonical-shape request digest is changed so strict parsing rejects the
   request;
2. the persisted request remains canonical while the live sufficiency
   attestation is replaced with stale lineage, so strict parsing succeeds and
   live validation rejects reuse.

For both paths, the same caller-owned dictionary is rejected twice. Its value,
JSON key/list ordering, recursive dictionary/list identities, and planning-only
non-authority stop line must remain unchanged after every rejection. Repeated
rejection must also return the same failure message, proving deterministic
failure semantics as well as input atomicity.

## Safety stop line

This test creates no classification decision and grants no transition,
collection, tool, target, execution, remediation, retest, deployment or
attack-path authority. Future semantics remain unresolved and no security
verdict is created.
