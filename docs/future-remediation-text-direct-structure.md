# Remediation text artifacts: direct structural integrity

The original ST5 remediation-text chain contains three persisted planning
artifacts after the authoring request:

1. `FutureRemediationTextProposal`
2. `FutureRemediationTextReviewRequest`
3. `FutureRemediationTextReview`

Their constructors now enforce the same canonical object structure already
required by the strict persisted handoffs.

## Proposal

Direct construction requires the exact schema, canonical lineage/content/
proposal SHA-256 values, a positive exact-integer item count, non-empty
provider/model/content, bounded NUL-free content, an exact content digest, and
the canonical proposal digest.

## Review request

Direct construction requires the exact schema, canonical request/bundle/
proposal/content/review-request digests, non-empty provider/model provenance, a
positive exact-integer item count, the exact fixed review rubric, and the
canonical review-request digest.

## Review

Direct construction requires the exact schema and digests, non-empty reviewer
provenance, an enum-typed decision, the exact ordered four-check rubric with
allowed results, decision/check coherence, canonical trimmed bounded summary
text, acceptance/decision coherence, and the canonical review digest.

The existing lifecycle and action-authority flags remain fail-closed. These
constructor checks do **not** replace persisted duplicate-key-safe decoding or
live upstream-lineage validation; those remain mandatory consumer boundaries.

This slice changes integrity only. It adds no model-role widening, tool call,
target interaction, remediation execution, retest execution, deployment,
future-state resolution, security verdict, or attack-path mutation.
