# Revised-remediation artifacts: direct structural integrity

The ST5 revised-prose loop now applies strict persisted-object structure at
direct in-memory construction as well as at serialization handoffs.

The covered chain is:

1. remediation text revision request;
2. revised remediation text proposal;
3. revised independent-review request;
4. revised independent-review result.

## Revision request

Direct construction requires exact schema and canonical lineage digests, the
fixed `revision_required` decision, a non-empty unique canonical subset of the
fixed review checks, and the canonical revision-request digest.

## Revised proposal

Direct construction requires exact schema/digests/provenance, canonical trimmed
bounded NUL-free revised prose, an exact content digest, and the canonical
revision-proposal digest.

## Revised review request

Direct construction requires exact schema/digests/provenance, the exact fixed
four-check rubric, and the canonical review-request digest.

## Revised review

Direct construction requires exact schema/digests/reviewer provenance, the
exact ordered typed four-check rubric with allowed results, shared
decision/check coherence, canonical trimmed bounded summary text,
acceptance/decision coherence, and the canonical review digest.

The existing lifecycle/action-authority stop line remains unchanged: these
objects never grant code/config, tool, execution, target, retest, deployment or
attack-path authority. Future semantics remain unresolved and no security
verdict is produced.

Persisted duplicate-key-safe decoding and immediate live upstream-lineage
revalidation remain mandatory; constructor integrity is defense in depth, not a
replacement for those consumer boundaries.
