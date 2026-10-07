# Review evidence-reference uniqueness

Issue: #899

This acceptance contract is pinned above draft PR #846 and leaves that PR as
the sole production-source owner for `src/lightup/ai/pipeline.py`.

## Problem

The current review evidence-readiness gate checks the finding-local
`evidence_ids` container and each reference, but repeated identifiers are not
rejected.

That means one observation can be represented more than once in the verifier
and remediation-advisor context. Review must preserve evidence lineage rather
than repair or multiply it.

## Required invariant

- a canonical list of unique evidence references remains valid;
- duplicate evidence references fail closed with `ValueError`;
- duplicate rejection happens before the verifier model is called;
- the pipeline does not sort, deduplicate or otherwise repair input;
- caller-owned review input remains unchanged on rejection.

## Collision boundary

This branch is tests/docs only. It does not modify:

- `src/lightup/ai/pipeline.py` (owned by PR #846);
- `src/lightup/labrun.py`;
- gateway/provider source;
- reporting;
- durable finding persistence;
- scope/authorization;
- target-capable workers;
- remediation/retest execution;
- deployment, security-verdict authority, or attack-path state.

The branch is intentionally expected RED until the active pipeline owner
absorbs the narrow uniqueness check.
