# Current remediation input integrity

Issue: #901

This acceptance contract is pinned above draft PR #846 and leaves that PR as
the sole production owner of `src/lightup/ai/pipeline.py`.

## Problem

The review pipeline forwards a finding's existing `fix` value as
`current_fix` to the remediation advisor without first enforcing the same
basic remediation-text invariant expected from canonical findings.

Malformed review input can therefore reach a model role with blank,
non-string, or polymorphic string remediation data.

## Required invariant

Before any model role is invoked:

- current remediation text must be an exact built-in `str`;
- it must contain non-whitespace text;
- malformed values fail closed with controlled `ValueError`;
- no trimming, coercion or other normalization occurs;
- caller-owned input remains unchanged on rejection.

Canonical exact non-empty remediation text must keep the existing
verifier -> remediation advisor -> report flow unchanged.

## Collision boundary

This branch adds tests and documentation only. It does not modify:

- `src/lightup/ai/pipeline.py` (owned by PR #846);
- labrun;
- gateway/provider production source;
- reporting;
- durable finding persistence;
- scope/authorization;
- target-capable workers;
- remediation/retest execution;
- deployment, security-verdict authority, or attack-path state.

The branch is intentionally expected RED until the active source owner absorbs
the narrow input-readiness guard.
