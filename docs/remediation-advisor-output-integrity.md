# Remediation advisor output integrity

Issue: #898

This acceptance contract sits directly above draft PR #846 and keeps that PR as
the production-source owner for `src/lightup/ai/pipeline.py`.

## Problem

The evidence-grounded remediation advisor currently returns model `content`
that is copied directly into `ReviewedFinding.remediation_advice` and then
forwarded to the report synthesizer.

If the advisor returns an empty or whitespace-only answer, the pipeline can
still synthesize a client-facing report even though no remediation advice was
actually produced.

## Required invariant

Before report synthesis:

- remediation-advisor output must contain non-whitespace text;
- canonical non-empty advice remains unchanged;
- empty or whitespace-only advice fails closed with `ValueError`;
- rejection happens after verifier/advisor calls but before any
  `REPORT_SYNTHESIZER` request;
- the caller-owned lab result remains unchanged.

This contract does not define a remediation execution authority. It only
determines whether read-only review text is ready to enter report synthesis.

## Collision boundary

This branch adds tests and documentation only. It does not modify:

- `src/lightup/ai/pipeline.py` (owned by PR #846);
- gateway/provider production source;
- lab execution or evidence collection;
- scope/authorization;
- remediation or retest execution;
- deployment, security-verdict authority, or attack-path state.

The branch is expected RED until the active pipeline source owner absorbs the
narrow output-readiness check.
