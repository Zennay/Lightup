# Remediation review: current_fix integrity (#901)

**Status: RED acceptance, not a production fix.**
Source-owner baseline PR #846 at commit
`26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6`.

`AssessmentReviewPipeline.review` currently sends `finding["fix"]`
to the remediation advisor after making a verifier request. A blank
or mis-typed fix is not safely rejected before the first model call.

## Required producer/consumer contract

1. Validate the remediation input before making **any** model call. Accept
   only exact built-in `str` values with at least one non-whitespace
   character; leave accepted text **byte-for-byte unchanged**, including
   optional leading/trailing spaces.
2. Reject `""`, whitespace-only, `None`, numeric/bool, bytes and
   `str` subclasses with controlled `ValueError`.
3. Rejected input produces no verifier, advisor or reporting call and leaves
   original input unchanged. No covert coercion, mutation or normalization.
4. Every test uses `ScriptedProvider` offline. The fixed advisor response
   and synthetic localhost label are not claims of observed security facts.

## Reproduction and integration

`PYTHONPATH=src python -m unittest tests.test_review_input_integrity_red_20261010_w4 -v`

The malformed cases are marked `expectedFailure` against current source.
That is intentionally RED evidence of missing admission, even if the
aggregate test command exits successfully. This suite may expose more than
one input gap: rejection must happen **before** verifier dispatch, not just
raise during later `json.dumps` in the advisor.

The PR #846 source owner must implement admission in the canonical
`src/lightup/ai/pipeline.py` path, re-run these cases without
`expectedFailure`, and obtain independent review, exact-SHA hosted and
permanent LightUp VPS evidence before any integration or release.

No source-owner edits, live customer data, real model/provider, active
targets, authorization, remediation/retest execution, deployment or
security-verdict promotion are part of this branch.

## Batch-atomic model-dispatch boundary

If a later finding contains malformed `fix` content, earlier findings must
**not** have caused any model request. Validate all finding remediation inputs
in a separate preflight pass before model dispatch. A second-finding RED
canary explicitly proves the existing sequential model loop is insufficient.
