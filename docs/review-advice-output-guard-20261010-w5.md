# W5: opt-in advisor-output readiness before report synthesis

**Evidence-remediation #898; draft/plan/lab-only.** Source owner #846
continues to own `src/lightup/ai/pipeline.py`. This module adds a separate,
optional gateway decorator and **never changes the product's default route**.

`review_with_batch_and_advice_guards(real_pipeline, synthetic_result)`:

1. Runs the pure `preflight_review_batch` across every finding before the
   first model request. Invalid evidence references, remediation text or
   summaries from a later finding must not leak an earlier finding to a model.
2. Passes the verified presentation-only snapshot through a newly constructed
   real `AssessmentReviewPipeline` with a local delegation layer.
3. After the `REMEDIATION_ADVISOR` model has replied, and **before**
   `REPORT_SYNTHESIZER` is requested, it requires an exact built-in
   `ModelResponse`, exact expected role and bound model ID, and exact
   built-in nonblank advice text of at most 8192 characters.
4. If advisor output is invalid, raises a fixed, non-leaking `ValueError`.
   Verifier and advisor calls may already have happened, but no report call
   occurs. Original source input and the accepted advisory bytes remain
   unchanged; the sidecar has no persistent state.

This opt-in path is *not* an authenticated model-provider or evidence-truth
gate. Provider registration, tenant identity, customer-disclosure consent,
scope/authorization grants, live revocation, evidence provenance, independent
security review and deployment are separate. In particular, this is not
proof that a remediating action is effective or allowed.

## Offline reproduction

`PYTHONPATH=src python -m unittest tests.test_review_advice_guard_20261010_w5 -v`

The tests use a scripted, non-network provider with capture of every role
request and assert successful canonical advice, blank/whitespace and
polymorphic rejection, excessive output denial, role/model spoof denials,
and **no** report synthesis on invalid advisor responses. Other tests show
a bad second finding results in **no model request at all**.

Existing original-entrypoint tests in
`tests/test_review_input_integrity_red_20261010_w4.py` remain deliberately
RED/expected failure. #898, #899 and #901 are not closed. Canonical source
integration belongs to #846; reviewed production-entrypoint tests must become
ordinary passing canaries and exact-head hosted + permanent VPS CI must pass
before further promotion. No real provider, customer, target, scan,
remediation/retest, tool call, deployment or authorization is introduced.
