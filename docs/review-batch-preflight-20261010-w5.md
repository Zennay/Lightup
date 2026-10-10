# W5: opt-in, whole-batch review admission (non-authorizing)

**M3/M7 evidence-remediation, plan/lab-only.** Supplement to the existing
[#902 review input/output integrity composition](https://github.com/Zennay/Lightup/issues/902)
and RED canaries in [#1179](https://github.com/Zennay/Lightup/pull/1179).

## Working implementation, not production integration

`lightup.ai.review_batch_preflight.preflight_review_batch(source)`
examines **all** submitted review findings before returning a separate
presentation-only snapshot. `review_with_batch_preflight(pipeline, source)`
optionally feeds this detached snapshot into the **real**
`AssessmentReviewPipeline`. The default `pipeline.review(source)` remains
unmodified, so its RED canaries remain real, and this sidecar cannot be
presented as a shipped fix.

Preflight enforces exact built-in JSON-shaped containers/strings, bounded
field sizes, bounded finding/evidence counts, unique finding-local evidence
references, nonblank exact `fix` text, and a bounded evidence summary.
Validation fails closed for invalid data in **any** finding before the first
call to `ModelGateway.complete`, including a malformed *second* finding.
No leading/trailing whitespace normalization, silent deduplication, source
mutation or reordering. The accepted snapshot is separately allocated and
omits raw evidence payloads, unknown keys and caller-controlled authorization
metadata rather than forwarding them in prompts.

Legacy top-level `evidence_id` is a single-item fallback **only when** a
finding's `evidence_ids` is missing or null. A present empty list is an
explicit failure and must not consume a fallback. Existing valid positive
fixtures, response ordering and exact untrimmed fix text are preserved.

`review_with_batch_preflight` is explicitly an **optional lab-only caller**.
It is **not** installed in a web route or production application and it does
not confer evidence authenticity, session/tenant identity, authorization,
operator approval, provider privacy/permission, retest validity or verdict
authority. Reviewing even already-validated data with a real remote model
would need its own approved data-disclosure and trusted operator checks.

## Limits and unaddressed gaps

- Up to 128 findings, 64 distinct references per finding, 256 chars/reference,
  4096 chars/evidence summary, 8192 chars/fix and text, 32 targets,
  2048 chars/target, 64 coverage count entries, exact nonnegative integer
  coverage counts.
- No normalization or repair of corrupted legacy/persisted evidence; that
  work belongs to the durable decoder owner (#856/#886) and SQLite owner.
- The snapshot is an ordinary **new mutable dict** intended for immediate,
  single-threaded use by the optional wrapper. Do not reuse it as an
  authenticated/durable object or mutate it between preflight and review.
- Future canonical integration is owned by #846, which must decide how to
  compose with #898 advisor-output validation and #899/#901 input
  acceptance. Its real default entrypoint remains unprotected until then.
- If a later provider returns an invalid verifier/advisor response, this
  preflight does not validate that output. #898 remains independently open.

## Offline reproduction

`PYTHONPATH=src python -m unittest tests.test_review_batch_preflight_20261010_w5 -v`

The new suite exercises actual role order on `ScriptedProvider` with
**no internet, DNS, real model or targets**. It covers full-batch zero model
calls on invalid second findings, malformed original inputs, duplicate
evidence, legacy fallback, type confusion, size limits, detached aliases,
skipped untrusted fields, and successful end-to-end synthetic review.

The separate `test_review_input_integrity_red_20261010_w4` still contains
**10 intentional expectedFailure** tests against the original default
entrypoint; a green aggregate test command must not be misreported as source
remediation.

**Stop line:** draft only. Do not merge, deploy, grant, scan, execute
remediation/retests, assert a security verdict or process real client data
based on this optional demonstration. Require independent source/security
review, ordinary passing production-entrypoint canaries and exact-head hosted
+ canonical permanent VPS CI proof before further promotion.
