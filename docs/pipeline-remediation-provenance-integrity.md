# AI review pipeline remediation provenance integrity

Issue: #836

## Contract

The review pipeline may describe model provenance only when every consumed
response matches the role/model identity that was configured for that request.

For verifier, remediation-advisor and report-synthesizer completions:

- the returned role must be the exact requested `ModelRole`;
- the returned model id must be an exact built-in `str` equal to the
  configured role binding;
- content must be an exact non-empty built-in `str`;
- a mismatch fails closed before that response can be represented as a
  `ReviewedFinding` or final `ReviewResult`.

The provider id remains enforced by `ModelGateway.complete()`. This layer
adds the response role/model/content checks needed before the review pipeline
claims its configured `model_bindings` as provenance.

## Why this matters

Verifier verdicts and remediation advice are quality evidence. Recording those
outputs under a configured model identity that did not actually produce the
response makes later lab evaluation and audit trails misleading even though it
does not itself widen execution authority.

## Safety boundary

This change validates in-memory model response metadata/text only. It does not
change scope, authorization, target access, tools, evidence collection,
remediation/retest execution, deployment, security-verdict authority or
attack-path state.
