# Review evidence/remediation integrity acceptance pack v2

Issues: #900, #902

This branch composes three independent expected-RED acceptance contracts above
draft PR #846, whose exact pinned head is
`26b0ca5e89648c3604ff3b9ca1ba2fab81dd2dd6`.

## Included contracts

- #899 — finding-local evidence references must be unique before verifier
  invocation. Duplicate references fail closed without normalization or model
  calls.
- #901 — current remediation (`fix`) must be an exact non-empty built-in
  string before any model role is invoked. Malformed input fails closed without
  coercion, mutation or model requests.
- #898 — remediation-advisor output must contain non-whitespace text before
  report synthesis. Blank output fails closed before the report role is called.

## Intended source-owner absorption

PR #846 remains the sole production owner of
`src/lightup/ai/pipeline.py`. A future source repair can absorb all three
narrow guards while preserving the existing verifier -> remediation advisor ->
report ordering for canonical input.

The acceptance pack itself changes no production source.

## Stop line

The pack grants no capability, target, tool, remediation, retest, deployment,
security-verdict or attack-path authority. It only pins read-only review
integrity behavior.
