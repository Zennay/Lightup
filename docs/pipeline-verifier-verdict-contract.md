# Review pipeline verifier verdict contract

Issue: #838

## Boundary

The verifier is the evidence decision immediately before remediation guidance is
derived. Its system prompt already defines three decisions:

- `CONFIRMED`
- `UNCERTAIN`
- `REJECTED`

The pipeline now treats that as a fail-closed data contract rather than prompt
advice.

The first response line must be exactly one decision token, or the token
followed by a single space and rationale. Unknown, lowercase, prefix-confusable,
leading-blank and prose-first responses are rejected before the
remediation-advisor call. Accepted response text is preserved byte-for-byte in
the `ReviewedFinding`.

## Separation from gateway hardening

Shared `ModelGateway` work owns response object/type/provider/model/role
integrity. This change does not duplicate those checks. It owns only the
pipeline-specific semantic meaning of verifier text.

## Safety

This is in-memory review validation. It does not change scope, authorization,
targets, tools, evidence collection, remediation/retest execution, deployment,
security-verdict authority or attack-path state.
