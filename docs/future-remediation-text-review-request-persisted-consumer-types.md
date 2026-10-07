# Remediation review-request persisted-consumer runtime-type contract

Tracking: GitHub issue #790.

This acceptance slice covers only the outer composed consumer
`load_and_validate_future_remediation_text_review_request()` above exact PR
#215 head `cee2e5391f32eed5212424d778c66cae73042e4a`.

## Required boundary

The composed consumer may dispatch only exact producer-emittable persisted
container types:

- exact built-in JSON text (`type(value) is str`); or
- exact built-in decoded/programmatic mapping (`type(value) is dict`).

Equal-content subclasses must fail closed before either strict parser is called.
No subclass normalization is allowed at this outer handoff.

Both canonical controls remain valid:

- `review_request.to_json()`;
- `review_request.as_dict()`.

## Ownership separation

Issue #622 owns direct-parser persisted-object exactness, #585 owns raw JSON
parser typing, #642 owns parser purity, #635 owns snapshot isolation, and #691
owns the broader persisted-integrity composition. This issue owns only the
outer composed-consumer runtime-type dispatch.

PR #215 retains all production-source ownership.

## Safety stop line

A review request requests independent review only. It cannot authorize
remediation acceptance, code/config changes, tool calls, execution, target
interaction, retesting, deployment, security verdicts, or attack-path
mutation. This branch changes tests/docs only.
