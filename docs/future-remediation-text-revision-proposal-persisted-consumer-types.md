# Remediation revision-proposal persisted-consumer runtime-type contract

Tracking: GitHub issue #794.

This tests/docs-only acceptance slice covers the outer composed consumer
`load_and_validate_future_remediation_text_revision_proposal()` above exact PR
#238 head `ef38622caf8c63be34785f971d0526e85740b55d`.

## Required boundary

Parser dispatch is permitted only for exact persistence/runtime shapes:

- exact built-in JSON text (`type(value) is str`);
- exact built-in decoded/programmatic mapping (`type(value) is dict`).

Equal-content subclasses must fail closed before either strict parser receives
them. Canonical `proposal.to_json()` and `proposal.as_dict()` stay valid.

## Ownership separation

PR #238 retains production-source ownership. Existing direct-parser exactness,
raw JSON typing, parser-purity, snapshot-isolation and canonicality packs remain
separate. This issue owns only the outer composed-consumer runtime-type gate.

## Safety stop line

A revised remediation proposal remains unaccepted planning text. It cannot
authorize code/config changes, tool calls, execution, target interaction,
retesting, deployment, security verdicts, or attack-path mutation.
