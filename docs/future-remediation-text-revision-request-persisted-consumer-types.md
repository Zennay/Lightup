# Remediation revision-request persisted-consumer runtime-type contract

Tracking: GitHub issue #793.

This tests/docs-only acceptance slice covers the outer composed consumer
`load_and_validate_future_remediation_text_revision_request()` above exact PR
#231 head `30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

## Required boundary

Only exact producer-emittable persisted container types may select a parser:

- exact built-in JSON text (`type(value) is str`);
- exact built-in decoded/programmatic mapping (`type(value) is dict`).

Equal-content subclasses must fail closed before JSON or direct-object parser
dispatch. Canonical `request.to_json()` and `request.as_dict()` remain green.

## Ownership separation

PR #231 retains production-source ownership. Direct parser exactness, raw JSON
typing, parser-purity, snapshot-isolation and broader integrity composition
remain with their existing owners. This slice owns only the outer consumer
runtime-type dispatch.

## Safety stop line

A revision request authorizes only another planning pass over remediation prose.
It does not authorize code/config changes, tools, execution, target interaction,
retesting, deployment, verdict creation, or attack-path mutation.
