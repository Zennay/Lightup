# Remediation-text proposal parser purity

Issue: #641

Parent boundary: strict remediation-text proposal handoff #209 at exact head
`38c40d112751728c238dcf5d7ab556079528c38e`.

## Contract

Direct parsing of a caller-owned canonical proposal dictionary is read-only:

- successful parsing preserves the payload value, root identity and key order;
- repeated parsing of the exact same object is deterministic;
- late proposal-digest rejection leaves caller state untouched;
- content-digest rejection leaves caller state untouched;
- action-authority rejection leaves caller state untouched;
- repeated rejection returns the same error without accumulated mutation.

## Collision boundary

This is direct-parser purity only. #209 retains production-source ownership.
Keep it separate from #621 object exactness, #636 snapshot detachment/post-parse
isolation, #584 raw JSON typing, producer/live-validation atomicity, and
downstream review-request work.

## Safety

Pure in-memory parser integrity only. No model invocation, evidence collection,
target interaction, code/config application, tool execution, remediation/retest
execution, deployment, future-state resolution, verdict creation, or
attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
