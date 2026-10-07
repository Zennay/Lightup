# Remediation-text revision-proposal parser purity

Issue: #645

Parent boundary: strict remediation-text revision-proposal handoff #238 at
exact head `ef38622caf8c63be34785f971d0526e85740b55d`.

## Contract

Direct parsing of a caller-owned canonical revised-proposal dictionary is
read-only:

- successful parsing preserves the payload value, root identity and key order;
- repeated parsing of the exact same object is deterministic;
- late revision-proposal digest rejection leaves caller state untouched;
- content-digest rejection leaves caller state untouched;
- action-authority rejection leaves caller state untouched;
- repeated rejection returns the same error without accumulated mutation.

## Collision boundary

This is direct-parser purity only. #238 retains production-source ownership.
Keep it separate from #625 object exactness, #633 snapshot
detachment/post-parse isolation, #588 raw JSON typing, #456 live-validation
atomicity, #468 producer atomicity, #231 revision-request work, and #244
revised-review-request work.

## Safety

Pure in-memory parser integrity only. No model invocation, target interaction,
code/config application, tool execution, remediation/retest execution,
deployment, future-state resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
