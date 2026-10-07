# Remediation-text revision-request parser purity

Issue: #644

Parent boundary: strict remediation-text revision-request handoff #231 at exact
head `30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

## Contract

Direct parsing of caller-owned revision-request dictionaries is read-only:

- canonical JSON-list and producer `as_dict()` tuple `revision_checks` forms
  remain supported;
- successful parsing preserves values, root/check-container identities and key
  ordering;
- repeated parsing of the exact same object is deterministic;
- late revision-request digest rejection preserves caller state;
- invalid/out-of-order revision-check rejection preserves caller state;
- action-authority rejection preserves caller state;
- repeated rejection returns the same error without accumulated mutation.

## Collision boundary

This is direct-parser purity only. #231 retains production-source ownership.
Keep it separate from #624 object exactness, #634 snapshot
detachment/post-parse isolation, #587 raw JSON typing, #460 live-validation
atomicity, #463 builder atomicity, and #238 downstream revision-proposal work.

## Safety

Pure in-memory parser integrity only. No model invocation, target interaction,
code/config application, tool execution, remediation/retest execution,
deployment, future-state resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
