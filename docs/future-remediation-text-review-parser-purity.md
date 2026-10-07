# Remediation-text review parser purity

Issue: #643

Parent boundary: strict remediation-text review handoff #220 at exact head
`82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Contract

Direct parsing of caller-owned review dictionaries is read-only:

- canonical JSON-list and producer `as_dict()` tuple `checks` forms remain
  supported;
- successful parsing preserves values, root/check-container identities, nested
  check-mapping identities, and root/nested key order;
- repeated parsing of the exact same object is deterministic;
- late review-digest rejection preserves caller state;
- nested decision/check-coherence rejection preserves caller state;
- action-authority rejection preserves caller state;
- repeated rejection returns the same error without accumulated mutation.

## Collision boundary

This is direct-parser purity only. #220 retains production-source ownership.
Keep it separate from #623 object exactness, #637 snapshot
detachment/post-parse isolation, #454 live-validation atomicity, #465 reviewer
producer atomicity, reviewer/raw-JSON canonicality, and revision-request work.

## Safety

Pure in-memory persisted-parser integrity using the existing deterministic
fixture. No external model/network call, target interaction, code/config
application, tool execution, remediation/retest execution, deployment,
future-state resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
