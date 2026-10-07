# Remediation-text review-request parser purity

Issue: #642

Parent boundary: strict remediation-text review-request handoff #215 at exact
head `cee2e5391f32eed5212424d778c66cae73042e4a`.

## Contract

Direct parsing of caller-owned review-request dictionaries is read-only:

- both canonical JSON-list and producer `as_dict()` tuple forms for
  `required_checks` remain supported;
- successful parsing preserves values, root/rubric-container identities and key
  ordering;
- repeated parsing of the exact same object is deterministic;
- late request-digest rejection preserves caller state;
- rubric rejection preserves caller state;
- action-authority rejection preserves caller state;
- repeated rejection returns the same error without accumulated mutation.

## Collision boundary

This is direct-parser purity only. #215 retains production-source ownership.
Keep it separate from #622 object exactness, #635 snapshot
detachment/post-parse isolation, #585 raw JSON typing, #459 live-validation
atomicity, #462 builder atomicity, and downstream review work.

## Safety

Pure in-memory parser integrity only. No model invocation, target interaction,
code/config application, tool execution, remediation/retest execution,
deployment, future-state resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
