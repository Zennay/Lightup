# Remediation authoring-request parser purity

Issue: #640

Parent boundary: strict remediation authoring-request handoff #198 at exact head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Contract

Direct parsing of caller-owned canonical JSON-shaped request data is read-only:

- successful parsing preserves the complete payload value;
- root, `items`, item mappings, item list containers, `evidence`, and nested
  evidence mapping identities remain unchanged;
- root/item/evidence key ordering remains unchanged;
- repeated parsing of the exact same object is deterministic;
- a late request-digest mismatch does not rewrite or normalize caller input;
- a nested evidence-manifest failure does not rewrite nested data;
- action-authority rejection does not rewrite caller state;
- repeated rejection returns the same error without accumulating mutation.

## Collision boundary

This is direct-parser purity only. #198 retains production-source ownership.
Keep it separate from #628 object exactness, #638 snapshot detachment/post-parse
isolation, #583 raw JSON typing, live-validation/atomicity, and semantic
lineage/capability owners.

## Safety

Pure in-memory parser integrity only. No model invocation, evidence collection,
target interaction, code/config application, tool execution, remediation/retest
execution, deployment, future-state resolution, verdict creation, or
attack-path mutation.

## Validation policy

The branch is prepared without another PR/workflow while permanent LightUp
self-hosted CI capacity is occupied. Do not claim runner-green status until
exact-head hosted/permanent proof exists.
