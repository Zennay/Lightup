# Remediation-text review snapshot isolation

Issue: #637

Parent boundary: strict remediation-text review handoff #220 at exact head
`82126cfccdcef85f51cd5d34cdcccfb05ebe8270`.

## Contract

The public review serialization boundary must stay deterministic and deeply
detached:

- repeated `to_json()` output is byte-for-byte stable;
- separately returned `as_dict()` snapshots do not alias at the root,
  `checks` container, or nested check mappings;
- mutating lineage, reviewer provenance, decision/check data, summary,
  acceptance, action flags, or verdict state in a caller snapshot cannot
  rewrite the frozen typed review or later JSON;
- an untouched programmatic snapshot round-trips to the exact review;
- forged check coherence, acceptance, lineage, and action-authority snapshots
  fail closed in the strict parser;
- rejected caller-owned snapshots remain unchanged;
- mutating caller-owned persisted data after successful parsing cannot rewrite
  the parsed review.

## Collision boundary

This branch adds tests and documentation only. #220 retains production-source
ownership. It stays separate from:

- #623 persisted object exactness;
- reviewer/raw-JSON canonicality owners;
- #454 live-validation atomicity;
- #465 reviewer producer atomicity;
- #215/#635 review-request work;
- #231/#634 revision-request work.

No model/gateway, scope-authorization, or target-capable source is changed.

## Safety

This is an in-memory persistence-integrity proof only. It introduces no model
invocation, evidence collection, target interaction, code/config application,
tool execution, remediation/retest execution, deployment, future-state
resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without opening another PR or dispatching another
workflow while the permanent LightUp self-hosted CI lane is occupied. Do not
claim runner-green status until exact-head hosted/permanent proof exists.
