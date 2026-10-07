# Remediation-text proposal snapshot isolation

Issue: #636

Parent boundary: strict remediation-text proposal handoff #209 at exact head
`38c40d112751728c238dcf5d7ab556079528c38e`.

## Contract

The public proposal serialization boundary must remain deterministic and
detached:

- repeated `to_json()` output is byte-for-byte stable;
- separately returned `as_dict()` values are independent caller snapshots;
- mutating request/bundle lineage, item count, provider/model provenance,
  content/digests, lifecycle/action flags, future semantics, or verdict state in
  a snapshot cannot rewrite the frozen typed proposal or later JSON;
- an untouched programmatic snapshot round-trips to the exact proposal;
- forged content, lineage, primitive count, and action-authority snapshots fail
  closed in the strict parser;
- rejected caller-owned snapshots remain unchanged;
- mutating caller-owned persisted data after successful parsing cannot rewrite
  the parsed proposal.

## Collision boundary

This branch adds tests and documentation only. #209 retains production-source
ownership. It stays separate from:

- #621 persisted object exactness;
- #584 raw JSON typing;
- existing proposal producer/live-validation atomicity owners;
- #215/#635 review-request work;
- revision/revised-review branches.

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
