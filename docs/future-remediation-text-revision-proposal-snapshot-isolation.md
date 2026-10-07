# Remediation-text revision-proposal snapshot isolation

Issue: #633

Parent boundary: strict remediation-text revision-proposal handoff #238 at exact
head `ef38622caf8c63be34785f971d0526e85740b55d`.

## Contract

The public revised-proposal serialization boundary must stay deterministic and
fully detached:

- repeated `to_json()` output is byte-for-byte stable;
- separately returned `as_dict()` values are independent caller snapshots;
- mutating lineage, provenance, content, digest, lifecycle/action flags, or
  verdict state in a snapshot cannot rewrite the frozen typed proposal or later
  JSON;
- an untouched programmatic snapshot round-trips to the exact proposal;
- forged content, lineage, acceptance, and action-authority snapshots fail
  closed in the strict parser;
- rejected caller-owned snapshots are not normalized or rewritten in place;
- mutating caller-owned persisted data after parsing cannot mutate the parsed
  proposal.

## Collision boundary

This branch adds tests and documentation only. #238 retains production-source
ownership. It stays separate from:

- #625 persisted object exactness;
- #588 raw JSON typing;
- #456 live-validation atomicity;
- #468 producer atomicity;
- #231/#624 revision-request work;
- #244/#632 revised-review-request work.

No model/gateway, scope-authorization, or target-capable source is changed.

## Safety

This is an in-memory persistence-integrity proof only. It introduces no model
invocation, target interaction, code/config application, tool execution,
remediation/retest execution, deployment, future-state resolution, verdict
creation, or attack-path mutation.

## Validation policy

The branch is prepared without opening another PR or dispatching another
workflow while the permanent LightUp self-hosted CI lane is occupied. Do not
claim runner-green status until exact-head hosted/permanent proof exists.
