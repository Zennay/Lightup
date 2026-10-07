# Remediation authoring-request snapshot isolation

Issue: #638

Parent boundary: strict remediation authoring-request handoff #198 at exact head
`7f41af2dcbecd84eee7830cae8b05c6acecdb923`.

## Contract

The authoring-request serialization boundary must remain deterministic and
deeply detached:

- repeated `to_json()` output is byte-for-byte stable;
- independently returned producer `as_dict()` snapshots do not alias the root,
  item records, tuple-backed item collections, evidence containers, or nested
  evidence mappings;
- mutating a producer snapshot cannot rewrite the frozen typed request or later
  JSON;
- canonical JSON-decoded list/dict persisted data round-trips to the exact
  request;
- forged nested evidence, request-digest, and action-authority persisted
  snapshots fail closed without rewriting caller-owned data;
- mutating caller-owned JSON-shaped data after successful parsing cannot
  rewrite the tuple-backed parsed request.

## Persisted-shape note

The strict #198 parser consumes JSON-shaped list/dict containers and rebuilds
tuple-backed typed state. This acceptance does not widen the parser to accept
the producer-native tuple containers returned by `as_dict()`.

## Collision boundary

This branch adds tests and documentation only. #198 retains production-source
ownership. It stays separate from:

- #628 persisted object exactness;
- #583 raw JSON typing;
- existing authoring/live-validation atomicity and lineage/capability/evidence
  semantic owners;
- #319 remediation-evidence-bundle snapshot isolation;
- #209/#636 remediation-text proposal work.

No scope-authorization or target-capable source is changed.

## Safety

This is an in-memory persistence-integrity proof only. It introduces no model
invocation, evidence collection, target interaction, code/config application,
tool execution, remediation/retest execution, deployment, future-state
resolution, verdict creation, or attack-path mutation.

## Validation policy

The branch is prepared without opening another PR or dispatching another
workflow while the permanent LightUp self-hosted CI lane is occupied. Do not
claim runner-green status until exact-head hosted/permanent proof exists.
