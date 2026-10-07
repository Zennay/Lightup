# Revised-remediation review-request snapshot isolation

Issue: #632

Parent boundary: strict revised-remediation review-request handoff #244 at exact
head `7eb4f5f72f5656b5476ba8735d7e83ded06decf3`.

## Contract

The public serialization boundary must stay deterministic and detached:

- repeated `to_json()` calls are byte-for-byte stable;
- each `as_dict()` call returns an independent top-level snapshot and an
  independent `required_checks` container;
- mutating lineage, provenance, rubric, lifecycle/action flags, or verdict data
  in a caller snapshot cannot rewrite the frozen typed review request or later
  JSON;
- an untouched programmatic snapshot round-trips to the exact typed request;
- forged lineage, rubric, acceptance, or execution-authority snapshots fail
  closed in the strict parser;
- rejected caller-owned snapshots are not normalized or mutated in place;
- mutating a caller-owned dictionary after successful parsing cannot rewrite
  the parsed request.

## Collision boundary

This branch adds tests and documentation only. #244 retains production-source
ownership. It is intentionally separate from:

- #626 persisted object-type exactness;
- #631 parser input-purity;
- #461 live-validation atomicity;
- #464 builder atomicity;
- #589 raw JSON typing;
- #248 and #629 downstream revised-review work.

No model/gateway, scope-authorization, or target-capable source is changed.

## Safety

This is an in-memory persistence-integrity proof only. It introduces no model
invocation, target interaction, code/config application, tool execution,
remediation/retest execution, deployment, verdict creation, future-state
resolution, or attack-path mutation.

## Validation policy

The branch is prepared without opening another PR or dispatching another
workflow while the permanent LightUp self-hosted CI lane is occupied. Do not
claim runner-green status until exact-head hosted/permanent proof exists.
