# Remediation-text review-request snapshot isolation

Issue: #635

Parent boundary: strict remediation-text review-request handoff #215 at exact
head `cee2e5391f32eed5212424d778c66cae73042e4a`.

## Contract

The public review-request serialization boundary must stay deterministic and
detached:

- repeated `to_json()` output is byte-for-byte stable;
- each `as_dict()` call returns an independent top-level snapshot and an
  independent `required_checks` container;
- mutating lineage, provenance, item count, review rubric, lifecycle/action
  flags, or verdict state in a caller snapshot cannot rewrite the frozen typed
  request or later JSON;
- an untouched programmatic snapshot round-trips to the exact request;
- forged lineage, rubric, primitive count, acceptance, and action-authority
  snapshots fail closed in the strict parser;
- rejected caller-owned snapshots remain unchanged;
- mutating caller-owned persisted data after successful parsing cannot rewrite
  the parsed request.

## Collision boundary

This branch adds tests and documentation only. #215 retains production-source
ownership. It stays separate from:

- #622 persisted object exactness;
- #585 raw JSON typing;
- #459 live-validation atomicity;
- #462 builder atomicity;
- #220/#623 downstream review work;
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
