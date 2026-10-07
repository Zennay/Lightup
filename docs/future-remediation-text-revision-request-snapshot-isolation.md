# Remediation-text revision-request snapshot isolation

Issue: #634

Parent boundary: strict remediation-text revision-request handoff #231 at exact
head `30ebbd9f335bcbbc0ab076d344b79d94be8434e6`.

## Contract

The public revision-request serialization boundary must stay deterministic and
detached:

- repeated `to_json()` output is byte-for-byte stable;
- each `as_dict()` call returns an independent top-level snapshot and an
  independent `revision_checks` tuple;
- mutating lineage, review decision/check data, lifecycle/action flags, or
  verdict state in a caller snapshot cannot rewrite the frozen typed request or
  later JSON;
- an untouched programmatic snapshot round-trips to the exact request;
- forged lineage, invalid/out-of-order checks, acceptance, and action-authority
  snapshots fail closed in the strict parser;
- rejected caller-owned snapshots remain unchanged;
- mutating caller-owned persisted data after successful parsing cannot rewrite
  the parsed request.

## Collision boundary

This branch adds tests and documentation only. #231 retains production-source
ownership. It stays separate from:

- #624 persisted object exactness;
- #587 raw JSON typing;
- #460 live-validation atomicity;
- #463 builder atomicity;
- #238/#633 revision-proposal work;
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
