# Risk-decision integrity acceptance pack

Issue: #897

## Parent

Pinned directly above PR #146 exact head:

`33c67f8e8b17bd9214c29d02fc52954cc42655da`

PR #146 retains all production ownership for the serialized risk-elevation decision path.

## Composed contracts

This branch carries three independent tests/docs-only sidecars:

- **#791 — approval identity binding:** one exact canonical `approval_id` must identify the row used for safety checks, mutation and readback; adaptable/polymorphic identities fail before the first bind.
- **#796 — requester provenance:** durable `requested_by` must remain exact non-blank text before self-approval logic; corrupt BLOB/blank provenance fails closed without repair.
- **#807 — decision audit coherence:** a PENDING approval may not already carry `decided_by` or `decided_at`; stale audit state fails closed before mutation.

Each rejection path preserves durable state so audit/corruption evidence remains inspectable.

## Collision boundary

Composition only: regressions + contract docs + this manifest. No production/source file changes. Do not edit PR #146, `src/lightup/domain.py`, #657 runtime reviewer identity, #656 justification intake, grant/execution policy, evidence-remediation, target-capable code, deployment, verdicts or attack-path state.

## Safety

Temporary SQLite and in-process authorization tests only. No DNS/network I/O, target interaction, scanning, model/tool execution, remediation/retest execution, deployment, verdict creation or attack-path mutation.

## Runner posture

Known expected-RED acceptance stays branch-only while the permanent LightUp self-hosted lane is occupied. No duplicate canonical workflow should be dispatched solely for this pack.
