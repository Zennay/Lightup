# Pending risk-approval decision-audit integrity

Issue: #807  
Pinned source owner: PR #146 at `33c67f8e8b17bd9214c29d02fc52954cc42655da`

## Boundary

A persisted risk approval may be decided only when its durable state is internally
consistent with a never-decided request:

- `status = pending`;
- `decided_by IS NULL`;
- `decided_at IS NULL`.

If either decision-audit field is already populated while the status still says
`pending`, the row is corrupted/legacy-incoherent and must fail closed before
any mutation. The decision path must not overwrite pre-existing audit evidence.

## Acceptance proof

`tests/test_scope_authorization_pending_risk_audit_integrity.py` pins three
behaviors:

1. a pending row with only `decided_by` populated is rejected and remains
   byte-for-byte/value-for-value unchanged at the decision-state columns;
2. a pending row with only `decided_at` populated is rejected and remains
   unchanged;
3. a canonical untouched pending row remains decidable by an unrelated operator.

The first two cases are intentionally expected RED on the pinned PR #146 source
head. The canonical control is expected GREEN.

## Ownership and safety

This branch changes tests and documentation only. PR #146 retains all production
ownership of `DomainStore.decide_risk_elevation()`. No target interaction,
network I/O, scanning, model/tool execution, remediation/retest execution,
deployment, verdict creation, or attack-path mutation is introduced.
