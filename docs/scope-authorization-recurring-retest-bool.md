# Recurring-retest grant authority must be an exact boolean

Issue: #868

## Boundary

`DomainStore.record_authorization_grant()` is the issuance boundary for durable
authorization grants. The `recurring_retest_allowed` flag is authority-bearing:
when true, later product flows may treat the grant as permitting recurring retest
activity without a fresh one-off grant.

The persisted flag must therefore represent an explicit canonical boolean, not
Python truthiness.

## Required contract

- exact built-in `False` is accepted and persists as disabled;
- exact built-in `True` is accepted and persists as enabled;
- every non-boolean value fails closed before the authorization-grant INSERT;
- rejection does not add, rewrite, or normalize any durable grant row;
- values such as `"false"`, `1`, `0`, empty containers, or objects with custom
  truthiness cannot mint or silently normalize recurring-retest authority.

## Current expected RED

Current `main` persists:

```python
1 if recurring_retest_allowed else 0
```

without first requiring `type(recurring_retest_allowed) is bool`.

The acceptance module therefore expects two failures on the current source:

1. the truthy string `"false"` is currently accepted and persisted as enabled;
2. integer `0` is currently accepted and persisted as disabled instead of being
   rejected as non-canonical authority input.

The exact-boolean round-trip control must remain green.

## Collision boundary

This slice intentionally adds tests and documentation only. It does not modify
`src/lightup/domain.py` while adjacent durable-grant read/resolver work is active.

It does not own:

- grant tenant-lineage reads;
- execution-time grant reconstruction;
- revocation coherence;
- approval/reference provenance;
- scope object/type integrity;
- recurring-retest execution itself.

## Safety

This is authorization narrowing using temporary SQLite state only. It performs no
DNS/network I/O, target interaction, scanning, capability execution,
remediation/retest execution, deployment, verdict creation, or attack-path
mutation.
