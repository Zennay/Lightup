# Scope authorization: persisted engagement lifecycle integrity

Issue: #550  
Parent source owner: #142  
Exact parent head: `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Boundary

The target-active execution resolver joins `authorization_grants` to `engagements` and consumes the durable engagement lifecycle before returning an executable authorization grant.

This acceptance slice freezes one narrow rule: **producer-impossible or legacy engagement lifecycle text must never escape as an exception or be interpreted as executable authority.**

It is intentionally separate from the persisted-grant integrity pack in #471:

- #470 covers `valid_from`, `valid_until`, and `revoked_at`;
- #475 covers `approved_by` and `reference`;
- #479 covers grant scope JSON and persisted risk;
- #550 covers only the joined `engagements.status` lifecycle value.

## Contract

A canonical non-closed `EngagementStatus` continues to resolve the unchanged live grant.

A canonical `closed` status returns no executable grant.

Unknown, blank, case-mutated, or whitespace-mutated persisted status values must also return no executable grant. They must not leak enum-construction exceptions, infer a lifecycle, trim/case-normalize the database value, or rewrite durable state.

After the durable status is explicitly restored to its canonical value, normal resolution is restored.

## Expected RED on the parent head

The exact #142 head currently evaluates:

```python
EngagementStatus(row["engagement_status"])
```

before the resolver can fail closed. Invalid persisted strings therefore raise `ValueError` instead of returning `None`.

The source-owner repair belongs at #142's resolver boundary: parse/validate the joined lifecycle defensively and return no executable grant on invalid durable state. Do not infer or persist a replacement status.

## Collision and safety

This child adds only:

- `tests/test_scope_authorization_persisted_engagement_lifecycle.py`
- `docs/scope-authorization-persisted-engagement-lifecycle.md`

There are **0 production/source changes**. It does not modify #142, #471, #100/#107/#112 lifecycle/dispatch code, ST5 evidence-remediation work, handlers, target interaction, scanning, remediation/retest execution, deployment, verdict creation, or attack-path state.
