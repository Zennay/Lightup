# Scope authorization: durable engagement ownership binding

Issue: #552  
Parent source owner: #142  
Exact parent head: `f6214a1dc3b2a86780e1b1d04d8e0803947e61ba`

## Boundary

The execution resolver binds the in-memory authorization snapshot back to the durable grant row by grant id, client id, and engagement id. It also joins the durable engagement to reject the `closed` lifecycle state.

That join is authorization-significant: the engagement itself has durable client ownership. A live grant must remain executable only while the grant and its joined engagement still belong to the same client.

## Contract

A canonical grant whose `authorization_grants.client_id` matches `engagements.client_id` remains resolvable.

If durable engagement ownership drifts to another existing client while the historical grant row retains the old client id, execution resolution must return `None`. It must not rely only on the stale grant lineage, silently repair either row, or mint cross-tenant authority.

After an explicit durable restoration to matching ownership, ordinary resolution may resume.

## Expected RED on #142

The current resolver selects the joined engagement status but does not select or compare `e.client_id` with `g.client_id`. Its lookup predicates only constrain the grant row to the in-memory snapshot:

```sql
WHERE g.grant_id=? AND g.client_id=? AND g.engagement_id=?
```

Therefore an engagement whose durable client owner has changed can still leave the historical grant resolvable.

The narrow source-owner repair belongs in #142's resolver query/validation boundary. It must require durable grant/engagement client coherence and fail closed without rewriting persistence.

## Independence

This is distinct from:

- #550/#551, which owns malformed persisted engagement lifecycle values;
- #471, which owns persisted grant temporal/provenance/scope schema;
- #106/#107, which owns live re-resolution of the exact grant snapshot;
- downstream `ExecutionPolicy` client/engagement checks, which consume the grant lineage and do not validate the joined engagement owner's durable record.

## Collision and safety

This branch adds only:

- `tests/test_scope_authorization_persisted_engagement_ownership.py`
- `docs/scope-authorization-persisted-engagement-ownership.md`

There are **0 production/source changes**. No target interaction, DNS/network I/O, scanning, handler dispatch, remediation/retest execution, deployment, verdict creation, or attack-path mutation is introduced.
