# Live grant identifiers must be canonical identities

Issue: #873

Pinned source owner: draft PR #107, exact head `c37ee27d922a7dd400eee1db39268f4a6269e431`.

## Boundary

Immediately before a `TARGET_ACTIVE` handler runs, PR #107 re-resolves the
caller snapshot against durable authorization state and then checks that the
returned grant has the same ID as the snapshot.

That boundary is only trustworthy if the snapshot `grant_id` is itself a
canonical identity.

## Gap

The resolver currently binds `grant.grant_id` directly into SQLite. Python
SQLite accepts objects implementing the adaptation protocol, so a
producer-impossible object can present arbitrary runtime identity while binding
the bytes/text of a real durable grant ID.

The executor then performs ordinary equality:

```python
authorization.grant_id != snapshot_grant_id
```

A caller object can also customize equality so the canonical returned grant ID
appears equal to that non-canonical snapshot identity.

A matching-text `str` subclass is likewise producer-impossible and should not
cross an authority-bearing identity boundary.

## Required contract

Before durable lookup or equality-based admission:

- `type(grant.grant_id) is str`;
- the value is non-blank and already canonical;
- SQLite-adaptable non-string objects fail closed;
- `str` subclasses fail closed;
- rejection occurs before target handler invocation;
- rejection produces no evidence;
- exact canonical grant IDs retain normal target-active behavior.

## Expected RED

Against the pinned #107 source:

- canonical exact-string control should remain GREEN;
- a SQLite-adaptable object that binds the real durable ID and equality-spoofs
  that ID is expected RED because it can currently traverse both resolver and
  executor identity checks;
- a matching-text `str` subclass is expected RED because no exact-type guard
  exists.

## Non-overlap

PR #107 keeps all resolver/executor source ownership.

This acceptance slice is separate from:

- #567 request-side client/engagement identity typing;
- #743 direct grant client/engagement lineage typing;
- durable grant schema/time/revocation work;
- target/evidence-remediation/deployment/verdict/attack-path work.

## Safety

Temporary SQLite and in-process authorization proof only. No external target
interaction, DNS/network scanning, exploit behavior, remediation/retest
execution, deployment, verdict creation, or attack-path mutation.
