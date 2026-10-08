# Offline authorization cache-key isolation — M7/ST5

This is a **reference-only regression contract**, not an implementation of authorization or a production cache. It exercises fully bound cache-key identity and demonstrates why cross-tenant, cross-grant, cross-capability, policy-version, and revocation-epoch collisions are unacceptable.

The illustrative key binds tenant, engagement, grant, asset, capability, risk, policy revision, and revocation epoch. Missing, extra, blank, non-string, or whitespace-padded fields disable caching in this fixture rather than falling back to a permissive partial key. A change to **any** bound field must cause a miss. The fixture demonstrates why asset-only keys are unsafe when the same asset appears under different tenant contexts.

**Important limitations:** Key isolation is necessary but insufficient. A cached historical 'eligible' verdict is not an executable grant. The real executor must revalidate signed trusted approval lineage, current tenant/engagement/asset/capability/risk binding, clock and approval window, policy changes, exclusions, revocation, and any other dispatch gate at the moment of action. A durable cache must also have a fail-closed invalidation protocol; a revocation epoch included in a key is worthless if stale requests can still supply or replay an old epoch. Treat missing/unavailable authoritative revocation state as a denial, never as a fallback to an old cached allow.

Run on the isolated branch:
`python -m unittest discover -s tests -p 'test_scope_cache_key_isolation_reference_20261008.py' -v`

Ownership: no modification to production authorization or executor code; production integration belongs to its source owner (PR #107). Remain draft until exact-head CI, canonical VPS verification, and independent review demonstrate a viable implementation. No real targets, network scanning, or active verification.
