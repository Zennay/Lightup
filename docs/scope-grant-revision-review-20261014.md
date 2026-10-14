# Grant revision narrowing review (offline, opt-in)

## Problem and ownership

A later grant snapshot can accidentally widen an existing customer's declared
asset scope, capabilities, risk ceiling, validity window, or recurring-retest
authority. LightUp needs a way for an operator to compare two **self-declared**
grant objects *before* a human reviews the change. This implementation is a
new isolated module; it does **not** alter the original `AuthorizationGrant`,
`ExecutionPolicy`, state store, active executor, web app, target adapters,
other workers, or CI configuration.

## What is implemented

`lightup.grant_revision_review.review_grant_revision(current, proposed)`
accepts the project's real frozen `AuthorizationGrant`/
`ScopeDefinition` classes and returns a small, privacy-safe receipt.
It enforces:

- Exact canonical grant, tenant, engagement, operator and reference identity.
- Non-increasing asset membership; no new assets.
- No removal of an excluded asset **while that asset remains in scope**.
  Removing an excluded asset entirely is safe and supported.
- Capability subset checks. **An empty `allowed_capabilities` means wildcard
  in the existing application**, not an empty allowlist. A proposed wildcard
  always yields `HOLD`, even when the original also had one.
- Exact `RiskLevel` identity, non-increasing maximum and refusal to present
  destructive risk 5 as a normal real-target grant.
- Strict timezone-aware UTC windows, preserved or shortened only, with
  well-ordered endpoints.
- `recurring_retest_allowed` must be a real `bool`: true-to-false is safe;
  false-to-true is rejected.
- Canonical bounded ASCII token sets. Duplicate, confusable, noncanonical
  and oversized inputs fail closed rather than being normalized by DNS.

`REVIEW_ONLY` means only *syntactically non-widening relative to supplied
objects*. Even equality and old expired grants can return `REVIEW_ONLY`.
The caller's snapshots are untrusted; this checks neither their authenticity,
freshness nor authorization. It must **not** grant permission to scan.

Every receipt fixes `authorization_verified`, `permit_issued`,
`execution_enabled`, `merge_approved`, and `release_approved` to
`False`. `HOLD` is returned on invalid input. Neither result may be used
as a permit, execution signal, green CI attestation, verified client consent,
or human sign-off.

## Minimal offline usage

```python
from lightup.grant_revision_review import review_grant_revision

# current and proposed are locally constructed AuthorizationGrant objects.
receipt = review_grant_revision(current, proposed)
assert not receipt.execution_enabled
print(receipt.verdict, receipt.reason_code, receipt.narrowed_fields)
```

Local tests (with repository `PYTHONPATH=src`):

```bash
PYTHONPATH=src python -m unittest -v tests.test_grant_revision_review
```

No database/customer state, internet target, socket, DNS, credentials, grant
issuer, release workflow, or scanner is accessed or modified. The test suite
uses real in-repository authorization data classes and synthetic `.test`
assets, and checks privacy and no-socket/no-database properties.

## Non-goals and mandatory gates

- **No integration into `ExecutionPolicy`, active admission, existing owner
  branches or production.** The module is not wired into any executor.
- Does not verify tenant, owner identity, reference signatures, clock trust,
  revocation, approval/release, mutable data-store version, policy version,
  full grant history, or original authorization provenance.
- A self-declared narrowed revision must never be treated as a trustworthy
  new grant or used to bypass active checks. Live/revocation validation is
  separately owned by other workers.
- Identity equality is not cryptographic authenticity. Exact string membership
  is intentionally conservative; adding IDNA, trailing-dot, DNS, IP aliases,
  or CIDR canonicalization requires a separate reviewed contract.

Next source-owner step (not automatic): integrate any desired human-facing
read-only preview with a **trusted persisted original grant**, version fencing
and explicit operator authorization. Independently review privacy and scope,
verify Python 3.11/3.14 exact-head hosted and registered permanent VPS test
logs, and obtain human merge/release approval.

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE · NO
DEPLOY · NO REAL SCANS.**
