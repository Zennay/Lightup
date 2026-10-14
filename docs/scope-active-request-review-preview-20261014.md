# LightUp active assessment request — offline human-review preview

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/NO DEPLOY/NO REAL TARGETS.

## New capability

`lightup.scope_request_review.preview_active_request` is an **opt-in, side-effect-free, in-memory** review helper over the *real* `AssessmentRequest` and `AuthorizationGrant` model types. No network, DNS, scanning, SQLite, agent dispatch, grant issuance, operator login, production handler or deployment change.

For a candidate active-assessment request it checks:
- Exact model/enumeration types; mode must be AUTHORIZED_ASSESSMENT and risk in LOW_IMPACT..ELEVATED (never destructive).
- Nonempty bounded canonical request assets (1–32), strict identifiers, no wildcard/URL-path/Unicode authority aliases, no duplicate assets.
- Nonempty canonical grant identity; matching tenant ID, distinct reviewer/requester labels, exact boolean retest marker.
- Explicit bounded grant assets, exclusions and **nonempty** capability list (legacy empty capability list means wildcard; refused for review); **caller must explicitly name one canonical requested capability and it must occur in the grant**.
- Risk never exceeds grant; requested asset inventory fully contained in grant and outside exclusions.
- UTC-only aware datetimes, a non-inverted window, strict half-open `[valid_from, valid_until)` freshness checked against caller-supplied or local UTC time.

A syntactically consistent packet produces `REVIEW_ONLY`, **not** an approval. Invalid or ambiguous packets produce `HOLD` with a stable reason code. Neither is executable proof. Every response hardcodes `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`. Receipts never echo targets, identifiers, secret material or exceptions. Negative-review asset count is zero to avoid partial authorization interpretations.

## Example (offline only)

```python
from datetime import datetime, timezone
from lightup.scope_request_review import preview_active_request
# request / grant are already-constructed *untrusted* in-memory model objects:
receipt = preview_active_request(request, grant, capability_id="http-baseline", now=datetime.now(timezone.utc))
assert receipt.status in {"HOLD", "REVIEW_ONLY"}
assert receipt.authorization_verified is False
assert receipt.execution_enabled is False
```

## Explicit trust boundaries

This **does not prove** consent signatures, proof-of-ownership, reviewer identity or separation-of-duties, tenant binding to a real session, active grant status in trusted storage, current revocation, policy composition at dispatch, network destination/DNS/IP pinning, immutable CI evidence, runner identity, any security or privacy approval, or release permission. A forged `AuthorizationGrant` dataclass may still look structurally correct. A positive preview MUST NOT feed an executor as a permit or authorize a scan. It is deliberately **not installed** into the existing product execution path. Source-owner integration requires its own independent review and explicit authority checks.

## Verification & collision rules

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_request_review_offline.py' -v
```

- Dedicated real-model synthetic suite covers positive/non-authorizing receipt, fake grant, cross-tenant, same actor, missing/wildcard capabilities, excluded/outside assets, Unicode/URL aliases, exact risk type, time edges, privacy, non-mutation and no network.
- Scope-authorization isolated branch from immutable original main; **new source, tests and docs files only**, no existing source-owner paths, workflows, runners or main edits.
- Exact-head hosted Python 3.11/3.14 unit + genuine producer integration CI and independently executed permanent VPS jobs, security/privacy/source-owner review and explicit human release decision are separate gates. Do not merge or deploy merely because a synthetic test passes.
