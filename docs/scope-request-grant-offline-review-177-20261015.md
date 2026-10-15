# LightUp scope-authorization #177 — offline request ↔ grant review

**State: INCUBATE M3/M7 • PLAN/LAB ONLY • DRAFT/HOLD. Not an authorization mechanism.**

## Why this exists

Current `DomainStore.record_authorization_grant` does not persist a foreign key to an
approved assessment request. A structurally valid `AuthorizationGrant` cannot
prove that the matching client actually obtained operator request approval.
Issue [#177](https://github.com/Zennay/Lightup/issues/177) remains **open**.

`src/lightup/request_grant_offline_review_177.py` is an **uninstalled, offline,
opt-in reference**, isolated from production source owners and other worker PRs.
It accepts two explicitly untrusted in-memory snapshots built from the actual
`AssessmentRequestRecord` and `AuthorizationGrant` classes plus a caller
supplied review instant. There is no network, DNS, database, clock read, mutation,
token, scan, or action on any customer system.

## Invariant matrix

| Gate | Explicit HOLD trigger |
| --- | --- |
| Types | non-exact request/grant/scope objects, impersonated strings or enum values, bool/int risk type confusion |
| Request approval | status other than exact `APPROVED`, mode other than `AUTHORIZED_ASSESSMENT`, no named operator, malformed request creation timestamp or decision timestamp; decision predates request creation |
| Tenant/provenance | mismatched request/grant client or grant approver vs request decider |
| Assets | grant target not *exactly* present in requested assets; blank, duplicate, mixed-case, non-canonical, URL/port/wildcard, Unicode or variant-IP spelling; excluded assets not among the granted set |
| Risk | grant risk above approved risk, destructive lab-only mode, malformed risk, empty wildcard capabilities (meaning unrestricted in the real model), unknown IDs, or LAB_ONLY/DISABLED IDs rather than canonical PLANNING capabilities |
| Time | decision in future, missing/invalid UTC decision, malformed, non-UTC-offset or naive grant times, hostile custom timezone object, grant precedes decision, grant not current at explicit review instant |
| Metadata | invalid excluded target/capability item collection; malformed recurring retest flag |

All identity fields also use a bounded (max 128 characters) ASCII identifier grammar with no whitespace or control characters. Empty allowed capability tuples are refused because the real ScopeDefinition interprets an empty allowlist as **unlimited tools**. The reviewer also requires a canonical request-created timestamp to precede the decision, strict built-in UTC timezone identity for supplied datetime objects, and a real high-level PLANNING-only capability ID from the currently installed catalogue. The catalogue check does not authenticate the caller or any authorization.

The conservative **exact-string** comparison deliberately refuses aliases
instead of equating non-canonical host/IP representations. DNS names must be
lowercase ASCII labels with no trailing dot. IPv4 and IPv6 literals are
syntactically reviewed via standard-library `ipaddress`; no lookup occurs.
The reviewer does **not** prove whether assets belong to a customer, whether
a hostname resolves, whether a request belongs to an engagement, or whether
a declared approval is signed or persisted. Source-owner canonical scope
rules are authoritative; this toy format is only a strict offline reference.

## Atomic multi-request review (opt-in)

`review_request_grant_batch(pairs, reviewed_at=...)` accepts only an exact Python tuple of 1–32 exact two-tuples of untrusted request/grant snapshots, all on one declared client. Every member must already be structurally REVIEW_ONLY using the single-grant reviewer. Duplicate request IDs, duplicate grant IDs, effective granted-asset overlaps, mixed tenants, malformed entries and input above the limit cause a single **atomic HOLD**. No per-item status, no granted asset/client ID, no partial acceptance. A completely coherent batch remains **REVIEW_ONLY with all six false flags**. Excluded assets are not treated as effective scope membership during overlap checking; overlapping claims without actual granted membership are still not permission. The batch performs no I/O or issuing step and is **not** a release authority.

## Three-way engagement lineage review (opt-in)

`review_request_grant_engagement(request, grant, engagement, reviewed_at=...)`
additionally inspects an **untrusted snapshot** of the real `EngagementRecord`.
It requires exact built-in `EngagementRecord`, exact declared
`EngagementStatus.AUTHORIZED` (DRAFT/RUNNING/CLOSED do not count as approval),
exact matching grant engagement ID, identical client on all three objects, and
canonical UTC engagement creation before the declared grant start. Type-confused
grant windows and malformed engagement timestamps atomically HOLD.
A coherent engagement snapshot still cannot establish an authenticated link
from the original assessment request to that engagement: the current domain
schema has **no such request FK**. The result remains `REVIEW_ONLY`, all
six authority flags false, with zero persistence or operational side effects.
Only source-owner implementation of a real durable request→grant→engagement
chain can resolve issue #177.

## Atomic composed 3-way review

`review_request_grant_engagement_batch(entries, reviewed_at=...)` composes
both strictly offline checks. It accepts an exact tuple of **1–32 exact
three-tuples** (request, grant, engagement). It refuses any invalid three-way
engagement lineage before applying the single-tenant, duplicate request/grant ID
and effective target-overlap checks to the **entire** group. Malformed
container types, duplicate records, mixed clients, one revoked/draft engagement,
unknown asset, risk escalation or a 33rd record are all an **atomic HOLD**.
Thirty-two distinct entirely synthetic, coherent records are still
`REVIEW_ONLY` only, with all six authority flags literally false. No
persistent cross-record linkage, consent, dispatch or trusted grant is created.

## Results and hard boundary

- `HOLD`: malformed or incoherent untrusted snapshots.
- `REVIEW_ONLY`: their declared shapes are mutually coherent but **not
  independently verified**. **Not PASS.**
- **Both** outcomes have exact literal `False` for `authorized`,
  `grant_allowed`, `dispatch_allowed`, `scan_allowed`,
  `merge_allowed`, and `deploy_allowed`. The receipt contains only
  fixed, non-customer-specific reasons. Nothing is installed into grant
  persistence, `ActivationGate`, `ScopePolicy`, `ToolExecutor`, or web ingress.
- Under **no circumstances** should `REVIEW_ONLY` be converted into a grant,
  permit, approval, dispatch, release, or CI PASS.

## Required production integration (not done here)

An independent source owner must implement durable approved-request linkage
on the same client **and engagement**, review decision persistence, immutable
operator provenance, exact canonical asset subset, approved mode/risk, current
grant + revocation checks on each active operation, and audit trail consistency.
Security/privacy review, current operator/customer consent, exact-head hosted
CI and separate registered permanent-VPS proof, then explicit human merge and
deployment authorization are required before a real active path can be enabled.

## Test

Offline synthetic fixtures only; real Python 3.11/3.14 CI validates single/batch denial, catalog and exact UTC isolation:

```sh
python -m unittest discover -s tests -p 'test_scope_request_grant_offline_review_177.py' -v
```

The acceptance suite checks approved narrowing, invalid status, mode, tenant,
approver, assets, risk, timeline, metadata, polymorphic identities, output
redaction, no-network property, and inclusive **non-authorizing** time bounds.
All fake client and asset names are fixed fixtures; no target traffic or real
credential is accessed. Passing these tests **does not close #177**.
