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
| Request approval | status other than exact `APPROVED`, mode other than `AUTHORIZED_ASSESSMENT`, no named operator or decision timestamp |
| Tenant/provenance | mismatched request/grant client or grant approver vs request decider |
| Assets | grant target not *exactly* present in requested assets; blank, duplicate, mixed-case, non-canonical, URL/port/wildcard, Unicode or variant-IP spelling |
| Risk | grant risk above approved risk, destructive lab-only mode, malformed risk |
| Time | decision in future, missing/invalid UTC decision, malformed or naive grant times, grant precedes decision, grant not current at explicit review instant |
| Metadata | invalid excluded target/capability item collection; malformed recurring retest flag |

The conservative **exact-string** comparison deliberately refuses aliases
instead of equating non-canonical host/IP representations. DNS names must be
lowercase ASCII labels with no trailing dot. IPv4 and IPv6 literals are
syntactically reviewed via standard-library `ipaddress`; no lookup occurs.
The reviewer does **not** prove whether assets belong to a customer, whether
a hostname resolves, whether a request belongs to an engagement, or whether
a declared approval is signed or persisted. Source-owner canonical scope
rules are authoritative; this toy format is only a strict offline reference.

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

Offline synthetic fixtures only:

```sh
python -m unittest discover -s tests -p 'test_scope_request_grant_offline_review_177.py' -v
```

The acceptance suite checks approved narrowing, invalid status, mode, tenant,
approver, assets, risk, timeline, metadata, polymorphic identities, output
redaction, no-network property, and inclusive **non-authorizing** time bounds.
All fake client and asset names are fixed fixtures; no target traffic or real
credential is accessed. Passing these tests **does not close #177**.
