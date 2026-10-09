# Session-principal binding — offline scope-authorization reference

This reference records an additional **non-authoritative** fail-closed invariant for a future interactive operator approval consumer. A previously approved operator identity must be bound to the authenticated session principal presented at use time. A caller cannot borrow a reviewer's approval, replace the operator with another human, or replay an approval under another tenant, request or revision.

The reference uses a frozen dataclass and pure string comparisons to make the expected decision table reviewable without browser cookies, identity providers, target I/O or privileged actions. The positive test is **not** an authenticated session, signed approval, grant issuance or permission for active assessments.

Requirements for a real integration:
1. Resolve the principal from a trusted, server-side verified session, never from a request payload or UI display label.
2. Independently load the current approved tenant/request/revision and current revocation state from issuer-owned storage.
3. Ensure approver differs from operator and session principal. Do not infer the approval from the session itself.
4. Revalidate before every capability dispatch, including asynchronous or resumed work; session changes and logout must invalidate a cached positive result.
5. Deny on malformed identities, revoked/expired approvals, mixed tenants, altered revisions, or absent session. Log a sanitized denial without secrets.
6. Preserve the separation between current assessment, isolated future simulation and lab evaluation. No implicit cross-purpose authority.

The standalone unittest is intentionally stricter about reference identifier grammar and only tests matching and negative cases. It does not implement authentication, authoritative grants, lifecycle management, policy integration or execution.

Run offline: `python -m unittest discover -s tests -p 'test_scope_session_principal_binding_reference.py'`.

Safety: no network, DNS, actual targets, scanning, deployment, approvals, worker dispatch or activation. Production ownership remains with existing scope authorization source owners. Keep the PR draft pending pinned-head hosted and permanent VPS CI evidence plus owner review.
