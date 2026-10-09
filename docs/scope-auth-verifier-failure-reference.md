# Authorization proof verifier failure boundary — offline reference

**Phase:** LightUp M7/ST5; fail-closed hardening only. This document and accompanying stdlib test are a *reference* for production-owner review, **not** production authorization enforcement.

## Invariant
When a trusted issuer-owned authorization proof lookup or verification cannot produce an explicit canonical boolean success, the admission/dispatch decision must be **deny**. A timeout, database outage, verifier exception, malformed return type or partially fetched record must not turn into a permit, a stale cached permit, or a fallback to caller-supplied claims.

## Offline acceptance cases
- An exact `True` result is *conditionally eligible* only; it is not proof of issuer provenance, current grant revision, tenant binding or active permission.
- `False`, `None`, truthy integers/strings/containers, or exception paths deny.
- Malformed, polymorphic, whitespace/control-character/Unicode-format ambiguous (including zero-width and line/paragraph separators), non-builtin-string, or oversized (>256 code point) reference envelopes deny before verifier invocation. The 256-character ceiling is an illustrative fixture limit, **not** an adopted production identifier policy.
- Reference inputs remain unchanged after failure; no client-provided metadata is treated as authority.
- The reference invokes a supplied verifier at most once per decision. Failed issuer lookups cannot silently invoke a permissive fallback, retry with relaxed controls, or reinterpret unavailable evidence as consent. Missing/non-callable verifier inputs deny.

## Production owner handoff
At **each** request admission, queue retry, step boundary and target-capable dispatch: resolve live issuer-owned grant and verify tenant, request, asset, capability, risk, approval lineage, revision, expiry, revocation, current test window and audit durability. Deny on unavailable source or indeterminate status. In-flight cancellation/revocation and positive-cache invalidation require production integration and separate evidence.

This model intentionally does not call DNS, network targets, scanners, capabilities or executors. Its caller-supplied `verifier` is a test seam: it must never be supplied by an untrusted client in production. It does not perform cryptographic proof verification and does not confer permission.

## Promotion gate
The authorization executor/source owner (existing PR #107) retains production ownership. Require exact-head Python 3.11/3.14 hosted **and permanent VPS** proof, owner review and real-domain test coverage before merging or claiming the invariant enforced. No real target activation is authorized by this PR.

## CI regression repair ledger (2026-10-09)

- Hosted preflight for predecessor `0c91483c290bd45b46618a5cd25a0fb22cc5ed70` (`37872558358`) exposed incorrectly doubled Unicode escape literals in the offline fixture, producing five failures in the Python 3.11 unit job. That predecessor is **not green proof**.
- The fixture literals were corrected on head `26b06ffc661b76bd0f89b4228b7b07ce2847eba8`. This correction does not alter production behavior.
- Acceptance still requires **new exact-head** hosted preflight on both Python versions plus canonical permanent VPS proof. Older runs, cancelled integration jobs, and this reference-only success must not be represented as production authorization acceptance.
