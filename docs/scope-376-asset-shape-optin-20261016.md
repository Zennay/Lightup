# Scope #376 — fictional durable asset identity shape review (DRAFT/HOLD)

## Purpose and ownership
This isolated child work addresses [issue #376](https://github.com/Zennay/Lightup/issues/376) without editing the existing `DomainStore.record_authorization_grant`, `ScopeDefinition`, the domain owner #554, the public-scope owner #100, other worker branches, workflows, or runners. Branch created from current `main`; all three paths are new and dedicated to this review.

**INCUBATE M3/M7 · PLAN/LAB ONLY. No source integration, merge, deployment, customer grant, handler invocation, scanning, or release.**

## Exact delivered contract

- `src/lightup/scope_376_asset_identity_review.py`: optional, unwired pure review function `review_asset_identity_shape`. It accepts only an exact `ScopeDefinition` with an exact nonempty tuple of built-in canonical already-trimmed text allowlisted assets and an optional exact tuple of equally well-formed excluded assets. Each collection is bounded to 256 entries and each identity to 2,048 characters; control characters, subclasses, blank or untrimmed entries are rejected before any untrusted string overrides run.
- `REVIEW_ONLY` means only a conservative *shape* check succeeded. The frozen receipt is always false in boolean contexts, exposes six literal false authority markers, and never echoes targets, tenant IDs, consent references, raw input, or claims. `HOLD` is returned atomically for invalid shapes.
- `tests/test_scope_376_asset_identity_optin_20261016.py`: ordinary fixture-only checks, boundary limits, polymorphic string and scope rejection, mutation guards, no-I/O checks, a positive real SQLite legacy roundtrip, and three **deliberately OPEN original-source expected failures** against actual `DomainStore.record_authorization_grant`. A separate RED oracle requires all three source failures to remain real, not hidden successes or runtime exceptions.
- The reviewer does **not** establish DNS/IP identity, CIDR validity, Unicode equivalence, ownership, consent, client/engagement binding, revocation, allowed capabilities, expiry, temporal validity, exact self-hosted GitHub runner proof or human approval. It MUST NOT be used as a permit or wired to active execution.

## Owner decision needed
The existing domain/grant source owner should decide whether this narrow text-shape preflight, or an equivalent source-side guard, belongs directly before any persisted grant row. The reviewer ceilings are **illustrative** and may reject legitimate large scopes; do not treat them as approved product policy. If integrated, the original source must enforce the same reject-before-write semantics and preserve valid grant roundtrips. Convert the three original-source expectedFailure methods to ordinary PASS only after the actual production source is fixed and revalidated. Do not claim the opt-in helper fixes persistent authorization.

## Verification and gating
- Validate exact immutable HEAD with original GitHub-hosted Python 3.11 / 3.14 jobs and real producer integrations; inspect **exact-head** job logs. A queued or absent VPS job is not evidence of a successful registered permanent VPS test.
- Independently verify production composition, security/privacy, real customer and operator consent, current durable revocation, runner registration/labels, and explicit human GO before any release.
- Existing release/runner issue: [#1144](https://github.com/Zennay/Lightup/issues/1144). Existing original durable-resolver issue: [#639](https://github.com/Zennay/Lightup/issues/639). This branch does not change either owner's code.

**Status remains DRAFT/HOLD regardless of isolated successful tests.**
