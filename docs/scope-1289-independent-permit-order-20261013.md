# LightUp #1289 — independent permit-order acceptance (stacked add-only)

**Posture:** INCUBATE M3/M7 · PLAN/LAB ONLY · **DRAFT/HOLD/NO MERGE/NO DEPLOY**.

## Isolated scope and ownership

Stacked on existing source-owner [draft #1290](https://github.com/Zennay/Lightup/pull/1290), pinned at immutable head `9d6041dbdac37a56462d2e0279416c052fe67908`. The parent implements the opt-in `StrictTargetScopePolicy`; this child adds **only new test and documentation files**. It does not modify parent source, legacy `scope.py`, `activation.py`, domains, webauth, alternate workers, CI workflows, or production deployment. The parent PR remains review-owned by its original branch. No default integration is enabled by this tests-only slice.

## Invariant and evidence requirements

The strict target admission decision must remain independent of an execution permit: invalid original target identities may not cause even an in-process `ExecutionPermit` identifier to be minted, even when the caller supplied authorization metadata. This is stronger than checking only an `INVALID_TARGET` reason after returning a decision.

The new [11-method offline acceptance suite](../tests/test_strict_target_permit_order_1289.py) asserts:

1. Hostname CR/LF rewrite, userinfo, invalid ports, bracket-tail garbage, percent-encoded authority, protocol-relative syntax, and synthetic authority-smuggling strings fail **before** `ActivationGate` calls `token_urlsafe`, both in LAB_ONLY and AUTHORIZED modes.
2. An invalid target also fails before even consulting the legacy scope policy or an authorization `is_current` callback, with sentinel mocks that raise if evaluated.
3. Target subclass input is refused before permit minting despite identical textual value.
4. Canonical valid loopback and bracketed IPv6 create only synthetic in-process permits whose target field contains a normalized hostname/IP, never an URL path/query, and with exactly one mocked token-generation call.
5. Valid public explicit-host authorization still requires AUTHORIZED mode plus an existing current grant; LAB_ONLY, expired/missing grant, unlisted asset and PLAN_ONLY are refused before minting.
6. Scope decisions require no DNS or socket connections; tests patch both calls to throw if used.

No real permit is delivered to an adapter, no active tool or target invoked, and no DNS, network, customers, grants, secrets, assessments, external models, database writes, findings, evidence, retests or deployments are exercised. `token_urlsafe` is mocked, so even its normal call is replaced with a synthetic marker.

## Review, CI and release gating

- Run `python -m unittest -v tests/test_strict_target_permit_order_1289.py` with `PYTHONPATH=src` on the PR exact SHA; execute hosted Python 3.11/3.14 and independent permanently registered self-hosted VPS exact-head CI. Previous parent CI results are not proof of this child head.
- Recheck child diff is exactly two **new files** relative to frozen parent SHA; never merge this into source-owner branch without reviewer agreement.
- Child work is an independent offline regression, not proof that the default or installed web/worker calls the optional policy or that a real network adapter is correctly bound. Original source owner, privacy/security reviewer, latest-main composition and explicit human approval remain required before any merge/deploy.
