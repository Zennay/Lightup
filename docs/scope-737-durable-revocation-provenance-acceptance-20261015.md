# #737 — stale durable-grant revocation metadata: original-source RED and isolated reference

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an independent, fully synthetic source-owner acceptance **not an implementation**. No real customers, targets, grants, scans, network I/O, handlers, operations, active authority, merge or release.

## Owner / collision

- [Open #737](https://github.com/Zennay/Lightup/issues/737), unclaimed by an issue-specific PR or branch when selected. Existing source-owner [draft #100](https://github.com/Zennay/Lightup/pull/100) exact frozen SHA: `ef553b6e0aa0c99855e9907f4b2dee9edc5aac0f`. Base this PR **directly on #100's branch, not main**.
- Changed paths are **new** `tests/test_scope_737_stale_durable_revocation_provenance_20261015.py`, `tests/test_scope_737_revocation_reference_preview_20261015.py`, and this document. Owner source `src/lightup/engagements.py`, `src/lightup/execution_policy.py`, SQLite production persistence, other worker branches, CI and VPS config remain unchanged.
- Distinct work: #722 legacy revocation; #560/#562 persisted coherence, #347/#734/#735 durable time parsing; #475/#554 live persisted dispatch revalidation.

## Real installed-source acceptance

`test_scope_737_stale_durable_revocation_provenance_20261015.py` invokes **real installed** `AuthorizationGrant.is_current` and `ExecutionPolicy.decide(TARGET_ACTIVE)` with fictitious valid target/capability/client/engagement. Controls cover correct unrevoked behavior, explicit revoked denial, fixed canonical future/expired instants, mismatched tenant/asset/risk denial and immutable data. **Eight deliberately expected original-source RED** cases require denial when revocation actor, reason, both, or even present-but-empty provenance exists without `revoked_at`. The source currently treats such objects as current. These are *not* successful security fixes.

`test_scope_737_revocation_reference_preview_20261015.py` includes test-only `reference_current`, wrapping original installed method with strictly **narrowing** semantics when `revoked_at is None` but `revoked_by is not None` or `revocation_reason is not None`. The reference is installed **only inside scoped `unittest.mock.patch.object`**, never persists, and does not modify source or grant issuance. Original method identity is checked after every reference test. Synthetic positive/negative controls verify that direct policy decisions deny stale provenance under the reference while legitimate grants, time boundaries and explicit revocations behave as before. A diagnostic witness separately proves the actual original source allows inconsistent in-memory grants. This witness must be retired when source owner implements a genuine repair; it must **never** be promoted as a release criterion.

## Required owner repair

1. Source owner #100 must reject inconsistent revocation metadata at construction or check time, without granting authority on malformed objects. The precise place/exception policy is theirs.
2. Real installed-source REDs must turn into ordinary denial PASS (remove `expectedFailure`), and the **diagnostic unsafe-source witness** must be retired/rewritten after real fix. Test-only reference acceptance does not repair product code.
3. Owner must preserve tenant/engagement/asset/capability/risk/time and live revocation gates. Persisted path and transport/runner behavior are **not** proven by these pure in-memory tests.
4. For this exact PR SHA, independently inspect GitHub-hosted Python 3.11/3.14 raw checkout job logs, full unit suites and actual producer integration logs. Separately require **genuinely assigned permanent registered VPS runner** evidence, independent security/privacy review, actual customer/operator consent, and explicit human release.

No conflict or wait state can imply approval. **DRAFT/HOLD, NO MERGE/DEPLOY/SCAN/GRANT/ACTIVATION.**
