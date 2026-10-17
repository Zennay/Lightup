# #775 — exact direct ScopeDefinition container and text types

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Independent non-authorizing branch-only direct-source acceptance. The source owner remains [PR #554](https://github.com/Zennay/Lightup/pull/554), exactly pinned at `4c8d5651fc0e23f94514daae56b4e5fe0549de37`. No existing source, other-worker branch, runner, workflow or deployment is changed. [Issue #776](https://github.com/Zennay/Lightup/issues/776) requires branch-only while permanent registered VPS runner saturation persists, so no duplicate PR/workflow is opened.

## Original-source authorization risks

A frozen dataclass does **not** enforce exact tuple or string types. In original `ScopeDefinition`, overridden Python protocol methods can disagree with the data physically represented by a tuple or string subtype:

- asset `tuple` subclass may iterate a different allowed asset than its stored underlying value;
- exclusion `tuple` subclass may hide exclusions by overriding iteration;
- capability `tuple` subclass may return `True` from overridden `__contains__` even when the underlying tuple lacks that capability;
- `str` subclass for an asset or exclusion may override normalization (`.strip`) to spoof another identity;
- `str` subclass for a capability may override equality/hash and widen direct scope;
- hostile tuple iteration can run Python code before a weak validator rejects it.

These are **direct in-memory scope contract issues**, not evidence of actual target calls, durable grant issuance, an authorized assessment or a deployed exploit.

## Tested invariant and limits

For each exact `ScopeDefinition` instance, `assets`, `excluded_assets`, `allowed_capabilities` must be exact built-in `tuple` values whose every element is an exact built-in `str`. Malformed objects should fail at construction **before invoking foreign iterator/string callbacks**. Canonical exact tuple+string scopes continue to permit the correct explicitly listed asset/capability and reject exclusions and unknown assets. Empty canonical capability list remains **deny-all**, as currently implemented in owner #554.

New source-integrated [acceptance tests](https://github.com/Zennay/Lightup/blob/chatgpt/scope-775-exact-containers-strings-20261017/tests/test_scope_direct_collection_types_775_20261017.py): two ordinary positive controls and seven intentionally unresolved original `expectedFailure` canaries. Only a fresh separate owner source fix can upgrade them to real PASS:

```sh
PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_scope_direct_collection_types_775_20261017.py' -q
LIGHTUP_SCOPE775_REQUIRE_SOURCE_FIX=1 PYTHONPATH=src python3 -B -m unittest discover -s tests -p 'test_scope_direct_collection_types_775_20261017.py' -q
```

Use no actual clients, grants, scanners, targets, network, DNS, handlers, security verdicts or deployment. A test that says `OK (expected failures=7)` means seven original source holes remain **UNFIXED**. Independent source-owner review, original exact-SHA hosted+registered permanent VPS CI, separate genuine client/operator authentication and at-use revocation, independent security/privacy review and explicit HUMAN GO remain required before any release.

## 2026-10-17 · original-source RED and disposable repair evidence

- Current isolated original installed-source checkout Python3.14, exact branch pre-handoff HEAD `7e6ef9fe3bb312008b956f1699ae69aaf7fc37b9`: **9 tests = 2 ordinary PASS + seven intentionally unresolved source expectedFailures**, clean Git tree, no real targets or handlers.
- New separate, **temporary local clone only**, two independent owner-fix rehearsals in `src/lightup/engagements.py` at original pinned #554 source. The **correct** `ScopeDefinition.__post_init__` rejects all three collection fields unless `type(values) is tuple`, then rejects any member unless `type(item) is str`, *before iterating a nonexact container*. Under literal `LIGHTUP_SCOPE775_REQUIRE_SOURCE_FIX=1`: **9/9 ordinary PASS, zero expectedFailures**. A deliberately **incomplete** variant checking only exact tuple containers, not individual entries, remains strictly **RED with three real source failures** (assets, excluded assets, capability string subtypes). Nothing is committed to original source or owner branch.
- Cross-issue **#648 + #775 compatibility**, with only the #648 isolated test module copied temporarily into the same disposable #775 repair checkout: `LIGHTUP_SCOPE648_REQUIRE_SOURCE_FIX=1 LIGHTUP_SCOPE775_REQUIRE_SOURCE_FIX=1` yields **18/18 ordinary source acceptances GREEN**, zero expectedFailures. The complete original suite with both cases included: **585 unit tests OK, no expected failures; 86 integration tests OK**. Disposable local files changed are only `M src/lightup/engagements.py` and one locally copied untracked #648 test module; no production branch or original source code remotely modified.
- This optional strict local rehearsal proves the #775 and #648 invariants can coexist under a source-owner **reject-noncanonical-input** policy, but does **not** prove release, full hosted Python versions, permanent named VPS runner execution, separate client/operator consent or at-use revocation. Any source-owner repair must be independently reviewed with the related #646/#773/#776 boundaries.
