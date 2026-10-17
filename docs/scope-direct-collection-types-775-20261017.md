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
