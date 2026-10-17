# LightUp #1533 — ToolOutput identity contract (offline, DRAFT/HOLD)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This branch is independent of #1531 handler-registration admission, #1152 output metadata identity, #1454 evidence-before-handler, and all source-owner branches.

## Exact original source finding

`src/lightup/ai/orchestration.py` defines a frozen `ToolOutput(summary, evidence_kind, evidence_payload, metadata)`, but its constructor does **not** check field types, plainness, or nonblank identity. `ToolExecutor.execute` only tests that returned objects are instances of `ToolOutput`; type-invalid identity can reach later evidence/result handoff. This is an evidence audit contract and availability/integrity issue — **not** an authorization bypass. `StateStore` and all production files are untouched.

## Isolated, material acceptance

- New unwired pure `review_output_identity` returns an immutable **falsy** `REVIEW_ONLY` enum receipt for exact plain nonblank `str` summary/kind and exact immutable `bytes` payload; otherwise immutable falsy `HOLD`. An accidental `if receipt:` can never authorize. Neither status can confer authority. Foreign subclasses and coercion protocols never run.
- Original-source nine specifically named `expectedFailure` cases: nonstring or blank summary, nonstring or blank kind, mutable bytearray payload, string payload, and forged plain-scalar subclasses (summary, kind, payload). Actual production repair would convert these to ordinary passing asserts that reject before any result/evidence handoff; no handler execution occurs in this test suite.
- Literal owner post-fix switch: `LIGHTUP_SCOPE1533_REQUIRE_SOURCE_FIX=1 python -I -S -B -m unittest discover -s tests -p 'test_scope_tooloutput_shape_1533_20261017.py' -v`. In current original source this command must fail exactly nine tests; this is intentional RED debt, not a promoted security pass.
- Dedicated opt-in hosted Python 3.11 / 3.14 branch-only workflow, no secrets, no real assets, no scans/grants/handlers, no production/deploy modifications. Only own new paths.
- Metadata intentionally excluded: dedicated existing [#1152](https://github.com/Zennay/Lightup/pull/1152) covers duplicate/reserved metadata. Do not overwrite those owners.

## Release remains HOLD

Source owners decide and review a future actual `ToolOutput` or pre-handoff validation fix. Nothing here proves authenticated independent client/operator consent, consent revocation at use, permanent named VPS runner `vps-bb300bba`, complete original CI, independent security/privacy approval or human GO. Original #301 fixture preflight is separately RED. **No merge, deploy, actual target, active scan, tool dispatch, grants or release.**
