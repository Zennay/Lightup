# Evidence-remediation W24 — checked WSGI post-render session shape

Status: **independent EXPECTED RED / DRAFT HOLD**, stacked on the exact [#1198](https://github.com/Zennay/Lightup/pull/1198) W11 head `bda8381857cc6767e1675e711c48e46b507f6864`; related issue [#1197](https://github.com/Zennay/Lightup/issues/1197). Add-only test + document. Default web/CLI, shared domain/session implementation, checked source owner and `main` unchanged.

## Narrow gap

`CheckedFindingExportWebApp.download_findings()` rechecks `store.session_context(token)` only *after* completing checked tenant CSV rendering. The current code verifies `live[0]` matches the pre-render `AuthState.context`, but it assumes the *shape* of `live` is a valid two-element tuple. A malformed adapter/store return (e.g. `()`, a mapping, arbitrary object, or unexpected tuple length) can otherwise throw an uncaught lookup exception or pass the first-element check without being canonical. This is **synthetic dependency-contract robustness**, not an observed real session compromise.

`tests/test_checked_export_postrender_session_shape_20261011_w24.py` uses the W11 **real WSGI + disposable SQLite fixture**, obtains a valid signed-in client session, creates a checked tenant CSV completely, and only then replaces the second persisted session lookup with seven malformed shapes. Acceptance requires a generic 403 **without releasing any generated finding ID or private canary**, `no-store` and unchanged persisted findings for each subcase. The canonical session positive control must continue serving redacted CSV.

## Owner review

A minimal potential fix is to validate the **exact tuple arity/type of the second persisted context** and fail closed *before* indexing or releasing output, while retaining the persisted principal/role/tenant equality check. Do not turn this synthetic assertion into a claim that adapters can return arbitrary objects in the deployed service. A source owner should decide precise CSRF element contract and exception containment, then run full exact-head dual-Python suite plus permanent self-hosted VPS CI and independent web/security/privacy/installed ingress review.

The test is expected to fail on unchanged #1198 source and is not a production release gate or a security verdict. No real tenant or target; no scans, external model, authorization grants, remediation/retest execution, merge or deployment. **M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.**
