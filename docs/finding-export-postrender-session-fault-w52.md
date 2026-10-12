# W52 post-render session failure atomicity — opt-in CSV (#1197)

**Safety posture:** LightUp Incubate / M3–M7 PLAN/LAB ONLY. This is an isolated **tests-only** child of immutable W11 [draft PR #1198](https://github.com/Zennay/Lightup/pull/1198) exact head `bda8381857cc6767e1675e711c48e46b507f6864`. Default web application, original owner files, installed ingress and other worker branches remain untouched. No production deployment, client information, grant, active scan, remediation or verified retest.

## Why it matters

The optional W11 WSGI factory selects and renders tenant-scoped CSV, then re-reads the real durable session before sending the response. Earlier W11 tests cover explicit revocation and account transfer during rendering. W52 independently characterizes **failed or unexpectedly changed post-render session revalidation** without modifying the current handler.

Five genuine in-process WSGI regression methods share the existing disposable two-tenant SQLite fixture and issue a signed-in GET through the optional checked factory. A guarded real checked CSV renderer emits a synthetic completed CSV first; **only after this** the instrumented session resolver returns a missing session, changed real AccessContext, invalid context type, or raises a synthetic `sqlite3.DatabaseError`, `ValueError` or `KeyError`. An additional path expires the **actual disposable SQLite session record** immediately after checked CSV creation, then requires the unmocked session lookup to deny the response. All denial cases must return **403, not CSV**, no finding ID/private data, keep `no-store`/`nosniff` headers and leave persisted data unchanged. Explicit markers prove the fault happened *after* a successful tenant CSV render and that final revalidation actually ran.

Reproduce from repository root:

```bash
PYTHONPATH=src python -m unittest -v tests.test_finding_export_postrender_session_fault_w52
```

These synthetic fault-injection tests do NOT demonstrate an actual Nginx/Gunicorn deployment, cookie parsing or distributed session consistency, bound post-send revocation races, guarantee secret redaction or authorize any asset. They assert the behavior of one opt-in, uninstalled factory only.

## Acceptance and release

- Record exact W52 commit/head, hosted Python 3.11 and 3.14 unit + real-producer integration results, and permanent registered `vps-bb300bba` CI *completed* exact-head success separately. Queued VPS is **not** accepted evidence.
- Owner review must cover #1197/#1198 and source owners of web/session/export, installed ingress and tenant privacy, race semantics and current-main compatibility.
- **DRAFT/HOLD/NO MERGE/NO DEPLOY.** No interaction with external targets, real client DB, scanner, grant, remediation execution or verified retest.
