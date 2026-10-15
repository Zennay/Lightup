# #1454 — Evidence-before-handler authorization/accountability acceptance

**Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a diagnostic, never a production mitigation or approval. Exact synthetic issue: [#1454](https://github.com/Zennay/Lightup/issues/1454).

## Installed-source order observed

On `main` at `e73b7445c87ad239bdb03c50a99078ef93163b02`, `ToolExecutor.execute` checks `ExecutionPolicy`, then executes a registered handler, then calls `StateStore.add_evidence`. The latter inserts into SQLite. A SQLite insertion failure can therefore occur **after** the handler was called, leaving **no recorded evidence and no successful ToolResult**. This is an accountability gap in simulated local sequencing; it does **not** demonstrate any actual customer target call, scan, leaked secret or exploitable network attack.

## Eight real installed-source acceptance tests

`python -m unittest discover -s tests -p 'test_scope_1454_evidence_prehandler_acceptance_20261015.py' -v`

The dedicated fixture constructs a **fabricated** low-impact TARGET_ACTIVE authorization, real `ExecutionPolicy`, real `ToolRegistry`/`ToolExecutor`, registered disposable SQLite run, and pure in-memory mock handler. The handler appends to a local Python list only. There is **no socket, DNS, shell, real customer grant or tool-worker integration**.

| Case | Current expected outcome | Release interpretation |
| --- | --- | --- |
| Normal synthetic policy-allowed tool | Handler exactly once; one SQLite evidence row | Control PASS only; not a real consent proof |
| Absent-grant policy denial | `ToolDenied`, handler not invoked, no evidence | Ordinary PASS |
| Required pre-handler durable attempt gate | **expectedFailure** while the ledger refuses insertion | **Open source RED; NOT FIXED** |
| SQLite failure witness | Exact `IntegrityError` from explicit `BEFORE INSERT` trigger; handler once, no evidence | Ordinary PASS corroborates failure ordering |
| Synthetic retry of same failing call | Handler twice; zero evidence rows | Ordinary PASS exposes replay/accountability concern |
| Exception after inert handler mutation | Exact controlled handler exception, handler ran, no evidence | Ordinary PASS proves a non-SQLite unlogged-attempt path |
| Malformed ToolOutput returned by inert handler | Existing `OrchestrationError` after handler, no evidence | Ordinary PASS confirms output validation occurs after callback |
| Persisted-run parent check before failed insert | Valid `runs` parent and authorization reference exist, yet post-handler SQLite evidence insert aborts | Ordinary PASS isolates issue from #170 unknown-run FK anomaly |

The two extra post-handler fault witnesses and explicit registered-run provenance control do **not** grant a lab or target authority; they isolate the failure ordering from authorization policy rejection and missing-run foreign-key bugs. The intentionally expected-failing requirement must be converted to a **normal passing denial test** once the source owner introduces a durable pre-handler admission/reconciliation protocol. If source repair changes the exception to `ToolDenied` and avoids executing the handler, the expectedFailure will become an unexpectedSuccess until promoted. An exception **alone** never proves denial; the independent witness pins the actual SQLite failure, invocation count, and absent evidence.

## Owner-controlled source repair and stronger acceptance

- Owners of [executor #107](https://github.com/Zennay/Lightup/pull/107), [StateStore #167](https://github.com/Zennay/Lightup/pull/167) and related [FK #170](https://github.com/Zennay/Lightup/issues/170) must agree on a **durable pre-handler attempt record**, failure reconciliation, idempotency/retry contract, and what counts as auditable completion.
- Do not claim an external action can be undone using a SQLite transaction; a two-phase or persisted attempt/reconciliation model is needed if externally effective handlers can start. An unavailable ledger must never become implicit execution permission.
- Durable run identity, tenant/engagement, exact grant, risk/capability/tool, current revocation, trusted isolation and destination checks still belong to their separate source owners. No test in this branch grants authority or weakens those gates.
- Once owner-integrated, require permanent no-handler and no-evidence denial when pre-handler admission fails; verify exact run/attempt linkage, crash/retry replay, double-execution prevention, and negative failure reporting. Add real local producer integration that can confirm a persistently installed attempt record before any side-effect-capable callback.
- Require newest-main compatibility; exact immutable-head hosted Python 3.11/3.14 units and producer integration; **separate** fully registered `self-hosted,zcloud,vps` execution with auditable job logs; independent security/privacy and explicit human GO. Pending/queued does not count as green.

## Isolation / no authority

Only this previously absent test file and this document are owned; **zero edits** to `src/`, original tests, workflow YAML, runner, target, SQLite customer database, grant issuer or other worker PRs. No merge, deploy, target interaction, license to scan or customer notification is implied. Review and source fixes belong to the owner PRs.
