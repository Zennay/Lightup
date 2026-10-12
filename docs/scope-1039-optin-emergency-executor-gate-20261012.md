# LightUp #1039 — optional emergency STOP vs normal authorization (offline, 2026-10-12)

## Ownership and safety

**M3/M7 INCUBATE · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**
This independent follow-up to [open issue #1039](https://github.com/Zennay/Lightup/issues/1039)
does not edit its existing `chatgpt/scope-auth-emergency-override-deny-contract-20261008-0339`
reference branch, or production-owner [PR #100](https://github.com/Zennay/Lightup/pull/100)
and [PR #107](https://github.com/Zennay/Lightup/pull/107).

New **opt-in** `src/lightup/emergency_dispatch_optin.py` wrapper is intentionally
**not registered** in the web, default executor, queue, runtime, CLI or deployment.
The attached tests execute the *real* `ToolExecutor` and *real*
`ExecutionPolicy`, but use mock registry, mock evidence sink, synthetic
authorization data and 127.0.0.1 strings only. No DNS, HTTP, socket, scanner,
live asset, client data, legitimate grant, target interaction or active test.

## Verified property to seek

1. `stop_active=True` denies **before registry lookup**, regardless of
   normal authorization or `override_requested`.
2. Only exact built-in booleans are valid emergency inputs; truthy strings,
   integers, containers and `None` are denied without side effects.
3. The `override_requested` signal **never creates, extends, substitutes,
   mutates or bypasses** the normal `RunContext.authorization`.
4. Missing/expired/out-of-scope/wrong-capability grants, passive mode,
   insufficient approved risk and untrusted override argument payloads are
   denied by the unchanged normal policy, not by a synthetic permissive mock.
5. Positive control proves a real-policy permitted synthetic request reaches a
   mock handler and mock evidence sink with/without override; denial paths
   prove zero handler/evidence writes, and inputs remain unchanged.
6. Socket construction is forbidden in the offline test context.

Run in a test environment with repo dependencies available:

```sh
PYTHONPATH=src python -m unittest -v tests.test_scope_1039_emergency_executor_optin_20261012
```

## What this does **not** establish

- This is an **opt-in prototype** and is not a production emergency-stop
  mechanism. Direct calls to `ToolExecutor.execute` bypass this wrapper.
- Boolean inputs are **not authenticated operator intent**, authoritative STOP
  storage, revocation, independent two-party step-up or release approval.
- One pre-dispatch check is subject to a TOCTOU race. It **cannot** cancel a
  dispatched handler, stop queued/retried work, fence in-flight actions, or
  revalidate a persisted STOP immediately before each network I/O.
- A passed synthetic test does not prove multi-tenant authorization, trusted
  persisted issuer, audit durability, authenticated tenancy, runtime deployment,
  network isolation or effectiveness of live emergency operations.
- No claim of defensive coverage or safety of arbitrary tools is made.

## Owner acceptance before any promotion

Require original #100/#107 owners and independent security/privacy/tenant
review. A source-owner integration must bind a durable authenticated STOP and
independently approved emergency operation to tenant, engagement, asset,
capability, execution generation, effective time, issuer and operator,
revalidate at queue/retry/pre-I/O boundaries, and prove interruption/fencing
without broadening normal target authority. Establish positive and negative
post-revocation race acceptance using **synthetic isolated lab** assets,
zero effects after denial, cross-tenant tests, and original-code tests.

Separately require:
- safe current-main source composition without overwriting other workers;
- exact immutable branch SHA, passing GitHub-hosted Python 3.11/3.14 offline
  preflight, **registered permanent self-hosted VPS CI** on that exact SHA;
- independent reviews plus explicit human approval before merge, activation
  or any real-target interaction.

Keep issue #1039 OPEN and this PR DRAFT/HOLD until all above gates are met.
