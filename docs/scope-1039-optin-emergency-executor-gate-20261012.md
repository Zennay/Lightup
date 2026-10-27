# LightUp #1039 — optional emergency STOP vs normal authorization (offline, 2026-10-12)

## Ownership and safety

**M3/M7 INCUBATE · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY.**
Independent follow-up to [open issue #1039](https://github.com/Zennay/Lightup/issues/1039).
Original emergency reference branch is not touched, nor are production-owner
[PR #100](https://github.com/Zennay/Lightup/pull/100) and
[PR #107](https://github.com/Zennay/Lightup/pull/107).

The **opt-in** `src/lightup/emergency_dispatch_optin.py` is intentionally
**not registered** in the web, default executor, queues, runtime, CLI or
deployment. Tests invoke actual `ToolExecutor` and `ExecutionPolicy` with
inert in-memory mock handlers and no sockets, DNS, HTTP, scans or clients.

## W1 acceptance — real policy + mocked evidence

`tests/test_scope_1039_emergency_executor_optin_20261012.py` includes 14
synthetic real-policy/executor methods: a positive mock control; stop before
registry access; invalid exact-bool flags fail closed without truth coercion;
overrides cannot mint grants, widen capabilities/assets/risks, resurrect expired
grant, activate passive mode or smuggle a model argument; zero denied handler
and evidence effects; unchanged caller objects. STOP does not grant authority.

## W2 acceptance — STOP precedence + disposable real SQLite

`src/lightup/emergency_dispatch_optin.py` now checks the **exact built-in**
STOP bool first and, if true, denies **before checking override shape or
touching executor/registry**. It checks override type only when STOP is false.
Malformed STOP always denies; a true STOP with a malformed override has
the explicit STOP reason, not an ambiguous malformed-override reason.

`tests/test_scope_1039_sqlite_emergency_denial_w2_20261012.py` adds 13
independent offline methods using real `ToolRegistry`, real `StateStore`
on a disposable SQLite database, real `ExecutionPolicy`/`ToolExecutor`,
actual `runs`/`evidence` queries and a mock handler. No socket is allowed.
Positive control persists exactly one **synthetic** record with checked SHA-256
and client metadata. STOP, malformed inputs, absent/expired grant,
out-of-scope asset, wrong capability, passive mode and risk ceilings
must cause zero handler calls, zero evidence writes and unchanged run count.

Two of the 13 methods are **intentional expected-RED** characterization
canaries for current-main cross-client and cross-engagement mismatches.
Unchanged main `ExecutionRequest` lacks client/engagement lineage, so an
unrelated tenant's / engagement's context may be admitted by the legacy
policy. These are **not passing authorization controls**; unittest
`expectedFailure` must remain explicit until #100/#107 production owners
repair and verify the behavior. Source owners must convert them to ordinary
passing denial tests against actual installed gate after repair. An
`unexpected success` on a changed baseline requires review, not blind
promotion.

Run in the repository's test environment:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1039*' -v
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src:tests python -m unittest discover -s tests/integration -v
```

## What this does **not** establish

- This is an **uninstalled opt-in prototype**. Default
  `ToolExecutor.execute` **bypasses the wrapper**.
- A caller-supplied bool is not authenticated operator STOP or approval.
- A single pre-dispatch check cannot protect against concurrent revocation,
  post-admission/queued retries, active handler I/O, in-flight cancellation or
  stale/persisted STOP state. There is **no** atomic, durable generation fence.
- A local SQLite positive control is synthetic, **not** an authorized client
  assessment. No actual cross-tenant denial has been fixed in production.
- Hosted diagnostics alone are not permanent VPS acceptance or proof of
  authenticated consent, tenant isolation, real ingress or pre-I/O fencing.

## Mandatory owner promotion gate

Source owners #100/#107 must install an independently authenticated persisted
STOP bound to operator, tenant, engagement, approved scope, capability,
execution generation and time, plus pre-I/O validation and queue/retry fences;
independent security/privacy reviews must confirm no scope widening and
correct tenant binding. Convert expected-RED identity tests to ordinary
passing tests **only after** the production fix passes on its exact SHA.
Require safe latest-main composition, exact-head hosted Python 3.11/3.14
preflight and separately registered **permanent VPS CI**, and explicit human
release authority. No merge/deploy/real-target interaction without all gates.

Keep #1039 OPEN, this PR DRAFT/HOLD. Do not treat synthetic expected failures
or hosted-green jobs as production authorization proof.
