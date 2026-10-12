# Scope #890: exact-time evaluation before live-grant selection (opt-in)

## Scope and ownership
LightUp remains **Incubate M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD-NO MERGE-NO DEPLOY**. This independent add-only branch addresses open [#890](https://github.com/Zennay/Lightup/issues/890), pinned directly to unchanged `main` `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`. Original persisted grant and `DomainStore` ownership remains with [#107](https://github.com/Zennay/Lightup/pull/107), direct `AuthorizationGrant.is_current()` input semantics with #734/#735, and other parallel scope owners remain untouched.

## Implemented, uninstalled
- `src/lightup/current_grant_instant_optin.py`: OPTIONAL, **not installed in default domain, policy, web, runner, executor or queue**, `checked_current_grant_at()`. It accepts a literal `None` as omitted time (creates an exact UTC-aware built-in datetime), or a literally exact built-in, timezone-aware datetime. Rejects all other values before invoking the store. It delegates to the original persisted current-grant selector but **does not authorize, create, extend or activate a grant**.
- `tests/test_scope_890_optin_grant_instant_20261012.py`: **14** real in-process unittest methods over disposable tenant-scoped SQLite and mock pre-store denials. Three deliberate `@expectedFailure` canaries prove current default `get_current_grant(now=False/0/"")` incorrectly treats invalid explicit arguments as omission. Remaining positive controls prove opt-in rejection before store, exact UTC/offset-aware selection, before/after validity returning None, immutable invalid reads and foreign-tenant isolation.
- Original current grant source, `main` and all other worker branches are left unchanged; no live clients, network, targets, scans, consent issuance, grants in production or action dispatch.

## Explicit security and release nonclaims
An *optional*, unmounted reference cannot fix the producer's `now = now or utcnow()` or real dispatch or tenant lease races. The three XFAIL cases are **unresolved production weaknesses**, not passing authorization controls. This reference is not a trust policy, only input acceptance shape.

Source owner must change current default selector to use **`if now is None`**, validate exact aware datetime on any supplied value, preserve existing tenant and grant revocation semantics, turn expected RED into ordinary green, and exercise real domain/WSGI/tool-executor admission plus owner-reviewed scope binding. Require immutable exact-head GitHub-hosted 3.11 + 3.14 evidence, **separately registered permanent self-hosted VPS CI**, independent security/privacy/tenant review, safe latest-main integration and explicit human release. Keep #890 OPEN and PR DRAFT/HOLD.

Local synthetic replay:
```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_890_optin_grant_instant_20261012.py' -v
```


## W2 — explicit no-grant/expired/future timestamp denial and durable-window boundaries

New isolated `tests/test_scope_890_grant_window_snapshot_20261012.py` adds **18** real temporary SQLite / opt-in adapter unittest methods, **five deliberate expected RED** proving current *unmodified* producer `get_current_grant` reinterprets explicit invalid falsy `now` values even if there is no grant, an expired grant or future grant. W1's three original expected RED tests remain unresolved.

Green controls cover exact current grant window start/end inclusive and microsecond outside denied, non-UTC timezone preserving the same instant, invalid/malicious `datetime` subclass and timezone invalidity refused before store access, malformed user time no persisted row changes, mock delegation on exact accepted time, different engagement and cross-tenant denial. No network, user grants, target interaction, side effects or production code were changed.

This extra acceptance *does not* make the optional reference an installed trust boundary or prove producer validity. The `now = now or utcnow()` source issue #890 remains open until #107's owner fixes the real method and all eight expected REDs become ordinary passing denial tests. Independent latest-main/tenant/privacy/security review and exact hosted + permanent VPS CI and explicit human release still required.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_890_*20261012.py' -v
```


## W3 — controlled hostile timezone faults before persisted grant selector

The optional uninstalled `checked_current_grant_at` now normalizes `datetime.utcoffset()` exceptions to a **controlled generic ValueError before any store access**, rather than exposing caller-controlled tzinfo internals as uncontrolled exceptions. It still preserves exact-builtin datetime identity, a sole `None` omission sentinel, aware fixed/non-UTC offsets, and unmodified accepted instant delegation; it does not fix the default persisted `DomainStore`.

`tests/test_scope_890_adversarial_timezone_20261012.py` adds **10 further** tests: caller-defined `tzinfo.utcoffset` raising RuntimeError/KeyError/TypeError/OverflowError, null offsets, no error-string leakage, acceptable builtin and custom aware offsets, naive rejection and genuine disposable SQLite grant-row immutability after all denials. No executor, target, API, network, grant issuance, merge or deployment.

W1 and W2's total **eight expected source-owner RED** canaries remain intentionally unresolved. The W3 reference exception hardening is uninstalled; safe release still requires production owner #107's true selector fix, RED→GREEN, latest-main/tenant/security/privacy review, exact hosted 3.11+3.14 CI and separately registered permanent VPS proof with explicit human approval.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_890_*20261012.py' -v
```
