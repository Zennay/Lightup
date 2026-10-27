# Scope #647 — canonical UTC issuance snapshot (development mainline)

This package contains a usable, **opt-in pure function**, extracted without
taking ownership of the original durable-authorization implementation.

## Exactly what is included

- `src/lightup/grant_issuance_window_snapshot_647.py` — strict exact
  built-in `datetime` and fixed-offset `timezone` admission, rejecting
  subclasses and custom timezone objects **before** their polymorphic
  methods can run. Valid dates are converted to canonical builtin UTC values;
  zero-duration, inverted and overflowing windows are denied.
- `tests/test_scope_647_mainline_utc_snapshot.py` — independent offline
  Python standard-library checks for malformed inputs, subclasses, no
  target/network/database I/O, timezone offsets and exact serialization.

This module has **no imports of or registration with** `DomainStore`,
`ToolExecutor`, `ExecutionPolicy`, `ActivationGate` or any active target
worker. The result is only a pair of timestamps. It does not grant customer
consent, confer a scan permit, check revocation, or write a database.

## Why this is a separate mainline PR

The earlier [#1324](https://github.com/Zennay/Lightup/pull/1324) is a
child PR of the source-owned [#554](https://github.com/Zennay/Lightup/pull/554)
durable authorization implementation. It contains **additional** genuine
disposable-SQLite tests for original `DomainStore` issuance and resolver
regressions; those tests require source not yet on `main`.

This new branch copies the **identical source file** from the author's #1324
into current development `main` with a separate suite that runs on current
`main`. It does **not** merge/modify/retarget #554 or #1324, nor duplicate
their tests, and does not enable any active execution. When the source owner
integrates the original backend, the same source snapshot file should not
need a second implementation.

## Example — synthetic, no authorization

```python
from datetime import datetime, timedelta, timezone
from lightup.grant_issuance_window_snapshot_647 import (
    snapshot_grant_issuance_window,
)

now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
window = snapshot_grant_issuance_window(now, now + timedelta(minutes=5))
assert type(window.starts_at_utc) is datetime
assert window.expires_at_utc.isoformat() == "2026-10-14T12:05:00+00:00"
```

Run ordinary tests:

```sh
python -m unittest discover -s tests -p 'test_scope_647_mainline_utc_snapshot.py' -v
```

The real issue #647 remains OPEN. The actual runtime source owner must enforce
canonical type admission in the installed issuance path and prove that
stored authorizations cannot widen. Specifically, the **six genuine expected
RED** issue-#647 acceptance canaries in child PR #1324 must become ordinary
PASS after repair. Trusted customer ownership, tenant, live revocation,
capability, asset and risk enforcement remain independent release requirements.

**Incubate / PLAN-LAB ONLY.** Source merge is not deployment, authorization,
or permission to assess any real-world system.

## W2 — genuine mainline disposable SQLite acceptance

After integrating the pure UTC snapshot via [PR #1325](https://github.com/Zennay/Lightup/pull/1325),
the **new** `tests/test_scope_647_mainline_sqlite_snapshot_integration.py`
executes real `DomainStore.record_authorization_grant` calls in a private
`TemporaryDirectory` fixture after, and only after, successful
`snapshot_grant_issuance_window` admission. It is **not** a production
source modification or real customer authorization.

The tests verify that a canonical UTC or non-UTC fixed-offset input stores
exactly the same safe UTC instant, including true raw SQLite `valid_from`
and `valid_until` columns. Invalid or spoofed subclass fields are rejected
before the original mutable/polymorphic source can invoke their `isoformat`
hooks; no grant record is created. An existing valid fictional record
survives a later invalid issuance attempt unchanged.

A patched socket boundary asserts this never performs DNS/target/network
I/O. All clients and grants are purely fictional under test-only SQLite.
`FICTIONAL-NOT-CONSENT` is not a customer approval reference.

```sh
python -m unittest discover -s tests -p 'test_scope_647_mainline_sqlite_snapshot_integration.py' -v
```

### Remaining *real* enforcement gap

The function remains **opt-in**. The installed production
`DomainStore.record_authorization_grant` still accepts its original raw
datetime inputs unless its caller deliberately invokes the new snapshot.
The original durable authorization source owner #554 is responsible for
failing closed at the actual runtime issuance boundary and validating
stored grant lineage/consent/revocation. The six source RED regressions in
its owner-dependent child PR #1324 remain unresolved until the real code
is repaired and all six are converted to ordinary PASS.

**Mainline unit/integration PASS is not permission to scan, issue real
authorization, deploy or call the feature production-safe.**
