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
