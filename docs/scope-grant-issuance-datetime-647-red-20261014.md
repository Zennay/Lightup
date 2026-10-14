# LightUp #647 — direct grant issuance datetime identity (RED acceptance)

## Source ownership and isolated base

[Issue #647](https://github.com/Zennay/Lightup/issues/647): a `datetime` subclass can compare as a narrow validity window during `DomainStore.record_authorization_grant()` and override `isoformat()` to persist a much broader period. The on-disk values are later interpreted as canonical timestamps by the live-grant resolver.

This pack is based on original [source owner PR #554](https://github.com/Zennay/Lightup/pull/554) immutable HEAD `4c8d5651fc0e23f94514daae56b4e5fe0549de37`, in a **separate child branch and draft PR**. It never edits the #554 branch itself, `src/lightup/domain.py`, policy, orchestration, target workers, workflows or runners. No target/network/sockets, real operator accounts, customer databases or authorization.

## Actual test coverage

- New disposable `tempfile` SQLite store for **each** test; fictional client, engagement, capability, scope and approval.
- A normal exact built-in UTC `datetime` issuance persists unchanged `valid_from` and `valid_until` values.
- Naive expiry and inverted validity bounds are refused without creating a grant row.
- Two explicitly expected RED issuance tests require both subclassed bound variants to be refused *before persistence*.
- Two further RED tests inspect the **real SQLite row** and assert that expiry/start values were not silently widened by malicious `isoformat()`.
- An ordinary test re-runs the four RED canaries under private unittest results, rejecting masked nonassertion exceptions or unexpected successes.

These are four open security acceptance failures. `expectedFailure` is not a repaired source path, trusted consent, a successful production safety gate or permission to execute a scan.

## Source-owner repair

1. In the exact `record_authorization_grant` production path, validate **`type(valid_from) is datetime`** and **`type(valid_until) is datetime`** before any object-supplied method, comparison, `isoformat()`, DB insertion or handler effect.
2. Enforce timezone-aware UTC-comparable inputs and strict `valid_until > valid_from`; retain canonical normal behavior and no-row-on-refusal.
3. After applying source repair, remove all four `@unittest.expectedFailure` annotations and demand ordinary green tests; keep the SQLite assertions to guarantee the stored window cannot be wider than approved.
4. Reconcile original owner #554 with #100/other live grant PRs, verify exact-head GitHub-hosted Python3.11/3.14 and registered permanent VPS evidence, and obtain independent security/privacy review before any activation.

Offline command (on this exact source-owner child branch):

```bash
python -m unittest discover -s tests -p 'test_scope_grant_issuance_datetime_647_red*.py' -v
```

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** No real assessment, deployment or scope grant is authorized by these checks.

## W2 — working uninstalled issuance window snapshot (source owner unaffected)

The new `src/lightup/grant_issuance_window_snapshot_647.py` contains the
**actual usable, strictly pure** `snapshot_grant_issuance_window(start, end)`.
It returns `CanonicalIssueWindow(starts_at_utc, expires_at_utc)` or raises
a sanitized `WindowRejected` before invoking any untrusted datetime
subclass serializer/comparison, `tzinfo` hook, SQLite writer or handler.
It accepts only the exact builtin timezone-aware `datetime` type and
exact builtin fixed-offset `datetime.timezone` class on **both** fields,
normalizes safe instances to exact builtin UTC datetime values, and
conservatively refuses invalid/empty/reversed windows and date overflow.
No implicit now, consent, customer lookup, grant issuance, or active target
exists in the new module.

The test-owned **disposable SQLite** integration in
`tests/test_scope_grant_issuance_window_snapshot_647.py` actually calls
`DomainStore.record_authorization_grant` only after successful opt-in
snapshot. It verifies normalized UTC values are what get persisted, and
that polymorphic or invalid data is rejected BEFORE a real synthetic
`authorization_grants` row can be created. This is a lab assertion in an
ephemeral database, not a production write or a real authorization.

Example, strictly fictional:

```python
from datetime import datetime, timedelta, timezone
from lightup.grant_issuance_window_snapshot_647 import snapshot_grant_issuance_window

now = datetime(2026, 10, 14, 12, tzinfo=timezone.utc)
window = snapshot_grant_issuance_window(now, now + timedelta(minutes=10))
assert type(window.starts_at_utc) is datetime
assert window.expires_at_utc.tzinfo is timezone.utc
```

**Important:** this helper is **not installed or wired** into the existing
`DomainStore.record_authorization_grant` production source owned by PR #554.
It cannot fix already-persisted forged grant data, replace live revocation,
validate tenant/client/capability/asset/approval, or issue a scan permit. The
four expected-RED production-source tests remain genuinely unfixed until
the owner adopts type validation at the real issuance boundary, normalizes
the persisted values, and changes the REDs to ordinary green tests.

```bash
python -m unittest discover -s tests -p 'test_scope_grant_issuance_window_snapshot_647.py' -v
```

### Required source-owner integration

Original #554 owner must call exact builtin checks on *every* production
issuance path before any object-provided `isoformat` or database insertion;
choosing to use this snapshot helper is a possible implementation detail,
not implied authorization for this worker to edit owner files. Verify
signed/tenant-bound consent and revocation separately. Run exact-head hosted
Python3.11+3.14 plus real producer integrations and registered permanent
VPS evidence before independent security/release review.

## W3 — original real durable execution resolver after spoofed issuance

The same owned real-SQLite regression module now adds **two further genuine
expected-RED security tests** using the actual
`DomainStore.resolve_authorization_for_execution(grant)` on original #554
source, after a synthetic `datetime.isoformat` override persisted a start
or expiry one year wider than approved in-memory.

- An exact fixed UTC `utcnow()` fixture is patched **within the local
  in-process test only**, to inspect a future instant after the intended
  expiry or a past instant before intended start. The resolver can accept
  the widened persisted grant on those otherwise unauthorized instants.
  The required security assertion (resolver must return `None`) remains
  **expected RED** on unmodified original source.
- Two ordinary control tests demonstrate a normally issued canonical grant
  returns `None` at those outside-window instants.
- The separate assertion-witness integrity runner now exercises all
  **six** expected-RED genuine source canaries. It refuses swallowed
  `TypeError`, `ValueError`, SQLite exceptions or XPASS.
- No actual `ToolExecutor`, capability dispatch, target, DNS, network,
  real customer grant or production database is touched.

These tests prove the durable issuance type bug has a real *authorization
resolver consequence* in a disposable fixture, not just a differing SQLite
string. The installed source **is not repaired**: original owner #554 must
reject polymorphic issuance values before serialization and require
every formerly RED test to become ordinary PASS after proper composition.

Any green hosted run must be checked at the exact latest head **after**
these new tests, alongside original producer integrations and the distinct
permanent VPS jobs. Earlier hosted success was on superseded SHAs and is
not final-head evidence.
