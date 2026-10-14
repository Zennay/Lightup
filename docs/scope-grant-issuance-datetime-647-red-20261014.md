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
