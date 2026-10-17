# #646 — canonical grant scope identity (isolated source acceptance)

**State: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a narrowly scoped, non-authorizing acceptance pack above the existing authorization-domain owner PR #554, pinned at `4c8d5651fc0e23f94514daae56b4e5fe0549de37`. It makes **no changes** to `src/lightup/domain.py`, `engagements.py`, or any other production/source-owner code.

## Problem

`DomainStore.record_authorization_grant` validates `scope.max_risk` and later serializes it. It does not first require `type(scope) is ScopeDefinition`. A structurally compatible substitute or `ScopeDefinition` subclass can pass the first read and change the value at a later read; in a disposable SQLite test, this is independently observable. This is issuance-time risk/identity integrity, **not** a demonstrated live authorization bypass.

## Exact proposed owner invariant

At the issuance boundary, after operator authorization but **before reading any field on `scope`**, require the **exact** `ScopeDefinition` type. Reject `None`, duck-typed objects, and subclasses with `ValueError` or `TypeError` before persistence. Canonical exact `ScopeDefinition` input must preserve issuance behavior. The issuing transaction may not persist any grant for rejected input. Other checks for asset/risk/capability content remain the owner's domain; this pack does not relax them.

## Self-contained evidence

`tests/test_scope_grant_scope_identity_646_20261017.py` uses a disposable temporary SQLite database with fictional client, asset, capability and approval labels. The cases are:

- ordinary PASS: canonical scope persists STANDARD risk and exact assets/capabilities;
- ordinary PASS: two consecutive canonical grants persist correctly;
- ordinary PASS: client-scoped context cannot issue;
- intentionally unresolved **original source RED**: exact-shape duck object accepted incorrectly;
- intentionally unresolved **original source RED**: harmless ScopeDefinition subclass accepted incorrectly;
- intentionally unresolved **original source RED**: synthetic subclass changes observed max_risk from STANDARD at validation to DESTRUCTIVE_LAB_ONLY at persistence;
- intentionally unresolved **original source RED**: `None` triggers `AttributeError` instead of canonical input validation.
- intentionally unresolved **original source RED**: forged `__class__` metadata on a foreign object must not bypass an `isinstance`-only check.
- intentionally unresolved **original source RED**: foreign property trap must not be accessed even once before canonical type denial.

Run (against this branch using the repository's Python environment):

```sh
PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_scope_grant_scope_identity_646_20261017.py' -v
# Once original owner source is repaired, require ordinary PASS for all source cases:
LIGHTUP_SCOPE646_REQUIRE_SOURCE_FIX=1 PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_scope_grant_scope_identity_646_20261017.py' -v
```

An additional ordinary **disposable owner-guard oracle** temporarily wraps issuance in memory with `type(scope) is ScopeDefinition`, proves that five synthetic invalid forms are rejected without reading hostile fields or writing grants, and proves canonical issuance still persists. This oracle preserves operator-role denial precedence, validates rejection of malformed synthetic scopes before field access **or opening the temporary SQLite connection at all**, rejects seven additional primitive/collection impostors, and proves an already-persisted canonical grant row is untouched after repeated invalid attempts. An additional ordinary regression demonstrates that Python `isinstance()` can be fooled by an object’s forged `__class__` metadata, while `type(scope) is ScopeDefinition` cannot. The original production source file is never modified. This oracle demonstrates a viable check, not completed source-owner remediation.

Default successful tests with intentional `expectedFailure` do **not** constitute source remediation. Strict opt-in must become genuinely green with zero expected failures *after* owner repair.

## Ownership and release fence

Own additions: `tests/test_scope_grant_scope_identity_646_20261017.py`, this document, and an opt-in hosted CI workflow. No original production, sibling, CI release, runner setup, customer data or other-worker paths may be changed. No real asset, DNS lookup, network scanner, handler, authorization grant, deployment or release is permitted.

**HOLD** until the owner addresses original source REDs and the original full hosted + permanently registered named VPS matrix is green at an approved exact SHA, separately authenticated client/operator consent and at-use revocation have been verified, independent security/privacy review passes, and an explicit HUMAN GO is recorded. No test result grants any execution authority.

## Verified disposable original-source repair rehearsal (not committed)

On the connected permitted zSSH VPS, a wholly separate **temporary local Git checkout** of own acceptance branch at `173ababec44a1c8361b3b90aee858b221c14ec59` was created. Only in that throwaway filesystem copy, immediately after the original operator-role check, the following **two-line** hardening was applied to `src/lightup/domain.py`:

```python
if type(scope) is not ScopeDefinition:
    raise ValueError("grant scope must be exact ScopeDefinition")
```

This enforces the exact built-in type **before any untrusted scope attribute access**. Evidence in that disposable Python 3.14 checkout:

- Opt-in strict `LIGHTUP_SCOPE646_REQUIRE_SOURCE_FIX=1` suite: **11/11 ordinary PASS, zero expectedFailures**.
- Original complete unit suite with the same strict opt-in: **578 tests OK, zero expectedFailures**.
- Original integration suite with the same strict opt-in: **86 tests OK**.
- `git diff --name-status` of throwaway copy: only `M src/lightup/domain.py`. **No Git push, no source-owner branch or PR update, no deploy, no real grant/asset or network scan.**

This is **reproducible local patch validation**, not a delivered source fix, multi-version source-fixed CI, or production authorization. Source owner #554 alone should implement/review the source change with other pending domain work, revalidate all integration and permanent named VPS gates, and obtain the separate human consent and release approvals.
