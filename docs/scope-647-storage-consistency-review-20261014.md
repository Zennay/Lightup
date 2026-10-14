# #647 — Offline persisted grant-window consistency audit (mainline)

## Scope and motivation

LightUp is **INCUBATE M3/M7, PLAN/LAB ONLY**. Real customer authorization,
tenant ownership, scope, revocation, approval provenance and active execution
remain controlled by original production owners. This source-only feature
adds **no grant issuance**, no runtime `DomainStore` hooks, no web API or
active target adapters.

Production bug [#647](https://github.com/Zennay/Lightup/issues/647) is that
an attacker-controlled `datetime` subclass can render a wider
`isoformat()` string than the validity window originally approved.
The legitimate install-time remediation is owned by original
[#554](https://github.com/Zennay/Lightup/pull/554), with still-unfixed
six original-source expected-RED acceptances in child
[#1324](https://github.com/Zennay/Lightup/pull/1324).

## Actual implemented feature

`src/lightup/grant_window_storage_consistency_647.py` adds
`review_grant_window_storage_consistency(approved_window,
stored_valid_from=..., stored_valid_until=...)`.

Inputs:

1. An exact built-in `CanonicalIssueWindow` obtained through the already
   merged non-authorizing `snapshot_grant_issuance_window` (or otherwise
   supplied by the caller), containing **exact built-in UTC datetimes**.
   Crucially, the auditor **cannot attest** whether this window truly comes
   from a trusted, independently recorded customer approval. Callers must
   authenticate/bind provenance themselves.
2. Two raw timestamp text fields from a presumed persisted grant row. Both
   must be exact built-in `str`, bounded, ASCII, and the exact
   `datetime.isoformat()` UTC +00:00 representation. Arbitrary string
   subclasses, alternate timezone offsets, lenient parser-normalized
   spellings and malformed dates are rejected.

The entire stored start and expiry must **exactly equal** the reference,
at microsecond precision. A start date moved backward, expiry widened,
moved forward, or shortened range is reported `HOLD`.
A canonical exact match returns only `REVIEW_ONLY`, never ALLOW.

Receipts contain only a short fixed reason code, `HOLD/REVIEW_ONLY`, and
**four hard-false** `authorization_verified`, `grant_issued`,
`execution_enabled`, `release_approved` flags, with no private timestamps,
tenant, grant IDs, hostnames or customer data.

## Actually tested

`tests/test_scope_647_storage_consistency_review.py` runs ordinary
pure unit validation and genuine **disposable SQLite** integration tests
using fictional clients/engagements in a `TemporaryDirectory`. It checks
correct storage, widened start/end, corrupted rows, immutable read-only
behavior, timestamp-type confusion, spoofed `str` and `datetime` subclasses,
UTC strictness, precision, privacy and zero network I/O. There are no
real targets, actual customer approvals or production persistence.

```bash
python -m unittest discover -s tests -p 'test_scope_647_storage_consistency_review.py' -v
```

A matching stored text record still does **not** prove consent, current
revocation, risk level, engagement status, tenant lineage, asset, capability
or any right to execute. The reviewer does not fetch or authenticate the
reference snapshot: it is simply an *offline developer audit helper*.

## Separation from concurrent workers and acceptance gates

This branch adds only owned new paths in `src/`, `tests/`, `docs/`.
It does not edit existing `DomainStore`, `AuthorizationGrant`,
`ExecutionPolicy`, `ToolExecutor`, WSGI, CI, runner, deployment, or
other workers' scope PRs (#100/#107/#554/#1318/#1321).

This does **not** fix issue #647. Source-owner #554 must ensure the real
issuance path rejects noncanonical datetime objects **before** any virtual
comparison/serialization, trusted approvals are bound to immutable
authorization state, and six original-source RED acceptances in #1324 become
ordinary PASS. Real rollout still requires independent security/privacy
review, valid customer authorization, source integration/tenant/revocation
checks and appropriate runner/release evidence.

**Develop-main code merge is not live deployment or scan permission.**

## Bounded fictional-only command-line audit (same review, no I/O)

`scripts/audit_fictional_grant_storage_647_offline.py` now exposes the
read-only audit to a local terminal, without introducing a real DB connector
or accepting customer IDs, file paths, target hosts, actual consent records,
signatures, or any authorization. Only four strict UTC builtin
`datetime.isoformat()` text arguments are accepted:

```bash
python scripts/audit_fictional_grant_storage_647_offline.py \
    --expected-start-utc 2026-10-14T12:00:00+00:00 \
    --expected-until-utc 2026-10-14T12:15:00+00:00 \
    --stored-start-utc 2026-10-14T12:00:00+00:00 \
    --stored-until-utc 2026-10-14T12:15:00+00:00
```

The local input fixture is **not** trusted permission; the CLI cannot verify
who selected the expected timestamps or whether those dates correspond to any
real record. It returns **one privacy-minimal JSON line** (no echoed timestamps
or exceptions), and deliberately **never exits successfully**:

- Exit **2 / HOLD** for invalid/inconsistent input, widened/narrowed storage.
- Exit **3 / REVIEW_ONLY** for syntactically canonical equality; *not a permit*.
- Exit zero is **never possible**, including on a matching fixture, so
  `audit && run_scan` cannot accidentally authorize a scan.

`tests/test_scope_647_storage_consistency_cli.py` asserts strict flag
admission, mismatches, microsecond precision, no network/DB, privacy, error
sanitization and all-nonzero exits. This is an optional offline diagnostic
for synthetic-only test workflows; no tool uses it in production.

```bash
python -m unittest discover -s tests -p 'test_scope_647_storage_consistency_cli.py' -v
```
