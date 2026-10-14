# LightUp #647 — original issuance RED canaries on development main

## Why

The original persistent authorization source owner [#554](https://github.com/Zennay/Lightup/pull/554)
and its child [#1324](https://github.com/Zennay/Lightup/pull/1324) contain
important regressions, but that child PR is deliberately based on the
original source owner's branch (not main) to preserve parallel ownership.
Development main meanwhile includes only *opt-in* safe UTC snapshot and
storage audit functions. A developer running its green hosted CI must NOT
mistake the original runtime issuer for already repaired code.

This PR brings **four minimal but genuine failing authorization requirements**
to current main, without modifying `src/lightup/domain.py` or any other
owner-controlled production path.

## What actually runs

`tests/test_scope_647_mainline_original_issuance_red.py` uses the original
installed `DomainStore.record_authorization_grant` in **disposable fictional
SQLite**. It constructs synthetic `datetime` subclasses that retain their
legitimate approved in-memory times, but override `isoformat()` to emit a
timestamp one year further out or one year further back.

Four `@unittest.expectedFailure` source-contract tests demand:

1. Original issuer rejects a subclassed expiry **before** creating a grant.
2. Original issuer rejects a subclassed start **before** creating a grant.
3. Raw persisted expiry must equal the originally supplied approved instant.
4. Raw persisted start must equal the originally supplied approved instant.

All four remain deliberately **RED on current main**; their `expectedFailure`
decorators do NOT mean authorization enforcement is secure. The original
`DomainStore` source remains vulnerable and source-owner #554 must repair it.

Additional **ordinary PASS** controls demonstrate canonical builtin UTC
storage, explicitly-applied safe snapshot handling and no socket/network use.
The independent ordinary `OriginalMainlineRedWitnessIntegrityTests` reruns
all four expected REDs under private `unittest.TestResult` and ensures
they are genuine assertion failures, not swallowed runtime errors or XPASS.

```bash
python -m unittest discover -s tests -p 'test_scope_647_mainline_original_issuance_red.py' -v
```

## Owner handoff and exit criterion

The owner must enforce exact builtin timezone-aware datetimes in the **actual**
production `DomainStore.record_authorization_grant` path, before any object
provided `isoformat()`, `__le__` or `tzinfo` hook is invoked. After the
fix, remove `@unittest.expectedFailure` from **each** RED, require ordinary
PASS and independently verify no database row on rejection, plus real
tenant/scope/revocation/provenance checks. The six additional REDs in child
PR #1324 (including genuine persisted resolver consequences) must also become
ordinary PASS after its owner integration.

The tests do not issue real customer authorization, resolve any host or scan.
They operate only in temporary test SQLite, cannot be treated as a release
gate success while four security expected-RED remain, and do not alter other
workers' branches. Hosted Python3.11 and Python3.14 tests and genuine
permanent self-hosted runner evidence must be recorded independently.

**INCUBATE M3/M7 · PLAN/LAB ONLY · NO REAL ASSET, PERMIT, SCAN OR DEPLOY**.
