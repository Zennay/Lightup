# Real SQLite pre-lookup evidence ID acceptance (2026-10-13)

Issue: [#1075](https://github.com/Zennay/Lightup/issues/1075)  
Parent: [DRAFT #1199](https://github.com/Zennay/Lightup/pull/1199), immutable head `c5e71925c5476172ab9a7f2d44e019db730aff7f`

## Scope and threat boundary

This child adds **only** `tests/test_evidence_1075_real_sqlite_prelookup_20261013.py` and this contract. It exercises the existing opt-in `canonical_evidence_id` using genuine disposable `StateStore` SQLite data. The test-only `checked_lookup` calls lexical admission **before** delegating to `get_evidence`. It is **not installed** in the application. Production `StateStore.get_evidence`, authorizing/session/tenant code, worker source, main, web routes and real targets remain unchanged.

Five regression methods cover:

1. Canonically issued RFC 4122 UUID4 evidence persists through real SQLite reopening without altering ID, run, SHA-256 or metadata.
2. Wrong types including boolean, `str` subclass, aliases, controls, confusable dashes, wrong version/variant and malformed widths are rejected before **any** delegate reader call. Durable rows remain byte-for-byte unchanged.
3. An unknown but lexically canonical UUID4 still produces `KeyError` from the real reader, without creating evidence. Syntax cannot establish existence or authority.
4. A manually seeded **synthetic historical noncanonical ID** remains retrievable by the unchanged legacy reader; the opt-in gate refuses it without silently rewriting/migrating durable state. This explicitly documents the compatibility concern, not a production repair.
5. Distinct valid generated IDs remain distinct and preserve lookup order in SQLite.

## Reproduce and proof requirements

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_real_sqlite_prelookup_20261013
```

This new branch needs exact-commit GitHub-hosted Python 3.11/3.14 regression results, **separate** permanent registered `vps-bb300bba` runner CI, independent source-owner and privacy/security review, historical-ID inventory/compatibility decision, latest-main integration, and explicit human release approval. A passing isolated test suite is never a production admission or tenant-authorization proof.

No client/target requests, scanning, evidence collection from systems, remediation, retest, code/config execution, authorization grant, product merge or deployment. **Incubate M3/M7 — PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY.**
