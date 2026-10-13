# Real SQLite pre-lookup evidence ID acceptance (2026-10-13)

Issue: [#1075](https://github.com/Zennay/Lightup/issues/1075)  
Parent: [DRAFT #1199](https://github.com/Zennay/Lightup/pull/1199), immutable head `c5e71925c5476172ab9a7f2d44e019db730aff7f`

## Scope and threat boundary

The first pass added `tests/test_evidence_1075_real_sqlite_prelookup_20261013.py` and this contract; a separate second-pass add-only producer canary module is documented below. It exercises the existing opt-in `canonical_evidence_id` using genuine disposable `StateStore` SQLite data. The test-only `checked_lookup` calls lexical admission **before** delegating to `get_evidence`. It is **not installed** in the application. Production `StateStore.get_evidence`, authorizing/session/tenant code, worker source, main, web routes and real targets remain unchanged.

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


## Independent installed-reader RED canaries (second pass)

A **third add-only path**, `tests/test_evidence_1075_installed_reader_red_20261013.py`, tests the unchanged production `StateStore.get_evidence` against genuine disposable SQLite fixtures. It includes 2 normal positive/unknown-ID controls and **4 explicit expected-RED cases** demonstrating that the default source still permits historical noncanonical record IDs, uppercase UUID4 stored aliases and `str` subclass selectors, and raises incidental exceptions rather than the intended pre-database ValueError for type-confused input. RED is deliberately marked `@unittest.expectedFailure` so it remains visible without accidentally treating a failing security gate as a release blocker on an unmodified producer.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_installed_reader_red_20261013
```

The previously verified hosted 573-unit/86-integration receipt applies **only to the earlier exact HEAD** `2b2da1707b7341d40c794199fcced33943946ff0`. Revalidation on this new head is required; do not reuse that receipt. The original source owner must integrate a canonical prelookup gate, inventory real historical identifiers, convert the 4 RED canaries to ordinary passing tests, and obtain explicit release approval. Tests-only addition does not claim authorization, historical record migration or production enforcement.
