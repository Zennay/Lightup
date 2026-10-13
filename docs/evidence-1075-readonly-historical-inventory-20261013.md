# Evidence-ID historical compatibility inventory — 2026-10-13

**Issue:** [#1075](https://github.com/Zennay/Lightup/issues/1075)  
**Parent:** [DRAFT #1265](https://github.com/Zennay/Lightup/pull/1265), pinned exact HEAD `4b5fe442bac71f9a89dce066bb7e2ed7a065e5ab`.  
**Stage:** LightUp Incubate M3/M7, strictly PLAN/LAB ONLY.

## Why this exists

The existing `StateStore.add_evidence()` emits canonical lowercase hyphenated UUID4, while the unchanged `get_evidence()` may read historical noncanonical values. The issue requires compatibility inventory **before** the source owner activates canonical prelookup refusal. This child supplies a diagnostic, not a migration or authorization change.

## Isolated implementation

- **New optional source:** `src/lightup/evidence_id_inventory_optin.py`. Takes an explicitly selected existing local SQLite file, opens `mode=ro`, sets `PRAGMA query_only=ON`, and uses the original #1199 pure lexical validator to count shapes.
- **Privacy-minimized aggregate:** `EvidenceIdInventory(total, canonical_uuid4, noncanonical_text, nontext_or_null)`. Never returns, logs, serializes or stores original identifiers, tenant names, findings, targets or remediation text.
- SQL restricts Python-facing identifier materialization to SQLite TEXT of **exactly 36 characters**; everything else is counted without returning the stored value. Iterates in **128-row fetch batches** with an exact integer, default **100000-row** diagnostic budget, failing instead of returning incomplete statistics. This does not prove a native SQLite/RSS/CPU bound.
- **No correction or coercion:** uppercased/compact/legacy/confusable IDs remain in their original category; NULL/BLOB count as unexpected SQLite storage. No writing, migration, grant, context or target interaction.
- **12 disposable real-SQLite unit tests:** empty and canonical snapshots, reopen, historic alias buckets, invalid version/variant, Unicode lookalikes, BLOB/NULL, large legacy TEXT, unchanged durable rows, exact-limit acceptance/denial, nonexistent database no-creation, invalid schema generic refusal, URI punctuation, and private immutable aggregate.

## Reproduce

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_readonly_inventory_20261013
```

## Limits and release gates

This is **not automatically run against any user or customer database**. The helper is uninstalled and does not inspect production, does not determine tenant ownership, evidence authenticity, authorization, or historical business migration policy. The original `StateStore` is **unchanged and unfixed**; four installed-reader tests in parent PR #1265 intentionally remain expected RED.

Original StateStore/source, privacy/security and tenant owners must approve the **site-specific historical-identifier inventory plan**, decide on migrations and accepted formats, integrate any strict production prelookup before database access, convert all intentional RED to plain PASS, verify latest-main compatibility and **exact-head GitHub-hosted Python 3.11/3.14 and separate permanent registered VPS CI**, and explicitly approve release. Never infer that a syntactically canonical ID is owned/authorized.

**DRAFT/HOLD/NO MERGE/NO DEPLOY** until all review gates. No live clients, targets, scans, evidence collection, remediation, retest, grants, or production database interaction.

## Schema identity preflight — independent follow-up (2026-10-13)

Before returning any aggregate, the diagnostic now refuses a missing/forged `evidence` object: SQLite `sqlite_schema` must report one ordinary **table**, not a view or virtual table; `PRAGMA table_info` must include original StateStore evidence columns and exactly **TEXT PRIMARY KEY** for `evidence_id`. Additive ordinary columns are allowed, so known schema extensions can remain reviewable. All validation executes through the same explicitly chosen **read-only** SQLite connection before selecting evidence rows. Wrong/incomplete schemas fail with a generic `ValueError`; no table names, paths or stored content are exposed in that error. This is a shape gate only, not evidence authenticity, tenancy, authorization or arbitrary untrusted-database execution safety proof.

Additional **8 real disposable SQLite tests** in `tests/test_evidence_1075_inventory_schema_identity_20261013.py` cover genuine StateStore schema, additive extension, missing table, a fake view over a synthetic secret, missing ID primary key, wrong BLOB primary-key affinity, missing required metadata and a single-column lookalike. They assert refusal without mutating SQLite database bytes. Total new inventory tests are **20** (12 initial, 8 schema identity).

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_1075_readonly_inventory_20261013 tests.test_evidence_1075_inventory_schema_identity_20261013
```

The earlier 4/4 hosted green receipt applies **only to the superseded HEAD** `932f44db98ac4ae5852aed9ed68e9eac47e964d1`, not to this updated source. Latest-head hosted and separate permanent registered VPS CI are mandatory before promotion; do not imply historical production database inspection or approval.
