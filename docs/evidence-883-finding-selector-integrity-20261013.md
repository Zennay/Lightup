# #883 — finding evidence integrity across all SQLite read selectors

**LightUp Incubate M3/M7 — independent synthetic acceptance / DRAFT HOLD / NO MERGE / NO DEPLOY.**

Source owner #856 already defines the reader-decoder invariant; issue #883 verifies its propagation through **all three real** `DomainStore.list_findings()` selectors:
- explicit engagement ID (after engagement tenant authorization),
- client-admin tenant-scoped default selector,
- operator-wide audit selector with multiple tenants.

Base is original #856 RED branch `chatgpt/finding-read-evidence-integrity-red-20261007` exact `1a6749098a85b00127cd711e3ab668215ee52ce8`. This child adds one new test module and this document **only**. It does not alter `src/lightup/domain.py`, finding write-side #857, twin projection #882, #854 labsync, scope, executor, another worker's branch, or deployed code.

## Tests

The module uses an ephemeral on-disk SQLite database with synthetic tenants A and B, each with independent engagement and durable evidence-backed finding. The three ordinary controls confirm that:
1. engagement-filtered reads preserve both canonical evidence refs;
2. client-scoped reads preserve only tenant A;
3. operator-wide audit preserves the exact records and refs across both tenants.

**Nine unresolved intentionally expected RED acceptance cases**: each of the three selectors must reject each of these corrupt persisted `evidence_ids_json` shapes with an evidence-integrity `ValueError`:
- a top-level string (currently becomes per-character evidence);
- a list containing a numeric element (currently accepted as invalid evidence);
- duplicate evidence refs (currently passed through).

Every negative case independently reopens SQLite, verifies that corrupt bytes were not rewritten during read, and proves the separate tenant B's evidence remained readable and unmodified. It must reject the entire selector response rather than silently yielding a partial safe-looking list.

Run the exact module:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_finding_evidence_selector_integrity_883.py' -v
```

**Expected pre-fix:** 12 methods executed; 3 PASS controls, 9 **expected failures**. Expected failures are unresolved vulnerabilities, **not** passing security claims. The #856 read source owner must add strict shared decoder admission, remove all nine decorators after actual fix, and require **12 ordinary passes with zero expected failures** on all selectors.

Exact-head GitHub-hosted Python 3.11/3.14 preflight, separate registered permanent VPS CI, original source-owner review, latest-main reconciliation, privacy/security review, and explicit human approval are prerequisites to merge or deploy. No customer records, targets, DNS, scans, grants, real evidence acquisition, external AI or actions are involved.
