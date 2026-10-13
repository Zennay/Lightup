# #882 — durable finding evidence → verified Security Twin projection

**Status:** Independent source-owner RED acceptance; **Incubate M3/M7 / PLAN-LAB ONLY / DRAFT-HOLD**.

## Ownership and pinned lineage

- Base: `chatgpt/finding-read-evidence-integrity-red-20261007` at `1a6749098a85b00127cd711e3ab668215ee52ce8` (the original #856 finding-read acceptance branch).
- This child changes **only new** `tests/test_twin_persisted_evidence_integrity_882.py` and this document. It does not change `src/lightup/domain.py`, `src/lightup/twin_projection.py`, `src/lightup/twin.py`, auth, labsync, target-capable code, or another worker's branch.
- Source owner #856 must implement a canonical strict persisted decoder after #828's reader ownership clears; this branch **does not** install that fix.

## Exact acceptance and proof boundaries

The test harness creates two synthetic clients, two synthetic engagements, and evidence-backed findings in a **disposable on-disk SQLite database**. It reads and deliberately alters only its own test database's `findings.evidence_ids_json` and reopens SQLite to check the exact original stored bytes after rejection.

Ordinary passing controls:
1. Canonical evidence projects one verified finding node, one attack path, one verified severity fact and one verified relationship with identical canonical evidence references.
2. Corruption in tenant A never affects tenant B's independent projected evidence, and the corrupt tenant A row is unchanged.

Five **deliberately `@unittest.expectedFailure`** source-owner RED requirements:
1. Top-level JSON string must not become per-character evidence.
2. JSON object keys must not turn into verified lineage.
3. Mixed string/numeric arrays must not throw uncontrolled `AttributeError` or become graph data.
4. Whitespace-only evidence must not be silently dropped as if no corrupt row existed.
5. Duplicate persisted references must not be sorted/deduplicated into verified evidence.

Every negative assertion requires a deterministic **evidence-related `ValueError`** raised before a verified Security Twin result escapes, and compares reopened SQLite evidence bytes before/after. Canonical empty evidence on deliberately manual findings is a separate #856 contract and must not be conflated with corrupt non-empty references.

## Run locally and in CI

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_twin_persisted_evidence_integrity_882.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

An `OK (expected failures=5)` result is **NOT** remediation or a green security verdict. Verify that all 7 methods execute and the 5 intentional RED cases are counted correctly. After the original reader source owner implements strict admission, remove the expectedFailure markers, require **seven ordinary passes and zero RED**, rerun exact-head hosted Python 3.11/3.14 and separately registered permanent VPS CI, reconcile with latest main, conduct independent privacy/security and explicit human release review before merging.

No real customer evidence, authorization grants, external target, DNS, scan, evidence collection, AI-provider dispatch, remediation action, retest execution, attack-path mutation, deployment or security verdict is performed.
