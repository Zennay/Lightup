# #897 — Read-only synthetic risk-decision coherence preview

**Scope:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. This reviewer is uninstalled test-only code; it cannot create/approve/deny risk elevations, issue grants, invoke capability handlers or change production SQLite.

## Ownership / exact lineage

This separate opt-in child starts from unchanged #897 composition HEAD `d9fe532ae90bffe5d6db303acc48287fe59a631b` (which itself contains intact #791/#796/#807 owner-source RED acceptance pinned to PR #146). Owner PR #146 remains responsible for `DomainStore.decide_risk_elevation`; no owner-source, workflow, persistent database, existing tests or other-worker branches were modified.

## Actual implementation

- `tests/scope_897_offline_risk_record_guard.py`: pure read-only `review_record` and bounded (3072-byte) explicit `--offline-synthetic-only` JSON CLI. Rejects non-built-in data, duplicate/extra/missing keys, noncanonical synthetic UUID4 approval identity, blank/polymorphic requester, self-reviewer identity, status other than exact `pending`, and stale `decided_by`/ `decided_at` fields. All string checks happen after **exact built-in type admission**, before attacker-provided SQL-adapter/equality methods are ever called.
- Always outputs generic `HOLD` or `REVIEW_ONLY`; **both exit nonzero (2/3)**. All six grant/permit/dispatch/scan/deploy/release flags are **literal false**. No IDs, customer data, input text or error values are echoed. Conservative sample actor and ID vocabulary is an offline *review subset*, not a source-owner requirement or permission claim.
- `tests/test_scope_897_offline_risk_record_guard.py`: 12 truly executed test methods, including two **real temporary in-memory SQLite fixtures** demonstrating corrupted BLOB requester and pre-decided PENDING audit fields are HOLD with the original stored row unchanged. Also identity coercion adapter zero-call, immutable caller snapshot, schema mismatches, noncanonical types, and subprocess CLI/no-echo regressions.

## Actual local test evidence

`unittest` **12 methods PASS** and `pytest` **12 tests, 29 subtests PASS**; `py_compile` PASS. Original local test bytes and exact committed GitHub blobs match:
- functional reviewer `30009b85246e308b7f06df51027102eebe3ec77e`;
- regression `0898c94dd6171a0cd69e29d7dbaf5cd146875599`.

These passes validate the isolated helper and real local SQLite *only*. The inherited original #791/#796/#807 **source-REDs remain unresolved**, and no release proof, production source fix, hosted preflight, registered VPS job, authentic customer/operator decision or independent security/privacy review is claimed.

## Owner handoff / hard stop

PR #146 source owner must implement exact authorization-request identity before multiple SQL binds, verify canonical durable `requested_by` before self-approval, reject PENDING rows with stale audit before mutation, and preserve transaction/role/tenant/risk/one-shot invariants. Source-owner integration then needs ordinary non-expected RED-to-PASS regressions on immutable reviewed HEAD, both hosted Python3.11+3.14 plus registered `[self-hosted,zcloud,vps]`/hostname evidence, independent review and human GO. #1144 runner state remains unverified. No real decisions, grants, handler, target, scan, PR/merge/deploy or release performed by this child.
