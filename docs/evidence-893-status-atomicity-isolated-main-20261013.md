# LightUp #893 — isolated SQLite retest status atomicity acceptance (2026-10-13)

**Posture:** Incubate M3/M7, PLAN/LAB ONLY, DRAFT/HOLD/NO MERGE/NO DEPLOY. The original `src/lightup/domain.py`, [owner opt-in retest-sidecar PR #1178](https://github.com/Zennay/Lightup/pull/1178), cross-row owners and main are untouched.

## Why this branch

The original tests-only branch `test/evidence-893-atomic-retest-crossrow-20261013` has four other independent test/docs paths and had **not been executed**. This branch starts on a fresh `main` and copies only the previously owned **single seven-method disposable real-SQLite acceptance suite**, with this handoff document. This provides a clean, separately checkable source-owner acceptance receipt without hiding any owner changes or inheriting older non-green retest-review dependencies.

## Failing contract

The current installed `DomainStore.set_retest_status(ctx, finding_id, status)` takes `status.value` without strict `RetestStatus` type admission and executes `UPDATE findings SET retest_status = ?` before decoding the resulting stored row. A forged object may therefore **commit an unsupported status to SQLite** and only THEN trigger `ValueError` during returned Finding decoding. A plain string instead produces incidental `AttributeError`; neither is a correct **controlled fail-before-write** contract.

`tests/test_evidence_893_status_type_atomic_red_20261013.py` has **seven executable unittest methods**, using genuine local disposable SQLite `DomainStore` and synthetic, role-scoped operator/client fixtures:
- **three normal PASS controls:** legitimate `RetestStatus.FIX_PENDING` persists, client cannot mutate and unknown ID does not mutate an existing finding;
- **four deliberate `@expectedFailure` safety canaries:** forged enum-like object with permitted value, forged unknown text, forged bool, raw string. A source-owner production fix must reject all **before mutation**, with controlled `ValueError` and bit-for-bit unchanged durable `retest_status,evidence_ids_json` tuple after reopening.

These four expected failures are **NOT passed release gates**; a suite reporting `OK (expected failures=4)` is test infrastructure evidence of an **open** installed integrity bug, not remediation. The branch contains no actual fix, no default-source modification, no external target, network call, client DB, active grant, remediation or retest execution.

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_893_status_type_atomic_red_20261013
```

**Source-owner handoff:** check exact trusted canonical `RetestStatus` before writing; review role/tenant and transaction atomicity; preserve genuine operator status progression; convert all four expected-RED tests to ordinary PASS; independently approve privacy/security, latest-main compatibility, exact-head hosted Python 3.11/3.14 **plus permanent registered VPS**, and explicit human release. **No merge/deploy.**


## W2 — cross-row and triggered side-effect durability (2026-10-13)

This clean-main tests-only branch now independently includes two earlier unexecuted original-owner laboratory suites:

- `tests/test_evidence_893_atomic_crossrow_20261013.py`: **6** genuine temporary-SQLite tests, **2 ordinary PASS** (two canonical independent finding transitions and unknown-ID denial) + **4 deliberately expected RED**: malformed JSON, JSON object, duplicate reference, and `null` evidence must not change ANY finding row after a rejected status mutation. Snapshot comparisons include two different findings and a second file reopen. Existing source still updates before validating the evidence.
- `tests/test_evidence_893_retest_audit_trigger_red_20261013.py`: **7** genuine temporary-SQLite tests using a synthetic, separately defined `AFTER UPDATE OF retest_status` trigger recording `retest_audit`. **3 ordinary PASS controls** check valid transition emits exactly one event, unknown ID creates none, client denial creates none. **4 deliberate expected RED** demand that malformed JSON, object-shaped JSON, spoofed canonical status and spoofed unknown status produce NO durable audit event or status mutation. This tests transaction side effects beyond the immediate finding row.

Together with the existing seven exact-status type methods (**3 ordinary PASS + 4 intentional expected RED**), the clean-main evidence suite now contains **20 real disposable SQLite test methods: 8 ordinary passing and 12 deliberately expected RED**. The original code owner still needs to validate evidence/status **before any UPDATE**, use an appropriate atomic transaction and prove rollback for both finding and trigger side effects; **this branch does NOT fix the product or provide source-owner integration**.

Run only synthetic local SQLite acceptance and hosted CI on exact head:
```sh
PYTHONPATH=src python -m unittest -v \
  tests.test_evidence_893_status_type_atomic_red_20261013 \
  tests.test_evidence_893_atomic_crossrow_20261013 \
  tests.test_evidence_893_retest_audit_trigger_red_20261013
```

No deployed `DomainStore` modification, authentic client grant, external target, executed retest, customer database, or authorization change. **Keep #893 OPEN and both permanent runner / security review release gates held**. Expected-failure cases are RED evidence, not acceptance. DRAFT/HOLD NO MERGE/NO DEPLOY.
