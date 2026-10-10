# Evidence-remediation: opt-in atomic retest-status metadata sidecar (W3)

**Phase:** M3/M7; PLAN/LAB only. **Status:** DRAFT/HOLD. Related open issue: [#893](https://github.com/Zennay/Lightup/issues/893). No live targets, tests against targets, evidence collection, remediation implementation, deployment or source-owner wiring.

## Why this exists

Current `DomainStore.set_retest_status()` writes `findings.retest_status` under SQLite autocommit *before* reconstructing the persisted `FindingRecord`. If historical `evidence_ids_json` is malformed, reconstruction can fail after durable status mutation. A failed retest-metadata update therefore need not be atomic. This was captured as an unresolved RED acceptance contract in issue #893.

`src/lightup/retest_status_atomic_sidecar.py` demonstrates a **narrow opt-in repair** without changing concurrently owned `domain.py`, the canonical persisted evidence decoder from #856/#886, the write validator #851/#857, lab sync #184/#854 or review/queue PRs #846 and #1177.

## Implementation

1. Fail-closed exact runtime types for an operator-shaped context, the finding ID and `RetestStatus`; **these types are not authenticated authority**.
2. Begin a `BEGIN IMMEDIATE` SQLite transaction **before** selecting any persisted finding data. A same-transaction join requires the stored finding tenant to match its engagement tenant.
3. Validate bounded persisted evidence JSON as a list of unique, nonempty, printable built-in strings, with no conversions or repairs.
4. Decode the canonical `FindingRecord` *before* writing, update with a compare-and-swap constraint, reconstruct the new row **before** commit, and roll back every exception (including decoder failures). Compare the complete original non-status row projection after the update: `finding_id`, client/engagement lineage, title/severity/asset/impact/remediation, original **raw evidence JSON bytes** and creation time must remain unchanged. This also fails closed on synthetic same-row SQLite trigger mutations. Compare SQLite connection `total_changes` around the update: any extra trigger write, including changes to a **different** finding row, aborts the entire transaction rather than silently modifying unrelated remediation state.
5. No change to the main `DomainStore.set_retest_status` entrypoint. The helper is deliberately not installed in the web/API/agent/assessment paths. It is not protection against an adversary who can modify the SQLite file, run arbitrary SQL, create triggers against other rows/tables, or bypass the trusted session system.

**Important semantics:** `RetestStatus.FIXED` is *only an existing data-model string/enum*. A successful synthetic metadata transition **does not** verify a fix, authenticate an operator, establish evidence provenance, prove a tenant session, authorize remediation, or permit any test. No background action is triggered by this helper.

## Acceptance / negative evidence

- Disposable SQLite canonical findings (including legitimate empty evidence) can transition without changing evidence/client/engagement bytes.
- JSON scalar, null, object, malformed array, nonstring members, blanks, duplicate references, control characters and size violations all fail before durable mutation; corrupted original bytes stay unchanged.
- An invalid severity that crashes row reconstruction also rolls back the transition.
- Synthetic SQLite `AFTER UPDATE` triggers that rewrite a finding's title, remediation, tenant, creation time, or reformat equivalent evidence JSON must cause **full transaction rollback**, without any silent change to the original row.
- A synthetic trigger that **writes to a second finding** must also fail before commit; neither the selected finding nor its sibling may change.
- Unbound client/engagement tenant mismatch, unknown finding, unsupported runtime types, nonoperator and concurrent writer lock all fail with no status change.
- One `unittest.expectedFailure` RED canary against **existing** `DomainStore.set_retest_status` uses deliberately truncated persisted JSON to prove the old entrypoint commits a partial status update **before** decode. This is a documented unresolved source defect, not successful production remediation. This expected failure is *not* green remediation evidence.

Run the offline acceptance (no network):
```sh
PYTHONPATH=src python -m unittest tests.test_retest_status_atomic_sidecar_20261010_w3 -v
```

## Integration dependencies: explicit HOLD

Owner-controlled resolution of #893 must happen on an exact integrated source SHA: absorb canonical strict evidence decoder (#856/#886); change the real DomainStore mutation in the #828 owner lane; replace RED canary with an ordinary passing entrypoint assertion; enforce real authenticated role/tenant/session and action-time revocation outside this standalone helper; acquire independent reviewer approval and **both** hosted Python 3.11/3.14 tests and canonical permanent VPS self-hosted CI on final SHA. In particular, a queued/cancelled VPS workflow is **not** CI proof. Do not merge/deploy or advertise a verified remediation based on this sidecar.

## Parallel ownership

Exactly these three **new paths** are owned by this draft branch:

- `src/lightup/retest_status_atomic_sidecar.py`
- `tests/test_retest_status_atomic_sidecar_20261010_w3.py`
- `docs/evidence-remediation-atomic-retest-sidecar-20261010-w3.md`

No edits to active worker-owned production source, no DB change outside disposable test instances, no real targets, no grants or assessment actions.
