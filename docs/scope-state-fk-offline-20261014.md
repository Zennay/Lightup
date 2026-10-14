# Scope state provenance FK gate — #170 (14 October 2026)

**Status: opt-in / disposable SQLite / DRAFT-HOLD / non-authorizing.** This reference addresses an observed connection-local foreign-key gap in `StateStore`, without changing owner-managed `src/lightup/state.py`, `src/lightup/ai/orchestration.py`, PR #167/#156/#169, existing tests, production workflow, runner, or deployment.

## Run (offline)

```sh
python -m unittest discover -s tests -p 'test_scope_state_fk_offline.py' -v
python scripts/check_scope_state_fk_offline.py
```

The script imports the real `StateStore`, creates its **own temporary disposable SQLite DB** and automatically deletes it. It never opens a provided/customer DB or performs network/DNS/target/scanning/grant operations. It deliberately writes synthetic database rows, but only in the freshly created temporary DB. No production-state side effects are possible through the ordinary CLI.

## Eleven independently reported checks

1. `new_connection_fk_enabled` — freshly opened SQLite connection has FK enforcement ON.
2. `orphan_evidence_denied` — real `add_evidence` rejects unknown run ID.
3. `orphan_lease_denied` — real `acquire_lease` rejects unknown run ID.
4. `raw_orphan_evidence_denied` — **direct SQL** orphan insert is rejected even if higher-level methods perform their own validation.
5. `valid_run_evidence_stored` — ordinary registered plan-only run persists evidence.
6. `registered_run_provenance_exact` — persisted run ID, localhost target, plan-only activation mode, absent auth reference and planned status match expected *exactly*.
7. `connection_fk_consistent` — a second, independent connection also enforces FK.
8. `delete_cascades_evidence` — removing the synthetic run on another connection removes associated evidence.
9. `delete_cascades_lease` — same for a genuine capability lease.
10. `sqlite_foreign_key_check_clean` — SQLite reports no FK violations both before and after the synthetic delete.
11. `no_orphan_rows_persisted` — neither orphan evidence nor orphan lease is retained.

This covers **both** high-level application behavior and an independent raw SQLite path, plus lifecycle cleanup after the run is removed. A green `PRAGMA` alone is insufficient; all checks must pass. Individual failed checks are booleans without sensitive IDs or paths.

## Contract

- All checks pass: `REVIEW_ONLY`, exit 0.
- Any check fails: `HOLD`, exit 2.
- Any unexpected error: `HOLD` + fixed `PROBE_UNAVAILABLE` without traceback, file path, record or exception detail; exit 2.
- Every receipt fixes `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved` and `release_approved` to **false**.
- `REVIEW_ONLY` is strictly a *synthetic local diagnostic*; it is **not trusted proof of runtime authorization, release readiness, or future safety**.

13 unittest methods run genuine temporary SQLite fixtures: positive enforcement, deliberately disabled FKs, split app-vs-SQL controls, independently denied evidence/lease, altered run mode/target, ephemeral cleanup, opaque failures, bounded receipt shape and non-authority flags. The source-owner production fix can turn HOLD into REVIEW_ONLY without rewriting tests to expect perpetual failure.

**Expected on main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`: HOLD** because `StateStore.connect()` does not enable FK on every opened connection; main cannot guarantee orphan denial or cascading cleanup.

## Remaining #170 production ownership

Source owner must enable per-connection FKs and ensure **exact** persisted run provenance before evidence, plus validate live `RunContext` mode, authorization reference and run identity in the **real executor**, including pre-I/O revocation. This reference is not a patch to those owner paths, not an independent verdict about a real target, and does not eliminate all SQLite trust-boundary threats.

Preserve **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS** until independent security/privacy/source-owner review, latest-main integration, exact SHA hosted Python 3.11/3.14 and actually executed permanently registered VPS CI, plus explicit human approval.
