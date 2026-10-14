# Destructive lab operator step-up: isolated candidate ledger (#1173)

This experimental component implements *durable candidate issuance and revocation* in a separately supplied SQLite database. It is intentionally **not connected** to ToolExecutor, web routes, the lab runtime, the deployment system or real targets. Scope and authorization remain **INCUBATE M3/M7, PLAN/LAB ONLY; DRAFT/HOLD**. An opt-in operator callback must return the literal boolean `True` after externally authenticating the operator and checking role + action. Nothing in this module implements or proves that callback, and it must never be populated by AI output, HTTP request fields or tool arguments.

## Material invariants

- Immutable per-run issue record with exact client, engagement, asset, capability, tool, operator and UTC timestamps, max 24 hours; no universal or wildcard target approval.
- Exactly one issuance per run enforced with SQLite `UNIQUE`. Revocation is durable, irreversible through this API, survives restart and cannot be evaded by reissuing the same run.
- Transactional `BEGIN IMMEDIATE` issuance/revocation; rollback on SQLite errors. Operator gate is called only after malformed identity/window input is rejected. Deny unknown callbacks, non-boolean results and exceptions without disclosing their details.
- Review receipts always return `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `merge_approved=false`, `release_approved=false`, including a current nonrevoked candidate. `REVIEW_ONLY` is an **untrusted local hint**, not authority.
- Real SQLite tests cover persistence across new connections, repeated issue, fail-closed revocation and malicious input. No simulated approvals establish real consent.

## Missing trust boundaries (DO NOT integrate yet)

This table is **not tamper-evident**. Anyone controlling the SQLite file or injecting a permissive operator callback can forge records. There is no independently proven authenticated human, durable role history, trusted clock, immutable audit log, customer consent/asset ownership, physical lab confinement, network egress fencing, destination binding, execution lock, or integration with every dispatch path. The original executor source owner [PR #107](https://github.com/Zennay/Lightup/pull/107) and optional step-up owner [PR #1172](https://github.com/Zennay/Lightup/pull/1172) must review and integrate only after those are independently established; this PR does not modify their files.

Run tests in the repository's existing environment with:
```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_lab_approval_candidate_ledger.py' -v
```

**NO REAL SCANS · NO ACTIVE LAB PAYLOADS · NO DEPLOY · NO CLAIM OF AUTHORIZATION.**
