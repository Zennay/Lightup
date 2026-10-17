# LightUp scope #1561 — offline tenant-grant lineage snapshot inspector

**Status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**
This is an **unwired informational diagnostic**, NOT an authentication,
consent, authorization, revocation, scan, tool dispatch, deployment, merge
or release gate. No result confers any authority, including `REVIEW_ONLY`.

## Why this is needed

Original issue [#829](https://github.com/Zennay/Lightup/issues/829) proves
`DomainStore.list_authorization_grants` may return a stored grant whose
persisted `client_id` disagrees with its actual engagement owner. A separate
[source-owner-only patch proposal](https://github.com/Zennay/Lightup/pull/1560)
is not merged into installed code. This module **does not apply that fix**.
Instead it provides an isolated **offline summary** of tenant grant-lineage
integrity in an already exported and quiescent local SQLite snapshot.

It is distinct from issue #647's timestamp widening audit, issue #1493's
cross-gate legacy/durable reviewer and issue #829's source RED suite.
It never opens a live service, calls `DomainStore`, reads policy/permit
objects, contacts customers or activates a tool.

## Use only with an offline, disposable, locally owned database copy

First **stop all writers** and create a consistent offline copy outside this
tool. The inspector deliberately refuses WAL, SHM and rollback-journal sidecars
instead of silently missing transactions. It refuses symlinks (including path
parents), hardlinks, non-regular files and snapshots over 16 MiB. It uses
`file:...` SQLite URI `mode=ro&immutable=1` plus `PRAGMA query_only=ON`
and never runs a write query. SQLite `quick_check` and schema checks must
pass. The caller must independently ensure the snapshot is not changing; no
concurrency guarantee can be established against an adversarial filesystem.

The invoked database must be an **authorized offline copy**, preferably a
fictional development fixture. Do not point this at the live LightUp database,
customer assets, production secrets or another worker's active checkout.

From an installed source checkout:

```bash
PYTHONPATH=src python3 -m lightup.scope_grant_tenant_snapshot_1561 \
  --offline-copy /path/to/fictional-offline-copy.sqlite
```

The executable prints exactly **one JSON line**. It **never** exits zero:
- `exit 3` `REVIEW_ONLY` — the complete bounded snapshot appears internally
  coherent. This is **not consent, approval or evidence of correct permissions**.
- `exit 2` `HOLD` — missing/malformed/unsafe snapshot, unknown row identity,
  unmatched tenant lineage, orphaned engagement or over-limit input.

It returns only a bounded tally:
`coherent`, `mismatch`, `orphan`, `total`, `status` and a fixed categorical
`reason`. It never emits arbitrary identifiers, paths, references, assets,
scope values, timestamp details, exception strings, or database contents.
Every `authorized`, `consent_verified`, `grants_allowed`, `scans_allowed`,
`dispatch_allowed`, `merge_allowed`, `deploy_allowed` and `release_allowed`
flag is literally `false`. At most 10,000 grants are read; if over-limit
or input corrupt, the result is `HOLD` with all count fields zero (no partial
or stale receipt). The file's size, device/inode and nanosecond timestamps
must match before/after the read. It is also SHA-256 hashed before and after
using read-only `os.open(O_NOFOLLOW)` to bind both hashes to the validated
inode. The checksum detects byte drift even when coarse external file
metadata would be misleading; no digest or byte content is emitted. This is
not a transactional lock: hostile concurrent filesystem mutation and trusted
source authenticity still require a separate security review.

A `REVIEW_ONLY` receipt does **not** validate the true identity, validity
window, risk, asset, signatory, revocation, tenant session or security boundary
of any individual row. Counts can themselves be confidential business
metadata, so store any emitted receipt only in approved internal systems.

## Exact source ownership and tests

New feature module:
`src/lightup/scope_grant_tenant_snapshot_1561.py`.

New real SQLite/CLI regressions:
`tests/test_scope_1561_offline_grant_tenant_snapshot.py`.

Original production `domain.py`, WSGI, scanners, activation, execution,
grant issuance, #829 acceptance files, #647 window-review source, shared CI,
permanent runner and unrelated worker branches remain untouched.

Tests exercise actual temporary SQLite clients/engagements/grants, wrong tenant,
orphan, mixed corruption, BLOB/empty identifiers, SQL-shaped values as inert
text, missing PK/schema, invalid data, symlinks/parent symlinks, journal
sidecars, 10k-row limit, 16 MiB ceiling, byte-identical file and metadata
after reads, ordinary subprocess CLI receipts and denial of socket creation.

```bash
PYTHONPATH=src:tests python3 -m unittest discover \
  -s tests -p 'test_scope_1561_offline_grant_tenant_snapshot.py' -v
```

No live network/target interaction and no production writes. All release,
real consent, operator signoff, at-use revocation, independent security/privacy
approval, exact-head hosted and named-permanent-VPS validation gates continue
to apply. **No merge/deploy or active scan.**

## W2 — exact-head standalone hosted matrix and SHA-256 hardening

The own isolated file `.github/workflows/scope-1561-grant-tenant-offline.yml`
is **GitHub-hosted only**, permissions `contents: read`, no secrets,
self-hosted runners, active scans, deploy, release or workflow dispatch.
The established shared LightUp CI was not edited.

At immutable source head `584461429dc01a44690973958e39b5e6e7e9f830`,
[dedicated GitHub-hosted run #39056355774](https://github.com/Zennay/Lightup/actions/runs/39056355774)
is **COMPLETED SUCCESS 2/2**. Both actual Python 3.11
(job 117465001263) and Python 3.14 (job 117465001443) completed
compile, all **27 ordinary synthetic SQLite/CLI tests**, and a static no
active-import guard **successfully**. This is **not** named permanent VPS
CI, release authority or proof the original #829 read bug is repaired.

Connected zSSH `vps-bb300bba`, Python 3.14.4, on the exact
`58446142...` head: **27/27 normal PASS**, no intentional source failures,
clean worktree; original **86/86 producer integrations** also passed on an
earlier head. A full 1,260-test original unit suite at earlier
`1e11205a...` had exactly **one existing #301 fixture failure** and 23
separate pre-existing expected source failures, so **full-suite CI is NOT green**.

The new SHA-256+inode tests cover exact raw digest, hash change even with
metadata held constant (fault injected), hardlinked path rejection, and
mismatched inode signature refusal. These are offline filesystem invariants,
not permission checks. The ordinary original code source and customer data
remain wholly untouched.
