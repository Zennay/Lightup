# LightUp #1039 W3 — evidence survives denied emergency dispatch unchanged

**INCUBATE M3/M7 PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE / NO DEPLOY / NO TARGET.**

## Dependency and ownership

This tests-only child branch is based on immutable W2 [DRAFT #1251](https://github.com/Zennay/Lightup/pull/1251) head `5e3aa5c1a635368598fdce7734678856a06357fc`.
It does not edit W2 source/test/doc files, original #1039 emergency
reference branch, #100/#107 owners, default execution policy, web, queue,
runner, or main.

## Acceptance added

`tests/test_scope_1039_sqlite_postdenial_w3_20261012.py` uses actual
`ToolRegistry`, `ToolExecutor`, `ExecutionPolicy` and a disposable
`StateStore` SQLite database, while the handler is an inert mock. A synthetic
positive control inserts exactly one evidence record, and then:

- an explicit STOP cannot change any existing `evidence`, `runs` or
  `capability_leases` row; the pre/post SQLite snapshots must match;
- a malformed override cannot use truth coercion or append evidence;
- STOP wins before accessing unregistered tools or malignant context/call
  objects, with no handler/database side effects;
- STOP refusal does not stringify a secret-bearing malformed override object;
- 32 concurrent STOP-**already-active** calls must all be denied without
  modifying the one pre-existing synthetic evidence record.

The thread test only demonstrates a gate given **STOP already true before
dispatch**. It is **not** a proof of dynamically changing STOP state,
linearizable revocation, thread-safe registry mutations or atomic cutover.

## Reproduce and promotion limits

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1039*' -v
PYTHONPATH=src python -m unittest discover -s tests -v
PYTHONPATH=src:tests python -m unittest discover -s tests/integration -v
```

The W2 parent includes two explicitly `@expectedFailure` cross-client and
cross-engagement RED regressions for unrepaired default policy. Green hosted
jobs on W2 alone do **not** prove this child exact SHA. Source owner must fix
default tenant/engagement binding and convert RED to passing denials before
promotion; keep the RED cases visible while root cause remains.

Do not treat a stop bool supplied by a test as authenticated operator consent.
The opt-in helper remains uninstalled; real network, request queues,
retries, in-flight cancellation, trusted issuer/tenant checks, exact pre-I/O
revalidation, installed source and ingress are NOT validated here.

Require independent security/privacy/source-owner signoff, safe latest-main
composition, exact-child-SHA hosted Python 3.11/3.14 and separate permanently
registered self-hosted VPS CI, plus explicit human release approval.
Keep parent and child DRAFT/HOLD; keep original #1039 OPEN.
