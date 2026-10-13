# #809 — independent postrepair tenant-lineage acceptance

**Isolated tests-only child of existing source-owner branch** `chatgpt/scope-authorization-risk-approval-tenant-lineage-fix-20261007`. This branch changes **no** existing source, owner tests, queries, decision logic, policy, users, or production database. The original source-owner branch is unchanged.

The earlier independent [#808 baseline draft PR #1272](https://github.com/Zennay/Lightup/pull/1272) has **8 normal PASS + 5 intentional expected RED** against unfixed main. This distinct integration suite removes **all** expectedFailure decorators and runs the same **13 real SQLite scenarios** against the unmerged source-owner #809 query fix. Passing all 13 is necessary for the proposed joined tenant/engagement read, but it is not sufficient proof of production authorization, durable revocation, installed ingress or tenant-owner review.

New negative acceptance beyond the old owner #809 tests: changing a persisted approval pointer A→B while leaving the A tenant label; orphaning an approval through explicitly foreign-key-disabled **temporary** offline SQLite; keeping an unrelated valid B record visible; and verifying rejected reads leave durable approval rows unmodified. Both client-wide and explicit engagement paths are covered. No network, real tenant, scan or target interaction.

Local command, repo root:
```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_809_real_sqlite_lineage_integration_20261013.py' -v
```

Do not merge a tests-only stack into main as if it integrated the #809 source fix. CI on this child only checks that old #809 source candidate satisfies the added tests; separately rebase and review the original owner-approved source diff against latest main, check authentication, operator-audit behavior and privacy/security, require exact-head Python 3.11 and 3.14 GitHub-hosted and genuinely permanently registered VPS CI, then explicit human authorization. **INCUBATE M3/M7 PLAN/LAB ONLY / DRAFT/HOLD / NO MERGE / NO DEPLOY.**
