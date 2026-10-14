# Offline tenant CIDR large-inventory and dual-stack adversarial review

**LightUp INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**

This supplemental test-only quality-validation companion belongs solely
to the isolated scope-authorization [DRAFT PR #1318](https://github.com/Zennay/Lightup/pull/1318).
It does not modify the LightUp production scope policy or original
source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100).

The deterministic stdlib suite
`tests/test_scope_tenant_cidr_adversarial_offline.py`
adds **12 genuine test methods**. It exercises precisely 64 disjoint
IPv4 and IPv6 networks, denial at the 65-record bound, a conflict
hidden in the last record, seeded 220-pair IPv4 and 160-pair IPv6
disjoint-versus-nested collision oracles, tenant-label invariance,
transient history widening, tenant reassignment, IPv6 textual aliases,
hidden Unicode identity controls, no-socket/no-DNS behaviour and
read-only caller-state preservation.

Run locally:

```sh
python3 -m unittest discover -s tests -p 'test_scope_tenant_cidr_adversarial_offline.py' -v
```

All cases remain synthetic. A green report is evidence only for the
code on its immutable commit: it does not verify true network
ownership, real client consent, trusted inventory state, live
authorization grants, tenant lineage, permitted windows, tool
capabilities, revocations, production execution or security release.
No DNS, network, scanning, grant issuance, database modifications,
workflow/runner edits or deployment. All review receipts preserve
five authority flags as `false` and have deliberately nonzero exit
codes even for `REVIEW_ONLY`.

Require exact-current-HEAD hosted and permanently registered VPS
verification, separate security/privacy/source-owner review and
explicit human approval before any merge/deploy or target activation.
**DRAFT/HOLD · NO MERGE/DEPLOY/REAL SCANS.**
