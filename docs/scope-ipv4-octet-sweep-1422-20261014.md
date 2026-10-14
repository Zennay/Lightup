# LightUp #1422 — W44 full IPv4 octet-boundary sweep (offline only)

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY/ACTIVE TARGETS**

## Why this adds separate coverage
Current `src/lightup/scope.py` uses `ipaddress.is_private or is_link_local` to grant automatic `PRIVATE_LAB` classification. These predicates are **not** equivalent to a trusted lab membership set, so non-routable documentation, benchmark, unspecified, broadcast or link-local addresses can be accidentally admitted. Issue [#1422](https://github.com/Zennay/Lightup/issues/1422) remains unresolved in installed source.

[PR #1423](https://github.com/Zennay/Lightup/pull/1423) owns named RED acceptance; [PR #1426](https://github.com/Zennay/Lightup/pull/1426) owns a fixed 34-address diagnostic matrix; [PR #1425](https://github.com/Zennay/Lightup/pull/1425) owns optional exact-literal candidate preview. This W44 lane adds an **independent bounded IPv4 octet sweep**, not source-owner changes or a duplicate fixed-literal list.

## Implemented
- `scripts/audit_scope_ipv4_octet_sweep_1422_offline.py` runs **1,024 deterministic IPv4 samples**, twice with `allow_private_lab=True/False`: every first-octet /8 at two edge samples, and every second octet for the 172/8 and 192/8 boundaries. Exactly **2,048 decisions** from real `ScopePolicy.decide(Target(...))`, purely in memory; never a packet, scan or DNS request.
- The independent expected contract restricts local automatic admission to loopback `127/8` plus private RFC1918 `10/8`, `172.16/12` and `192.168/16`. Switching private-lab mode OFF must disable all private-use automatic admissions but preserve loopback.
- Every checked `ScopeDecision` must have canonical result and flag types, exact unchanged normalized literal host identity, and exact expected denial/admission reason. **Any** mismatch, exception or partial review yields atomic `HOLD` with `checked_count=0`.
- `REVIEW_ONLY` on a fully matching synthetic oracle has no authority. The receipt always includes five **literal false** markers: `authorization_verified`, `permit_issued`, `execution_enabled`, `merge_approved`, `release_approved`.
- The executable takes **no arguments**, reads **no stdin**, emits one short JSON line with no target literals, customer IDs, grants, paths or traceback. Both `HOLD` and `REVIEW_ONLY` exit nonzero (2 and 3). Exit 0 is never a permit.
- `tests/test_scope_ipv4_octet_sweep_1422_offline.py` checks a separate strict synthetic oracle, deliberate allow-all/deny-all, host-label swap, non-boolean decision, exception-privacy, socket/process denial, strict argv and a real `python -I -B` subprocess.
- The **actual installed source** is intentionally covered by one `@expectedFailure` assertion plus a second test that verifies the RED witness is an authentic assertion failure, not a masked runtime error. An expected RED must never be called a source fix.

## Offline operator checks
```bash
python -I -B scripts/audit_scope_ipv4_octet_sweep_1422_offline.py
PYTHONPATH=src python -B -m unittest discover -s tests -p 'test_scope_ipv4_octet_sweep_1422_offline.py' -v
```
Run exact-head Python **3.11 and 3.14** plus real producer integration tests on hosted CI. Permanent registered VPS proof is a **separate requirement**: queued/cancelled actions do not demonstrate runner execution. This is Python-level no-I/O evidence, **not** an OS sandbox or production release gate.

## Collision and ownership
Only the following **three newly owned paths** may change in this PR: this document, the offline script and its tests. Original `scope.py`, `models.py`, activation, executor, source-owner [PR #100](https://github.com/Zennay/Lightup/pull/100), parser [PR #1290](https://github.com/Zennay/Lightup/pull/1290), tenant CIDR [PR #1318](https://github.com/Zennay/Lightup/pull/1318), W38–W43 [PR #1426](https://github.com/Zennay/Lightup/pull/1426), workflows, self-hosted runners, customer data and deployment must remain untouched.

**Owner handoff:** repair installed `ScopePolicy.decide` with an explicit, reviewed trusted-lab class rather than a generic non-global predicate, preserve legitimate private/lab/loopback behavior, and convert genuinely RED tests to ordinary PASS after independent security and privacy review. Review of source, per-tenant consent, bounded asset/capability/risk, live revocation and explicit human release decision remain separate mandatory controls. Neither this audit nor any `REVIEW_ONLY` receipt can authorize scanning.
