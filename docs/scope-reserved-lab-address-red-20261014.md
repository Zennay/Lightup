# LightUp #1422 — reserved/non-routable IP is not automatic private-lab authority

**Status: owner handoff / deliberately RED on current `main`.**
**INCUBATE M3/M7 · PLAN/LAB ONLY.** No real target scans or grants.

## Concrete cause
`ScopePolicy.decide()` currently delegates the privileged `PRIVATE_LAB` shortcut to Python `ipaddress.is_private or is_link_local`. `is_private` is a non-global-reachability classification, **not** membership in a designated trusted private lab. A host from an IANA documentation, benchmark, unspecified, broadcast or link-local range is not a customer-authorized or private-use lab merely because it is non-global.

Synthetic literals reproduced using Python's `ipaddress` semantics:
- IPv4 TEST-NET: `192.0.2.1`, `198.51.100.1`, `203.0.113.1`.
- Benchmark testing space: `198.18.0.1`.
- Unspecified/broadcast: `0.0.0.0`, `255.255.255.255`.
- IPv6 documentation: `2001:db8::1`.
- IPv4 link-local: `169.254.1.1`.

These strings are used **only in memory** as `Target` values. No DNS resolution, sockets, HTTP requests or probes.

## Added acceptance
`tests/test_scope_reserved_lab_address_red_20261014.py` contains eight separate `@unittest.expectedFailure` **known source defects**. A companion integrity test independently executes all eight and requires genuine `AssertionError` witnesses, with zero runtime errors and zero unexpected successes. This is deliberately **not a security PASS**. Two ordinary positive checks preserve current loopback/RFC1918/ULA semantics, and verify disabling private-lab mode denies all synthetic non-loopback targets.

Run from repository root:
```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_reserved_lab_address_red_20261014.py' -v
```
Run with both Python 3.11 and 3.14 on hosted CI, then check exact-commit head and genuine permanent VPS CI separately. Do not claim green from an older or queued run.

## Composition / collision boundary
Current source-owner PR [#100](https://github.com/Zennay/Lightup/pull/100) owns `src/lightup/scope.py` and adjacent classification logic. This change **only adds two fresh files** in a self-owned acceptance branch. [#365](https://github.com/Zennay/Lightup/issues/365) intentionally excludes reserved/link-local positive membership, and [#1289](https://github.com/Zennay/Lightup/issues/1289) owns parsing; neither source code nor worker branch is changed here.

The owner should define an explicit trusted-lab network membership policy independent of `ipaddress.is_private`, avoid blanket non-global admission, and convert every RED canary to ordinary PASS only after fixing the production boundary. Explicit public scope authorization, grant scope, tenant, revocation and execution checks remain separate. A test-only source fix is not authorization to scan or deploy.

All authority/permit/execution/merge/release permissions remain **false/unissued** for this work.
