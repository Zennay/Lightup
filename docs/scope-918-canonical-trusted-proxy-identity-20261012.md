# Scope #918 — trusted proxy exact-identity acceptance (offline lab)

## Collision and release boundary
- OPEN GitHub issue [#918](https://github.com/Zennay/Lightup/issues/918), production WebSecurity source owner [#202](https://github.com/Zennay/Lightup/pull/202).
- Adjacent distinct public-origin issue [#919](https://github.com/Zennay/Lightup/issues/919); its independent DRAFT [#1255](https://github.com/Zennay/Lightup/pull/1255) owns separate paths.
- Pinned, unchanged main `05b80319cd0581fed21fe9d8f565bcb0a56cd2df` (12 October 2026). This branch adds only an independent test and this runbook. No production security, web, domain, executor, Nginx, settings or parallel-worker changes.

## Exact requirement
A production `WebSecurity(public_origin, trusted_proxy_ip)` must require **`type(trusted_proxy_ip) is str` before any IP parsing**; do not rely on annotations or `isinstance(..., str)`. After exact type admission, parse as IP loopback and hold immutable built-in value (or canonical trusted peer). Never allow polymorphic equality on stored configuration to decide if the request's `REMOTE_ADDR` is trusted.

## Offline acceptance
`tests/test_scope_918_canonical_proxy_identity_20261012.py` has 11 actual real-source/WSGI unittest methods:
- Two **intentional expected RED** canaries for same-value `str` subclass admission and equality-spoofing proxy subtype retention.
- Green exact builtin `127.0.0.1` and `::1` controls and strict peer/port/forwarded metadata denials.
- Reject nonloopback, invalid and nonstring proxy configuration before any handler or session.
- WSGI foreign-peer POST returns 403, no-store; mocks ensure no session DB method call or request-body read.
- Generic errors do not echo sensitive/foreign peer content.

A deliberately expected RED passing in unittest is **not proof of the production fix**. Equality-spoofing is a credible trust hazard but this suite's XFAILs establish the **configuration type gap**, not an observed deployed socket-peer compromise. The real WSGI control verifies that a builtin exact proxy remains fail-closed. All I/O is in-process with mock store and synthetic RFC5737 address; no DNS, listeners, scans, real targets, accounts or grants.

```bash
PYTHONPATH=src python -m unittest -v tests.test_scope_918_canonical_proxy_identity_20261012
```

## Owner and release conditions
- Coordinate any production source change exclusively with #202 and parallel #919; turn both intentional RED canaries into ordinary passing tests *only when source actually fixes the defect*.
- Add original-production factory + installed ingress validation with peer provenance; test direct/non-proxy, IPv4/v6, host/proto/origin/POST/CSRF and actor/tenant boundaries; freeze trusted peer before request reads.
- Independently review privacy/security, latest-main composition and registered permanent self-hosted VPS LightUp CI on **exact final HEAD**, in addition to Python 3.11/3.14 hosted diagnostic.
- Explicit human release authority is required. Keep #918 OPEN and this PR **DRAFT/HOLD/NO MERGE/NO DEPLOY**. LightUp remains Incubate M3/M7 PLAN/LAB ONLY.
