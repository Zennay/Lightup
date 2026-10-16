# #920 — Offline synthetic transport-identity HOLD reviewer

**NON-AUTHORIZING.** This opt-in test sidecar is not imported by the LightUp product, cannot configure a proxy or origin, and never creates an execution permit, scan, client grant, release or deployment.

## Pinned ancestry and ownership

Direct child of the already-isolated #920 branch HEAD `55e0abb629c7c5bc630f9d95ba6b50f26727aaef`, itself stacked on **unchanged** WebSecurity source-owner PR #202 HEAD `0a6eb118de5153eb72115cc871122175b8d54dfd`. No other worker's branch or original runtime/CI/workflow files are modified. This branch adds only wholly new `tests/scope_920_offline_transport_guard.py`, `tests/test_scope_920_offline_transport_guard.py` and this document. It is a disposable **offline review reference**, not owner-integrated production code.

## What the reviewer validates

The standalone reviewer accepts one bounded (<=4,096-byte), unique-key UTF-8 JSON object from stdin with *exactly* the two attributes `trusted_proxy_ip` and `public_origin`. The direct Python review API additionally rejects subclasses, strange outer dictionaries and spoofed `__class__` without using caller-defined comparisons. Only canonical fictional localhost/loopback IP `127.0.0.1` or `::1` and exact lower-case HTTPS origin under reserved `.example` qualify for **REVIEW_ONLY**. This is a deliberately narrower diagnostic vocabulary than production. Any remote/ambiguous/private IP, non-HTTPS origin, userinfo, port, URL path/query/fragment, Unicode/IDN, duplicate/extra/missing key or malformed input becomes **HOLD**.

**Both decision types always emit SIX literal `false` authority flags**, and both exit nonzero: HOLD=2, REVIEW_ONLY=3. No input values, assets, identifiers, raw JSON, authorization claims or exception strings appear in output. The script has no network/client/target imports and cannot issue real approval, probe a host or mutate the running service.

## Opt-in invocation — fictitious data only

```bash
printf '%s' '{"trusted_proxy_ip":"127.0.0.1","public_origin":"https://lightup.example"}' |
  python tests/scope_920_offline_transport_guard.py --offline-synthetic-only
# exit 3; generic REVIEW_ONLY + six false authority flags
```

Omitting the explicit switch always returns HOLD exit 2. No step here means GO. Do **not** feed customer endpoints or production-origin configurations into this synthetic-only tool.

## Verified and unverified

Local hermetic `unittest` discovery on the two identical GitHub/local blobs produced **9 tests PASS**: exact fictional loopback/origin controls, subclass and `__class__` spoof denial, non-canonical IP/origin matrix, duplicate-key/unicode/oversize/invalid-JSON, 3 actual subprocess CLI paths and privacy non-echo. This is supplementary **local unit evidence only**, not the installed owner `WebSecurity` suite or trusted VPS CI. Production #918/#919 source-RED contracts on parent #920 are **still unresolved** and have not been rerun here.

Release guardrail: source-owner PR #202 must independently repair and review real WebSecurity constructor admission. Then promote the two real installed-source contracts to ordinary PASS, obtain exact integrated HEAD on hosted Python 3.11+3.14 and assigned registered VPS `[self-hosted,zcloud,vps]` with matching `vps-bb300bba` hostname, independent security/privacy and actual client/operator consent plus explicit human GO. No PR/merge/dispatch/deploy by this sidecar worker while shared runner lane is held.
