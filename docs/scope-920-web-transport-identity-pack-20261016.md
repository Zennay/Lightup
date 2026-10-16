# #920 — Production transport identity acceptance pack

**Status:** INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD. No scan, deployment, production trust change, client authorization or live request is permitted by this tests-only branch.

## Source ancestry and file ownership

- Immutable base: WebSecurity source-owner PR #202 HEAD `0a6eb118de5153eb72115cc871122175b8d54dfd`. Its existing `src/lightup/webapp/security.py`, routing/session files, tests and workflows remain untouched.
- #919 public-origin identity files copied **byte-for-byte** from `03e81f7514f25fe2491d584779ed2594c2214749`:
  - `tests/test_scope_authorization_public_origin_identity.py`, original blob `1896265dd80b0bdee2dbb61ab31c2e7ec285b257`.
  - `docs/scope-authorization-public-origin-identity.md`, original blob `751d7bb042a102589cd13512e96e21f5af478c65`.
- #918 trusted-proxy identity files copied **byte-for-byte** from `a8adfcdb291c38b66a301cb9facd4da284825060`:
  - `tests/test_scope_authorization_trusted_proxy_identity.py`, original blob `bd4049f0d3d1f7d0726cdda103238c26300d3614`.
  - `docs/scope-authorization-trusted-proxy-identity.md`, original blob `bc9d17acaf4394c1eddc09992cab10d8740f098c`.
- This independent composition manifest is the sole new-original file. The branch must be **five newly added paths only**, zero existing files modified or removed and zero commits behind exact #202. No source-owner or other-worker branch is written to.

## Required execution boundary

All eight original unittest methods operate on synthetic in-memory `WebSecurity` configuration and a fictional request environment, without opening listeners or talking to any remote peer.

- **#918:** exact built-in `str` loopback `127.0.0.1` and `::1` remain accepted; `203.0.113.5` peer remains denied. A same-text `str` subclass and an equality-spoofing subclass that claims a remote address is loopback must be rejected at construction **before** request trust is established.
- **#919:** exact built-in HTTPS origin remains accepted and insecure HTTP remains rejected. A same-text `str` subclass and a stateful override of `lstrip` that changes the expected origin after configuration validation must be rejected before origin parsing/retention.
- No coercion of polymorphic configuration into a trusted canonical identity is allowed. Preserve all existing Host, Origin, forwarded-proxy and development peer boundaries from source-owner #202.

## Review/runner gate

Expected source REDs are **unfixed authorizer defects**, not regression success, and cannot be papered over with expected-failure decorators. The source owner of #202 must implement/review any runtime solution and then run the two source-RED contracts as normal PASS. Merely copying these original files does **not** execute them.

The issue requests branch-only work while shared permanent self-hosted LightUp capacity is occupied. Do not open a PR or retrigger permanent VPS CI just to run known REDs. Before any promotion the exact integrated HEAD needs original hosted Python3.11/3.14 evidence, genuinely assigned registered VPS `[self-hosted,zcloud,vps]`/hostname proof, independent security/privacy review, authentic customer and operator consent, durable revocation and explicit human GO. None is claimed here.

**No real proxy trust, network, listener, target, scan, handler, client grant, workflow modification, merge or deploy.**
