# IPv4-mapped IPv6 identity boundary (offline reference)

This isolated regression suite records that an IPv4 literal/CIDR allowlist must not silently become authority over the **different literal address family** `::ffff:a.b.c.d`. Synthetic `8.8.8.8` is a fixture string; no connection or resolver call occurs. The tests check current `ScopePolicy.decide` behavior only.

An explicit IPv6-mapped /128 CIDR with a synthetic `Authorization` exercises **legacy IP-network scope matching**, not persisted or trusted human consent. This does **not** permit real-target dispatch. A production executor must bind verified issuer, client, engagement, asset, capability, grant freshness and revocation before any I/O, including DNS and redirect hops; source owners of #107/#1128 retain that implementation.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_ipv4_mapped_ipv6_boundary_20261009.py' -v`

Release: **DRAFT/HOLD** pending exact-head hosted Python 3.11/3.14 + canonical permanent VPS proof, source-owner review and verified zero-handler-call pre-I/O gate. No production changes, real targets, scanning or grant issuance.

## Extended negative controls

The nine synthetic test methods now distinguish an IPv4 allowlist from an IPv4-mapped IPv6 /120 network, reject a neighboring mapped address outside that network, and require a grant for a mapped literal *inside* the network. Network matching remains necessary but never sufficient to authorize production dispatch. This suite does not validate effective socket destination identity after DNS resolution or platform IPv4-mapped socket handling; that is an independent pre-I/O production gate owned by #107/#1128.

## Positive/negative pair

Eleven methods now include an explicit **synthetic-only** in-prefix IPv4-mapped IPv6 acceptance control and an ordinary (unmapped) IPv6 noninheritance denial. This catches overbroad implementations that reject everything or incorrectly collapse IPv6 address families; a passing scope decision is not authorization to dispatch.

## Grant time-window negative controls

Thirteen offline test methods now include an expired authorization (`valid_until` in 2000) and a future-dated authorization (`valid_from` in 2099) against an explicitly listed mapped-IPv6 `/128`. Both must fail with `AUTHORIZATION_EXPIRED`. Fixed timestamps avoid wall-clock edge flakiness while testing the legacy scope gate. These fixtures do not confer persisted, issuer-verified consent.

## CI-driven fixture repair

Hosted unit CI on prior HEAD `fe576bd` rejected the unmapped-IPv6 fixture because `2001:db8::1` is non-global under Python `ipaddress`, so the policy's intentional `allow_private_lab=True` shortcut applied. The negative control now uses a globally routed IPv6 literal `2606:4700:4700::1111` **as a parser-only fixture**; no connection, DNS query or target interaction is performed. This change tests only public-network allowlist inheritance, not private lab policy.

## Equivalent IPv6 literal notation

Fifteen offline cases now include the expanded spelling `0:0:0:0:0:ffff:808:808` of the same mapped address, asserting it matches the exact `/128` network only when the synthetic grant is present. This prevents bypass through address-text formatting and does not grant any network activity. The trust-boundary check remains a separate production requirement.

## Case-normalization control

Seventeen offline regression methods now include the uppercase `::FFFF:808:808` literal, which must have the same `/128` network identity and missing-grant denial as its lowercase equivalent. This is a parser/scope-only test, not a trusted authorization grant or target operation.

## Network-free positive scope decision

Eighteen offline methods now also assert that even an explicitly allowed mapped-IPv6 `/128` scope decision with a synthetic test grant never invokes `socket.create_connection` or `socket.getaddrinfo`. Both socket entrypoints are patched to raise. This is deliberately a **scope-parser** invariant only: real production dispatch must independently enforce verified consent, authorization freshness and destination binding before I/O.

## CI acceptance checkpoint

Do not infer green validation from predecessor commits: the previous `e20413f` hosted and VPS runs were cancelled, while `ba96584` runs were pending/queued at inspection. Freeze the final tested SHA for exact-head hosted Python 3.11/3.14 plus permanent VPS success and source-owner approval. Keep this draft on HOLD until those proofs exist; avoid unnecessary retriggers or merges.
