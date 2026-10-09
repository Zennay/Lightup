# IPv4-mapped IPv6 identity boundary (offline reference)

This isolated regression suite records that an IPv4 literal/CIDR allowlist must not silently become authority over the **different literal address family** `::ffff:a.b.c.d`. Synthetic `8.8.8.8` is a fixture string; no connection or resolver call occurs. The tests check current `ScopePolicy.decide` behavior only.

An explicit IPv6-mapped /128 CIDR with a synthetic `Authorization` exercises **legacy IP-network scope matching**, not persisted or trusted human consent. This does **not** permit real-target dispatch. A production executor must bind verified issuer, client, engagement, asset, capability, grant freshness and revocation before any I/O, including DNS and redirect hops; source owners of #107/#1128 retain that implementation.

Run: `PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_ipv4_mapped_ipv6_boundary_20261009.py' -v`

Release: **DRAFT/HOLD** pending exact-head hosted Python 3.11/3.14 + canonical permanent VPS proof, source-owner review and verified zero-handler-call pre-I/O gate. No production changes, real targets, scanning or grant issuance.
