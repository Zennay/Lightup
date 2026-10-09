# HTTP cache metadata is non-authoritative for scope authorization

This **offline synthetic reference**, not an implementation of trusted grants,
makes HTTP caching a non-authority boundary. A cached success response, a
`304 Not Modified`, `ETag`, `Age`, `Cache-Control`, CDN copy, or cached
approval page cannot create, extend, refresh or restore consent. Even when an
HTTP cache entry is fresh, current issuer-controlled state and separate
authenticated reviewer/operator approval remain mandatory.

## Required production integration contract

1. Load a verified, issuer-owned live grant at every admission and dispatch.
2. Bind tenant, request, grant revision, exact capability and purpose to the
   authenticated principal and target authorization record.
3. Revalidate revocation, expiry, approval, policy/risk limits and any
   authorization epoch at dispatch time; fail closed if source is unavailable.
4. Do not accept HTTP cache metadata, cached positive decisions, UI badges,
   proxy headers or previously exported policy documents as proof of authority.
5. Keep authorization responses `no-store` where appropriate, but **do not**
   treat cache headers themselves as a security control; check live authority.
6. Independently validate provenance and signatures where applicable. This
   reference's matching values are necessary conditions, never permission.

## Isolation and proof

The companion `tests/test_scope_http_cache_nonauthority_reference.py` contains 17\noffline regression methods, including missing-grant, missing-dispatch, forged dispatch\nmalformed revision denials, matching invalid controls in identities,\nand strict lexical checks across every bound identity field. It uses only
Python stdlib and synthetic fixtures, with no sockets, DNS, scanners,
credentials, targets, production executor changes or grant activation.

Run `python -m unittest discover -s tests -p 'test_scope_http_cache_nonauthority_reference.py' -v`.
A local or hosted unit result cannot prove live authorization or real-target
safety. Keep this contribution draft until exact-head Python 3.11/3.14 and
permanent VPS checks plus production gate owner review. Real-target
activation stays disabled.
