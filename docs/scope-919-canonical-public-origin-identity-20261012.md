# Scope #919 — canonical production public-origin identity (offline test-only)

## Ownership and environment

- Parent issue: [#919](https://github.com/Zennay/Lightup/issues/919).
- Production transport/security source owner: [PR #202](https://github.com/Zennay/Lightup/pull/202), which retains `src/lightup/webapp/security.py`.
- Related but separate proxy-identity owner: [#918](https://github.com/Zennay/Lightup/issues/918).
- Baseline `main`: `05b80319cd0581fed21fe9d8f565bcb0a56cd2df` on 2026-10-12.
- Change set: **new isolated test file and documentation only**. No production `WebSecurity`, app, proxy, sessions, grants, executor, default factory, main or other workers changed.

## What this tests

The exact real `WebSecurity` constructor accepts a `public_origin` value, calls `origin()` at construction, and currently parses that stored object again during `validate()`. The root contract requires a **built-in `str` exactly** for non-null production origin, before any parsing, so a polymorphic `str` subclass cannot switch trusted host between constructor and request.

`tests/test_scope_919_public_origin_identity_20261012.py` provides:

1. **Two deliberate `@expectedFailure` production canaries**: same-text `str` subclass accepted at construction and stateful `lstrip()` substitution when origin is reparsed on a later real `WebSecurity.validate` invocation. A passing XFAIL suite **does not mean this weakness is repaired**.
2. Green positive controls using built-in strings: exact HTTPS origin, case/default-port equivalence, required proxy identity and HTTPS transport.
3. Green negatives for different Host, forwarded-host spoofing, malformed/non-string config, foreign POST Origin despite a good Referer, sanitized denial reason, and development host boundary.
4. In-process **actual LightUp WSGI** denial proof: foreign host returns 403 / no-store before mocked session store or request-body read.

All hosts are reserved `.test` values; no listener, socket, DNS, HTTP clients, real target, client data, grants, scan, or remediation.

## Local laboratory command (not a claim of execution)

```bash
PYTHONPATH=src python -m unittest -v tests.test_scope_919_public_origin_identity_20261012
```

Run full project offline and producer suites on Python 3.11 and 3.14, pin each job to **this PR's exact final commit**, and separately check registered permanent self-hosted VPS LightUp CI. GitHub-hosted green alone is not the required VPS acceptance. A deliberate XFAIL is outstanding negative proof, not release readiness.

## Production remediation contract — handoff to existing owner

- Validate `type(public_origin) is str` before invoking `origin`, `urlsplit`, or any inherited overridable string methods. Reject string subclasses (including same-value subclasses).
- Freeze the admitted canonical expected origin as immutable trusted configuration; do not reparse a caller-controlled behavioral object on every request. Review immutable config binding and constructor/dispatch lifetime races.
- Independently enforce `trusted_proxy_ip` exact-value identity and network peer checks under #918. Do **not** conflate a matching Host/Origin with an authorization grant.
- Integrate production changes only through #202's source owner. Convert both XFAIL canaries to ordinary passing assertions only once the exact executable source actually enforces the gate, then test against the real production WSGI factory, trusted-proxy/Host/Origin/Referer paths, and replay/role/tenant boundaries.
- Security/privacy review, latest-main composition, exact final-head registered **permanent** VPS evidence and explicit human release authorization remain required. Do not merge/deploy this DRAFT reference in lieu of a fix.

**Status: Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY. Keep #919 OPEN.**
