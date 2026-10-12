# Scope #1112 — actual WSGI Accept-Language non-authority acceptance (2026-10-12)

## Status
**M3/M7 Incubate / PLAN-LAB ONLY — DRAFT / HOLD / NO MERGE / NO DEPLOY.**

Independent implementation evidence for [open issue #1112](https://github.com/Zennay/Lightup/issues/1112). Earlier [draft PR #1113](https://github.com/Zennay/Lightup/pull/1113) covers only a synthetic pure-predicate reference. This isolated follow-up instead exercises the actual default `LightUpWebApp.__call__` entry point, its `WebSecurity.validate`, `_authenticate`, `_dispatch`, existing `DomainStore` sessions and tenant access in-process against disposable SQLite. No modifications to those source owners.

## Acceptance invariant

For a fixed, otherwise identical request, changing or adding client-supplied `HTTP_ACCEPT_LANGUAGE` must not change the status, response bytes or headers of a real WSGI route, nor create or destroy persisted sessions or tenant data. Header values used: absent, standard language ranges, weighted and wildcard language ranges, empty strings, misleading role/path strings, CRLF attempts, embedded NUL and a large uninterpreted header. They are synthetic WSGI-environ strings, **not** requests emitted onto the network.

Tests compare baseline vs every input for:
1. Anonymous denial on operator/client routes;
2. Client cannot promote to operator;
3. Client cannot read another tenant;
4. Real authorized tenant session and operator access remain functional;
5. Absent/bad CSRF cannot be replaced by language metadata;
6. Client CSRF cannot authorize operator-only mutations;
7. Revoked or forged session cookies cannot be reinstated;
8. Bad Host is not rehabilitated by language;
9. Session identities and tenant count remain unchanged by GET.
10. Legitimate operator CSRF-protected client creation remains functional for each language input and mutates only disposable SQLite;
11. Valid logout revokes the correct temporary token regardless of locale while unrelated client sessions survive.

The suite contains **14 actual unittest methods**. Normal logged-in `GET /login` is expected to redirect with `303 See Other`; this must not be confused with a denial or a locale influence.

## Reproduce

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_accept_language_real_wsgi_20261012.py' -v
```

All fixtures use `tempfile.TemporaryDirectory`, in-process stdlib WSGI and disposable SQLite, and cause **no network I/O**. Tests exercise web login/portal/CSRF **without** active assessment, grant creation, tools, scanning, target I/O, or live clients. Host `external.example.invalid` is an intentionally invalid **header string** only.

## Evidence limitations

This is a narrow current-default WSGI acceptance, not a production ingress/Nginx proof. It does not show an authorization grant is valid or binds issuer, tenant, asset, capability, risk, time or revocation at the target I/O boundary; it must not imply actual permission to scan. WSGI `HTTP_ACCEPT_LANGUAGE` does not model every possible upstream proxy normalization or physical HTTP parsing ambiguity.

Keep independent:
- source-owner review and existing PR #1113;
- exact-head hosted Python 3.11/3.14 runs;
- separate registered permanent LightUp VPS runner on the same immutable head;
- privacy/security and installed ingress review;
- latest-main compatibility and explicit human release approval.

A green hosted test or this document alone does **not** authorize merge or deploy.

## W4 — production-factory in-process WSGI acceptance

Additional strictly **tests-only** file:
\`tests/test_scope_1112_production_wsgi_language_20261012.py\`

This instantiates \`create_production_app\` using a disposable SQLite database and *synthetic* HTTPS origin \`https://lightup.example.test\`. Production \`WebSecurity\`, cookie issuance and revocation, tenant identity, form/CSRF processing, Host, trusted-proxy peer, and Origin restrictions are exercised through the **actual** in-process WSGI callable. No Gunicorn, Nginx, HTTP listener, DNS, sockets, real external requests, or customer state.

The production matrix contains 19 independently named unittest methods over 14 synthetic \`Accept-Language\` header values (including missing, empty, weighted and wildcard locales, attempted path/role names, CRLF, NUL and 8,192-character text). It checks:
- exact status, headers **and body** invariance on anonymous/operator/client and foreign-tenant GETs;
- denial invariance on missing or forged CSRF, client-only CSRF, forged/revoked cookies, invalid peer/Host/Origin;
- authorized tenant/operator GET and proper signed-in login redirect are not spuriously denied;
- production \`Secure\` cookie/HSTS/no-store/nosniff and absence of injected response headers;
- positive server-side operator POST writes under each locale (disposable SQLite only), valid login issuing session cookies, and logout revoking **only** the proper token;
- no mutations on denied foreign-tenant/client-privilege paths.

Run the new slice independently:
\`\`\`sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1112_production_wsgi_language_20261012.py' -v
\`\`\`

The test does **not** prove that a real reverse proxy or HTTP server always passes headers safely as synthetic WSGI strings, nor does it prove the grant-resolution, durable issuer/asset/risk/time/revocation, per-I/O execution, or live target safety boundaries. Upstream normalization is an independent owner gate. Never describe hosted CI as permanent VPS acceptance. **DRAFT/HOLD/NO MERGE/NO DEPLOY.**
