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
