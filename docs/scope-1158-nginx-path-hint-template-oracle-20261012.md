# Issue #1158 — standalone offline Nginx path-hint denial oracle

**Status:** Incubate M3/M7, PLAN/LAB ONLY. DRAFT / HOLD / NO MERGE / NO DEPLOY. This is not an installed Nginx or Gunicorn test, not an authorization decision, and never sends traffic.

## Gap and independent ownership
[Issue #1158](https://github.com/Zennay/Lightup/issues/1158) requires that raw caller-supplied route hints cannot alter a real request's upstream path. The earlier [PR #1156](https://github.com/Zennay/Lightup/pull/1156) tests **WSGI PATH_INFO** with a real in-process app, but cannot prove that a deployed reverse proxy did not rewrite the request before WSGI. This isolated patch changes **only new tests/docs**. It deliberately does not modify PR #1156, #1155's ingress owner files, #1167's canonical path guard, #107's executor, main, or any concurrent worker branch.

## What this new test actually proves
`tests/test_scope_1158_nginx_path_hints_reference_20261012.py` provides a conservative pure-text preflight for an **example Nginx configuration**. To pass, the literal root `location /` must explicitly remove all seven route-hint headers using empty `proxy_set_header` statements:

`X-Original-URL`, `X-Rewrite-URL`, `X-Original-URI`, `X-Forwarded-URI`, `X-Forwarded-Path`, `X-Forwarded-Prefix`, `X-Script-Name`.

The tests exercise seven single-missing and seven attacker-forwarding variants, duplicate declarations, unknown routing include/rewrite/try_files/dynamic upstream controls, unchanged input and a clean fixture. The checked-in **main template** is deliberately an `@expectedFailure` canary because it does not yet explicitly strip these headers. A green suite can therefore still contain one XFAIL and **does not** mean ingress is safe. No configuration is modified or deployed by this test.

The W2 review now scans only the single literal root-location body, **not** server-level header declarations, because those can be shadowed by a location's own `proxy_set_header`. It requires the existing pinned literal lab upstream, refuses nested/unclosed root syntax, refuses duplicate root locations, and exercises server-level false positives plus case-insensitive header names. The header-gate unit suite has 11 methods including one deliberately expected-failure main-template canary; this remains non-authorizing.

This heuristic neither parses Nginx grammar completely nor verifies virtual server selection, nested locations, inherited proxy headers, third-party modules, header normalization, loaded configuration, proxy binary, Gunicorn parser, TLS, app authentication or route authorization. An ingress source owner must separately inspect those.

## Required independent promotion sequence
1. Assigned Nginx/ingress owner decides whether explicit header stripping is compatible and changes the actual **installed** config under separate ownership. Review all includes, maps, rewrites, module configuration, virtual hosts, location inheritance, other proxy hops and any reload/rollback.
2. In an isolated *loopback-only* disposable stack, pin config hash, Nginx/Gunicorn binary versions and full loaded modules. Feed actual raw HTTP header variants. Capture backend-observed **PATH_INFO** and routing result for unknown paths, conflicting hints and authenticated CSRF-valid synthetic POST non-write. Include authorized positive controls, cross-tenant and logout controls. No real customer/public target.
3. Keep stage-dependent proof separate: (a) exact test SHA, (b) GitHub-hosted Python 3.11/3.14 offline + producer suites, (c) registered permanent self-hosted VPS CI, (d) installed ingress experiment, (e) independent source/security/privacy and human release approval.
4. After an owner config repair, remove or replace the `@expectedFailure` canary with an unconditional passing check; until then issue #1158 stays OPEN and this PR stays DRAFT.

## Offline reproduce
```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1158_nginx_path_hints_reference_20261012.py' -v
```

No process launch, network, scanning, active authorization, grant issuance, customer data, target interaction, CI registration that implies VPS proof, source change, merge or deployment is performed by this artifact.
