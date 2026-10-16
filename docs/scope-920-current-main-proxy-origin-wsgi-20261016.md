# LightUp scope #920 — current-main transport identity acceptance

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a new, *separate*
tests/docs-only acceptance child of the CURRENT shared `main`, not the historic
#202 WebSecurity source-owner branch. It introduces no runtime fix or authority.

## Immutable ownership/lineage

- Base shared main `e73b7445c87ad239bdb03c50a99078ef93163b02`.
- Current-main `src/lightup/webapp/security.py` blob at this base:
  `ca657372e43a15f212b3b7c92605f9f29e055531`.
- Historical #202 owner HEAD `0a6eb118de5153eb72115cc871122175b8d54dfd`,
  diverged by **82 commits behind / 6 ahead** relative to current main when read.
- Independent [draft #1478](https://github.com/Zennay/Lightup/pull/1478)
  tests the exact historical #202 code (not current main). Its test paths,
  original sidecar branches #1255/#1256, #202 source and all other workers
  remain completely untouched.
- This branch adds only two *unique, new* paths:
  `tests/test_scope_920_current_main_proxy_origin_wsgi_20261016.py` and
  this document. No existing source, tests, CI, runners or workflows edited.

## Source-owner acceptance and non-authority

WebSecurity constructor must reject any non-exact builtin `str` object for
production `trusted_proxy_ip` and non-null `public_origin` before parsing
or storing; a proxy `str` subclass's overridden equality must not make a
different socket peer trusted.

**Sixteen genuine installed-source synthetic unit tests**:
- nine ordinary controls covering exact built-in IPv4/IPv6 identity,
  forwarded-header non-authority, independent host/HTTPS and POST Origin,
  actual WSGI anonymous login, and genuine builtin untrusted peer producing
  403/no-store *before* store use or POST body read, plus actual production
  `create_production_app` factory built-in canonical admission and bad
  built-in configuration rejection before any (mocked) store construction;
- seven deliberately OPEN original-source `unittest.expectedFailure` checks:
  reject subclass proxy at construction, reject subclass public origin at
  construction, reject subclass-equality spoof at actual `validate()`, and
  reject the same fictional request at actual installed WSGI `create_app()`,
  reject subclass proxy/origin inputs at the **real production factory**
  before constructing a domain store, and block the fictional request on
  WSGI created by the actual factory.

The real factory uses a fictional absolute database path and `Mock` DomainStore;
no file is created or opened. All tests use fictitious `.example.test` and documentation-only
`203.0.113.19`. No socket, DNS, customer, production target, model,
active scanning or tool/handler execution. Even a source RED in the WSGI
login route is *not* evidence of a login, privilege escalation or an
external exploit: it checks anonymous route admission only.

Run from exact checked-out commit:

```sh
PYTHONPATH=src python -m unittest discover -s tests \
  -p 'test_scope_920_current_main_proxy_origin_wsgi_20261016.py' -v
```

ExpectedFailures are **unresolved source defects**, not passing security
properties. Hosted CI green is not the authorization/release decision.
The original source owner #202 must independently implement the source fix,
reconcile with current-main changes including development peer checks,
and convert every source RED to ordinary PASS. Then require exact-head
Python3.11 and 3.14 suites, real producer integration, *registered permanent
VPS* CI on the exact head and hostname, installed proxy/TLS/ingress proof,
tenant checks, original client+operator consent and revocation, independent
security/privacy review, and explicit human GO.

This work must remain **DRAFT/HOLD**, with no merge, real-target activity,
grant issuance, permission widening, production deploy or release.

## Baseline CI independence (2026-10-16)

Initial [hosted preflight #38870179781](https://github.com/Zennay/Lightup/actions/runs/38870179781) for the initial 11-test exact head
`b9094867e14c532abbc2ff644f1cac0d4ee9c111` **FAILED on both Python versions**:
all 11 owned tests behaved as expected (7 ordinary PASS, 4 intentionally open
source expectedFailures), but the unrelated pre-existing
`test_scope_legacy_falsy_window_301_red_20261014.py::test_all_inputs_remain_unchanged_after_pure_scope_decision`
failed due an October 14 static fixture evaluated against the advancing
real current date. [Draft PR #1452](https://github.com/Zennay/Lightup/pull/1452)
is owned by the #301 worker and already provides its distinct clock-fixture
repair; neither the failing baseline test nor the owner's branch is touched
here. The initial full suite ran **1,248 tests with 27 expected failures and
one unrelated baseline failure** per Python; producer integrations were
skipped by GitHub Actions. This is **not a green hosted run** and cannot be
used as release evidence. The latest source SHA and fresh CI must be
verified separately. Do not copy #1452 edits into this branch or hide that
baseline failure.
