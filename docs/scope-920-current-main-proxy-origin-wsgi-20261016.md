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
- This branch adds only three *unique, new* paths:
  `tests/test_scope_920_current_main_proxy_origin_wsgi_20261016.py`,
  `scripts/check_scope_920_current_main_acceptance_20261016.py`, and
  this document. No existing source, tests, CI, runners or workflows edited.

## Source-owner acceptance and non-authority

WebSecurity constructor must reject any non-exact builtin `str` object for
production `trusted_proxy_ip` and non-null `public_origin` before parsing
or storing; a proxy `str` subclass's overridden equality must not make a
different socket peer trusted.

**Nineteen genuine installed-source synthetic unit tests**:
- ten ordinary controls covering exact built-in IPv4/IPv6 identity,
  forwarded-header non-authority, independent host/HTTPS and POST Origin,
  actual WSGI anonymous login, and genuine builtin untrusted peer producing
  403/no-store *before* store use or POST body read, plus actual production
  `create_production_app` factory built-in canonical admission and bad
  built-in configuration rejection before any (mocked) store construction;
- nine deliberately OPEN original-source `unittest.expectedFailure` checks:
  reject subclass proxy at construction, reject subclass public origin at
  construction, reject subclass-equality spoof at actual `validate()`, and
  reject the same fictional request at actual installed WSGI `create_app()`,
  reject subclass proxy/origin inputs at the **real production factory**
  before constructing a domain store, and block the fictional request on
  WSGI created by the actual factory. Two additional new source REDs
  require a configured production gate and real production-factory WSGI
  to reject a **missing** `REMOTE_ADDR` even when a fictional untrusted
  proxy `str` subclass claims arbitrary values are equal. A new ordinary
  WSGI control proves missing peer is rejected by canonical builtin config.

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

The opt-in, **independent targeted** diagnostic runner is:

```sh
python scripts/check_scope_920_current_main_acceptance_20261016.py
```

It runs **exactly 19 owned tests**, insists on **exactly nine intentionally
open source REDs**, no other skip/error/unexpectedSuccess, and prints a
minimal JSON receipt with explicit literal `false` for source-fix,
release, merge, scan, dispatch, registered VPS, full-suite and consent
authority. Exit 0 means **only these 19 tests ran as designed**, not
"all LightUp tests green" and never release authorization. If any case
changes it fails with a HOLD receipt. The tool cannot replace exact-head
GitHub job logs or the queued permanent VPS CI; only run it on trusted
exact checked-out code and do not accept self-declared receipts as
cryptographic provenance.

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

## W2 exact-head hosted result, unrelated original baseline failure

[Hosted #38870507591](https://github.com/Zennay/Lightup/actions/runs/38870507591)
completed **FAILURE on both Python 3.11 and 3.14**, immutable head
`195c153ac5ecf4f57134a85bb40e7638de237bbc`. All **16 own methods**
logged as designed (9 `ok`, 7 `expected failure`). Both unit jobs:
**1,253 tests, 30 intentional expected failures, one unrelated existing #301
frozen-date test FAIL**. Producer integrations **SKIPPED**. The full suite
remains red until the distinct #301 owner safely integrates [PR #1452](https://github.com/Zennay/Lightup/pull/1452).
Permanent VPS [#38870507522](https://github.com/Zennay/Lightup/actions/runs/38870507522)
was queued with two jobs unassigned, not proof of real runner execution.
The opt-in standalone 16-case command above is a narrow diagnostic **not a
workaround for full-suite certification or permission to release**.

## W4 current-main missing-peer trust boundary (2026-10-16)

New tests require the production peer to be **present and exact** before
any anonymous WSGI dispatch. The original `WebSecurity._validate` compares
`environ.get("REMOTE_ADDR") != self.trusted_proxy_ip`: a caller-owned
`str` subclass can override equality such that **missing**
`REMOTE_ADDR` (the `None` returned by `get`) compares equal to the stored
proxy identity. One ordinary WSGI test uses an exact builtin proxy and
requires 403/no-store/no-store access for missing peer; two **intentional
source REDs** test the original `validate` and the actual production factory's
WSGI path against a fictional always-equal proxy config object. They test
only synthetic in-process metadata; never an external request or exploit.

The latest W4 head is separate from W3 and previous hosted jobs. Re-run
immutable-current-head jobs for this change and require **10 ordinary PASS +
9 deliberate source expectedFailures**. Current-main baseline #301 remains
independently red; do not suppress that or claim full suite green. The
standalone 19-case tool is a **narrow diagnostic**, not current VPS authority.
