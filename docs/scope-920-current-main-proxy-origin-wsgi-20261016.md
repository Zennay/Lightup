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
- This branch adds only four *unique, new* paths:
  `tests/test_scope_920_current_main_proxy_origin_wsgi_20261016.py`,
  `tests/test_scope_920_runner_provenance_20261016.py`,
  `scripts/check_scope_920_current_main_acceptance_20261016.py`, and
  this document. No existing source, tests, CI, runners or workflows edited.

## Source-owner acceptance and non-authority

WebSecurity constructor must reject any non-exact builtin `str` object for
production `trusted_proxy_ip` and non-null `public_origin` before parsing
or storing; a proxy `str` subclass's overridden equality must not make a
different socket peer trusted.

**Twenty genuine installed-source synthetic unit tests**:
- eleven ordinary controls covering exact built-in IPv4/IPv6 identity,
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

It runs **exactly 20 owned tests**, insists on **exactly nine intentionally
open source REDs**, no other skip/error/unexpectedSuccess, and prints a
minimal JSON receipt with explicit literal `false` for source-fix,
release, merge, scan, dispatch, registered VPS, full-suite and consent
authority. Exit 0 means **only these 20 tests ran as designed**, not
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
standalone 20-case tool is a **narrow diagnostic**, not current VPS authority.

## W5: repair-ready source REDs and strict isolated reference mutation (2026-10-16)

Five downstream `expectedFailure` regression methods previously demanded
WSGI/request denial *only after* a malicious proxy configuration was
constructed. That was an invalid repair oracle: implementing the superior
**constructor-time ValueError** would cause those old test methods to error
rather than pass. Those five methods now accept **either** fail-closed
constructor admission (preferred, including before mocked DomainStore) **or**
an actual `RequestRejected`/403 during in-process request verification.
Both denial paths are required to be explicit and cannot be replaced with an
unexamined exception, a skip, or a suppressed assertion. On the unchanged
current-main source, they remain deliberately failing regressions.

Added **one ordinary non-authorizing acceptance mutation witness**:
`test_test_local_constructor_reference_clears_all_nine_source_reds`.
Inside a `unittest.mock.patch.object(WebSecurity, "__post_init__", ...)`
context **only**, it adds two exact built-in string type checks *before* the
original constructor logic, then directly runs all nine original RED method
bodies; each must become ordinary PASS. Canonical IPv4/IPv6 production
constructors/requests must remain accepted. The patch is guaranteed to be
removed by the context manager and does not change any production source,
app state, other worker branch, runner, permissions or real requests.
This is a **local reference/acceptance proof**, not an integrated fix,
release permission or demonstration of real network exploitability.

The bounded opt-in runner now checks **20 methods: 11 ordinary controls +
9 intentionally OPEN source REDs**, rejects skips/errors/unexpected success,
and emits `REVIEW_ONLY` at best; all release/scan/grant/VPS/full-suite
flags remain explicitly false. The prior W4 [hosted run #38871511511](https://github.com/Zennay/Lightup/actions/runs/38871511511)
was FAILED due the separate #301 expired fixture (19 owned cases behaved
10 ordinary OK/9 expected RED). **It predates this change**; do not claim
exact-head green until new job logs have been verified. Current-main full
suite remains pending owner #1452's already drafted clock correction.

## W6: immutable local source fingerprint and independent fail-closed CLI QA

The **opt-in standalone 20/9 runner** now checks the exact *Git blob ID* of
`src/lightup/webapp/security.py` in its checkout **before even discovering
unit tests**. Expected original current-main source blob:
`ca657372e43a15f212b3b7c92605f9f29e055531`. Git framing is computed
in-memory as `SHA1(b"blob " + size + NUL + content)`; this deliberately
matches the already pinned GitHub blob, without a git subprocess, network,
customer files or external source access. A missing file, symlinked source,
oversized file, unreadable file or ANY changed source bytes causes immediate
`HOLD` and nonzero exit; the script never claims authority from its own
plain-text receipt. It does not and cannot validate the *entire* branch,
runner identity or cryptographic build provenance. On eventual source-owner
repair the old exact-blob guard will deliberately require review/update.

A new separate test-only module
`tests/test_scope_920_runner_provenance_20261016.py` adds **six ordinary
controls** for exact known Git blob encoding (`hello` and `hello\\n`),
current source pin, a full real in-process invocation of the narrow
20/9 script requiring `REVIEW_ONLY` with every authority flag false,
altered fictitious local source, missing fictitious local
source, and early `HOLD` without running tests or granting release/merge/
scan/dispatch/VPS/full-suite/consent flags. The altered-source fixtures use
`tempfile.TemporaryDirectory` and contain only synthetic bytes, no real
assets or client data.

These six checks are part of regular GitHub hosted unit tests, **not** the
standalone command's exactly 20 scope-source regression methods; the narrow
command deliberately cannot mark the rest of LightUp's full suite green.
Do not claim these W6 changes are tested on a specific head until its actual
hosted original job logs have been reviewed. The unrelated #301 frozen-clock
fixture remains an independent ordinary full-suite FAIL owned by draft #1452;
permanent VPS #1144 still requires real runner execution. **DRAFT/HOLD**.

## W7: exercise the actual narrow runner inside hosted unit CI

`test_real_offline_runner_executes_all_twenty_but_never_releases` calls the
actual `acceptance.main()` in-process while capturing stdout/stderr. It
requires exit code 0, `status=REVIEW_ONLY`, **exactly 20 actual installed-source
method runs and 9 still OPEN expected source REDs**, and literal false for
`source_fixed`, `release_authorized`, `merge_authorized`, `scan_authorized`,
`dispatch_authorized`, `registered_vps_verified`, `full_suite_verified`,
and `client_operator_consent_verified`. It does not start a child process,
network client, real engagement, or tool handler. The test is a **normal
ordinary CI method** separate from the narrowly discovered 20. This is a
real hosted execution of the runner function, **not** evidence that the
standalone command was executed on a registered permanent VPS or that the
full suite's unrelated #301 failure is resolved.

Verify the latest exact-head hosted job logs before calling this `ok`.

## W8: acceptance-test integrity and explicit failure-state oracle (2026-10-16)

The offline, **non-authorizing** `scripts/check_scope_920_current_main_acceptance_20261016.py`
now checks **two separate fixed Git blob identities BEFORE test discovery**:
(1) original current-main installed `src/lightup/webapp/security.py`
`ca657372e43a15f212b3b7c92605f9f29e055531`, and (2) **this branch's
owned 20-method acceptance test module** `tests/test_scope_920_current_main_proxy_origin_wsgi_20261016.py`
`ae63a85546e970a19a9f44489732b45a70448811`.
Both must be regular readable files, within bounded size, not symlinks and
exact-byte Git blobs. A changed test suite that artificially returns 20
success-looking tests and nine expected failures can no longer silently
inherit the old REVIEW_ONLY result without a deliberate reviewed blob-pin
update. This is a local integrity guard, **not signed provenance** or a
substitute for immutable GitHub Action commit identity, permanent registered
VPS, consent or independent release approval.

The independent `tests/test_scope_920_runner_provenance_20261016.py` suite
includes standalone actual-source pin, actual-test pin, changed-test bytes,
missing/symlinked-test source, incorrect test count (proves no runner call),
and **eight synthetic result permutations**: unexpected success, skip,
ordinary failure, runtime exception, missing/extra expected source RED,
incorrect testsRun, or self-reported unsuccessful status. All must yield
`HOLD`/exit 2 with authority flags false; no network or real target is
involved. The narrow runner checks `failures` and `errors` explicitly,
in addition to the genuine `unittest` `wasSuccessful()` result, to avoid
accepting an internally inconsistent synthetic result.

**Ownership:** only the preexisting four NEW paths of our isolated draft
#1479 are modified, with no source/runner/workflow changes. These acceptance
and result tests do not touch #202 original source, #1452 frozen-date fixture,
#1144 permanent VPS operator or other #920 sibling branches. Current-main
full-suite remains blocked by the separate #301 fixed-clock baseline issue;
a targeted REVIEW_ONLY receipt must never be represented as full-suite green.

## W9: loaded Python WebSecurity module origin cannot drift (2026-10-16)

The CLI validates not only the immutable SHA-1 Git blobs of the **installed
WebSecurity source** and **owned #920 test module**, but also the *runtime
module origin after test discovery and before test execution*:
`sys.modules["lightup.webapp.security"].__file__` must resolve to the
expected `ROOT/src/lightup/webapp/security.py` in the current checkout.
An unimported module, a non-string `__file__`, a missing path, or a path
pointing to another repository checkout is `HOLD`/exit 2. This prevents a
previously imported local copy from silently passing the narrowly pinned
test runner; it does **not** cryptographically attest runtime memory or the
host and cannot replace registered VPS CI/release gates.

Three new ordinary test-only controls in
`tests/test_scope_920_runner_provenance_20261016.py` exercise the real
module-origin positive, a synthetic swapped/absent `sys.modules` entry,
and a run with matching synthetic test count but mismatched module origin
that must reject **before calling TextTestRunner.run()**. The existing
synthetic outcome matrix explicitly patches *only* the module-origin guard
to retain an isolated failure-result oracle. A real in-process CLI run on
the pinned checkout must still yield at most `REVIEW_ONLY` and all authority
flags false. New exact-head hosted jobs are required before claiming these
new tests PASS. The full LightUp suite still has the unrelated #301 clock
fixture failure owned by draft #1452, and permanent runner evidence remains
separately required under #1144. No original runtime/other-worker edits.

## W10: post-execution integrity recheck and real-suite drift witnesses

On a nominally passing **20-method** synthetic in-process acceptance suite,
`scripts/check_scope_920_current_main_acceptance_20261016.py` now repeats
**all three acceptance gates AFTER test execution** and before printing
`REVIEW_ONLY`: source Git blob, owned tests Git blob, and actual imported
`lightup.webapp.security.__file__` checkout path. The early guards remain.
A changed file/module identity during the window yields `HOLD`/nonzero even
if all 20 test methods reported ordinary PASS/intentional source RED as
expected. This is a bounded in-process integrity check, not signed build
provenance, permanent VPS attestation, permission to deploy, or a runtime fix.

New independent `test_real_suite_cannot_issue_review_only_after_input_swaps`
in the runner QA suite runs **all 20 actual installed-source methods three
times** on genuine pinned source while independently simulating a single
late change to (a) source blob, (b) test blob, or (c) imported module origin
via test-only `unittest.mock.patch.object(..., side_effect=[True, False])`.
Every run must exit 2 with `HOLD`, preserve 20-method/9-RED counts and keep
all release/full-suite/VPS flags false. No actual file is changed; no socket,
external target, customer data, authentication or security tool is invoked.
The test helper monkeypatches disappear upon exit. The exact new-head hosted
logs must independently verify this test's PASS before citing results.

Previously pinned head `52fda7aa350af24430381890c6b5e6a1e3b346e6`
[hosted #38874274435](https://github.com/Zennay/Lightup/actions/runs/38874274435)
**COMPLETED FAILURE**. Both original Python3.11 / 3.14 logs confirm all
**14** own runner QA ordinary PASS and all **20** source acceptance tests
run, with **9** deliberate source expectedFailures. Full suite **1,271
tests per interpreter / 32 intentionally still open source REDs / exactly
one unrelated baseline #301 frozen-date test ordinary FAIL**. Producer
integrations skipped. These prior logs predate this post-execution recheck.
