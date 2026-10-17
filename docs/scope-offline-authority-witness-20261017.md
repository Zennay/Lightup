# #1565 — Canonical scope-decision offline witness (DRAFT/HOLD)

## Purpose and ownership

This is an **independent offline diagnostic** on the immutable base `e73b7445c87ad239bdb03c50a99078ef93163b02`. It reads the current checkout's real `ScopePolicy.decide()` and `ScopeDecision` but never modifies the scope evaluator or auth state. New files are limited to the `scope_offline_authority_witness_20261017` script/test and this doc. Active owner branches and PRs (including #1564, #1538, #1486 and #346) are not rewritten.

LightUp remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. The witness is neither customer consent nor operator signoff nor authorization of any asset. Its `REVIEW_ONLY` is *not* a GitHub merge-go, grant, execution, security-review, deployment or release verdict.

## Execute locally in a disposable checkout

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s tests -p test_scope_offline_authority_witness_20261017.py -v
PYTHONDONTWRITEBYTECODE=1 python3 scripts/scope_offline_authority_witness_20261017.py --offline-lab-only
```

On an installed canonical evaluator that matches the fixed matrix, the CLI emits exactly one sorted ASCII JSON object:
- `schema=lightup.scope-offline-decision-witness.v1`
- `status=REVIEW_ONLY`, `reason=canonical_synthetic_matrix_matches`, `checked=17`, two independently pinned SHA-256 digests for exact fictional fixture inputs and ordered observed synthetic classifications
- `client_consent_verified`, `operator_consent_verified`, `authorization_granted`, `dispatch_allowed`, `scan_allowed`, `deployment_allowed` and `release_allowed`: exact JSON `false`
- exit status **3**, never 0.

With missing/malformed opt-in, a changed decision (allow, reason, host), bad shape/schema or evaluation exception, the result is `HOLD`, with a generic failure reason, seven false authority flags, no matrix hash, and exit status **2**. No input/exception text, URL, IP or consent reference is emitted.

## Real test surface

The fixed **17-case** in-memory matrix uses loopback IP/hostname, private lab IP (allowed and lab-disabled), out-of-scope public IP, a synthetically allowlisted `.example.test` hostname with and without a **fictional, unsourced** `Authorization`, explicit public CIDR with and without that same fictional object, an expiration and not-yet-current date contract, an explicit policy that deliberately disables public authorization requirements (classification only, not a live permit), removed host/CIDR allowlists, and blank-target denial.

This is a deterministic **behavior witness**, not a proof that the policy is secure for all targets. Canonical examples with a synthetic authorization show existing `ScopePolicy` semantics in an **offline unit invocation only**. They do not create grants or prove that an actual human approved any asset. No DNS, socket, HTTP, scan, subprocess handler, credentials, database, production data or target-capable runner step occurs in the witness itself. The subprocess regression launches only another Python process running the same offline witness.

## Verified execution (17 October 2026)

On the connected authorized zSSH host, a dedicated disposable checkout at exact source head `d30a1e2e9deeacb4ba72c98a23b728488628d057` passed **16/16 dedicated unittest methods** on Python 3.14.4. Negative mutation controls rejected incorrect allow/host/reason/boolean return values, bad opt-in, identity-spoofing objects and evaluator crashes without yielding authority. The live CLI control produced `REVIEW_ONLY/3`, while the no-opt-in control produced `HOLD/2`, both with seven hard-coded `false` authority flags. Git status was clean; no other workers' paths were edited.

The earlier, same-branch full original unit suite on head `705b525ec485f5779ad9a2846e10e036ccb7039d` ran 1,251 tests and returned **5 FAIL, 23 expected failures**. Failures included pre-existing #301 date-fixture and #1535 registry-history issues; other failures are not independently baseline-proven. This **does not** constitute full-project green or release evidence. The new two polymorphism tests added afterwards have dedicated green proof, not a new full-suite result.

## Independent original-main regression comparison

On the connected zSSH VPS, two separate clean, isolated checkouts were used for the same original RED tests: untouched main `e73b7445c87ad239bdb03c50a99078ef93163b02` and this branch at `cea9050c9f85fe41aa7db45f088a51aa6c692741`. The **same five precise failing subtests** occurred in both, across 34 top-level unittest methods:

- `test_scope_composed_native_offline_cli_20261014.py`: 3 unittest methods; two fail because registry-history CLI returns 92 instead of 2/3.
- `test_scope_legacy_falsy_window_301_red_20261014.py`: 19 methods; one time-fixture assertion fails on both heads.
- `test_scope_offline_cli_socket_fleet_20261014.py`: 12 methods; two registry-history CLI subprocess cases return 92 instead of 2/3.

This directly reproduces pre-existing defects for those exact failing testcases; it is **not** a claim of a complete original-main full-suite pass or a source-owner repair. Own new witness remains **16/16 PASS**. No extra named LightUp self-hosted runner workflow was started.

## W3 — pinned two-layer matrix and expiry witness (17 October 2026)

- Exact synthetic fixtures increased **11 → 17** with expired/not-yet-current UTC approval, expired CIDR approval, a public-host policy-without-auth counterexample, removed CIDR, and loopback despite disabled private lab. Both dates are fixed at **2000-01-01** and **2100-01-01 UTC** to keep the reference stable across present-day runs.
- The helper now validates the *complete* exact-type in-memory fixture set before the first policy call. Bounded target strings, labels, allowed host/CIDR containers, exact UTC datetime instances and exact expected-result metadata are required; malformed input returns `HOLD` before the real `ScopePolicy.decide()` method runs.
- The canonical fixture representation (including synthetic authorization provenance, dates and policy settings) has its own pinned SHA-256: `b7f7d7595f7afc56605410fc3dce434da8ff2bad6900672a9890cc3cc176071a`. The independent ordered observed-result hash is pinned to `075c7598f4a01809cd19ef8a02d9380a2bdbde01e2a22fd8dfc940475386dcb1`.
- Wrong type/schema or unrecognized status = `HOLD`. Input/reference fixture drift, including a change to a semantically equivalent hostname or a fictional reviewer ID, = `HOLD/reference_fixture_drift` **before policy execution**. If allowed/reason/host changes, `HOLD/scope_policy_contract_drift`. If the observed digest differs, `HOLD/reference_behavior_drift`. Neither HOLD prints fixture contents, customer details or hashes.
- The two hashes are plain local drift fingerprints, **not digital signatures, chain-of-custody, source authenticity, user consent, security clearance or execution permission**. They can be changed by a source writer; Git history/reviews and real independent approval remain separate prerequisites.
- **23/23 focused Python3.14.4 tests PASS** on authorized zSSH, exact intermediate branch `b94c5b992b120839d0d764ef68735f957a427531`: both CLI exits, malformed and polymorphic cases, date spoofing, expired-authorization policy mutation, semantic-input tamper detected before calling the policy, order/provenance tamper, pinned reference-output downgrade and always-false authority flags.
- This is an *unwired offline diagnostic*, with no added target action or production authorization path. Existing #301 and #1535 source/fixture owners remain untouched; do not mistake a witness PASS for project-wide test green.

## W4 — Python I/O denial during installed-scope evaluation (17 October 2026)

**New runtime fence:** the offline witness installs a context-local Python audit hook that is active **only while** the installed `ScopePolicy.decide()` method runs. During that call, common Python audit events for sockets/DNS/network, file opens, child processes, OS fork/exec/spawn/system, and native-library loads are denied by raising `PermissionError`. The generic catch turns such an attempt into `HOLD/offline_witness_evaluation_failed` without printing audit arguments. The guard resets in `finally`, including after exceptions.

This is **not a security sandbox** and cannot stop every possible native/OS-level I/O or untrusted module import before the guard is active. The witness remains intended for reviewed, trusted offline fixture code only; no live credentials, targets or authorization may be supplied.

Actual connected zSSH VPS Python 3.14.4 test receipts on exact own intermediate SHA `a5cc8e0a3da77978ae331a52319a02eb85c35e50`:
- **25/25 dedicated tests PASS**, including real Python socket-construction, file-read and subprocess-spawn attempt regressions (all denied); private audit arguments are not echoed; subsequent clean evaluations still pass.
- **86/86 real producer integration tests PASS** with `PYTHONPATH=tests:src` and unchanged original source.
- Previous whole local unit suite at `6c6025ea59e04595150ed2fdc9d53e520bbe0837` ran **1,260 tests, 5 inherited identical baseline failures, 23 expected failures**. The five existing failing subtests were previously independently reproduced on untouched original main. This is NOT whole-suite green, source-owner repair, hosted 3.11/3.14 CI or registered named VPS proof.
- The offline stopline and seven literal false authority flags remain unchanged, and no runtime target, grant, handler, source-owner path, CI/runner or production state was changed.

## W5 — exact full-suite comparison after I/O guard

The exact latest source+documentation head `ae9967b2f3e257991ef3e1dc3d41354074db5a3c` was checked on connected zSSH Python 3.14.4 with the original suite: **1,262 tests executed, exactly five inherited ordinary FAILs, 23 expectedFailures**. The five failure identities are the same two registry-history composed CLI failures, one #301 expired-calendar fixture and two registry-history socket-fleet cases independently reproduced on original unmodified `main`. There are **no new unexpected failures** relative to the previous exact branch before the Python I/O guard (1,260 tests, same five FAILs). This supports non-regression for the new hook but is **not** a passing full suite.

Independent GitHub compare from pinned original main to current branch: **18 exclusively additive commits / 0 behind, precisely three NEW owned files and zero modifications of any existing source, production authority, workflow, runner or another worker's files**. No PR was opened or permanent runner job dispatched. The clone's Git index/worktree was clean after the tests.

## W6 — fail-closed evaluator output privacy (17 October 2026)

The context-local witness now also redirects Python-level `stdout` and `stderr` **only for each call** to the real installed scope evaluator. An attempt to `print` or write to either stream raises `PermissionError`, produces generic `HOLD/offline_witness_evaluation_failed`, and never includes the attempted text in the machine JSON receipt. The streams and Python audit-hook context are restored in `finally`; subsequent normal evaluations still succeed.

This covers regular Python prints/writes, **not** raw native writes to inherited file descriptors or arbitrary untrusted native code, and is not a strong security sandbox. All code remains for *reviewed offline fixtures only*.

On the connected zSSH Python 3.14.4 disposable checkout, **26/26 dedicated tests PASS** and **86/86 producer integration tests PASS** at exact code head `d5208ae1b335d17b6dbf7dc5b2d99d2ed52e2baf`; clean Git worktree and index. The previous post-audit-hook full original unit suite ran **1,262 tests with five previously baselined failures and 23 expectedFailures**, not a full-green production gate.

GitHub comparison after output-privacy hardening was **21 additive own commits / 0 behind original main**, exactly three new dedicated paths and zero changes to any existing source-owner, other worker, shared workflow, runner, grant, activation, live consent or deployment file. All statuses continue to disable authorization and execution; no PR/CI retry/merge/deployment/scan/grant is attempted.

## W7 — hard wall-clock scope-evaluation deadline (17 October 2026)

A source-policy regression that never returns must not leave the offline review CLI running indefinitely or capable of emitting a positive receipt. The witness now uses a **2.5-second POSIX `ITIMER_REAL` deadline** for the complete **17-case** installed evaluator invocation. A dedicated `BaseException` sentinel interrupts ordinary blocking operations even if a source policy catches standard `Exception`; it produces generic `HOLD/offline_witness_time_budget_exceeded` and exit **2**. No target data, exception text, grant or execution ability is emitted.

- **Timer ownership is fail-closed:** any pre-existing `SIGALRM` handler or armed timer, a worker-thread call, unavailable `setitimer`, or nested evaluation causes `HOLD/offline_witness_time_fence_unavailable` before the installed scope evaluator runs. The witness **never steals or cancels another component's timer**.
- The temporary handler and timer are restored in `finally` on success, exception and timeout. The context-local Python I/O/output-denial guard remains separate and intact.
- **Limitations:** this timer is only supported in the main thread on POSIX/Linux. It is not a kernel-enforced sandbox, OS resource limit, protection against arbitrary native code or a substitute for reviewed source and trusted execution. On unsupported hosts it fails closed. Code designed to suppress or override Python signals is outside its security promise. Do not run the witness on an untrusted plugin or live customer target.
- **Demonstrated RED → GREEN:** prior exact witness accepted `REVIEW_ONLY` from a background-thread evaluation instead of `HOLD`. A new regression exposed this and the deadline fix corrects it.
- Connected authorized zSSH VPS, exact code head `0424e22f45617b547f7e052748e51fcc7a046c05`, Python 3.14.4: **33/33 targeted tests PASS; 86/86 producer integrations PASS**. A genuine 7-second stalled mocked policy was bounded within 4.5 seconds; external alarm ownership, nested calls, crash recovery and clean follow-up evaluation were tested.
- Same exact code-head full local unit suite: **1,270 cases, five previously baseline-reproduced ordinary FAILs, 23 expectedFailures**. Those failures belong to existing #301 and #1535/registry-history source/fixture owners and appear on original main; this is not a wholly green project run or a release decision.
- The work remains strictly branch-only/additive with zero existing source, shared CI/runner, another-worker, runtime authorization, handler, live consent, deployment or target code changed.

## Gate interpretation

- Green unit tests validate the witness's own classification, deterministic receipt, zero-network boundary, no authority flags and mutation-detection sensitivities.
- `REVIEW_ONLY` cannot release any blocker. Source-owner #301 time-gate defects, other open source REDs, independent authentic client/operator approval, at-use revocation, review, correct hosted + named registered permanent VPS exact-head CI and explicit HUMAN GO remain required.
- **Do not merge/deploy/scan/grant/dispatch/release** this issue's code merely because the witness passes.
