# Scope #1147 — duplicate typed argument keys: installed-source acceptance, 2026-10-15

**Posture:** LightUp INCUBATE M3/M7; **PLAN/LAB ONLY · DRAFT/HOLD**.
**Source owner:** orchestration/runtime ownership (#107, #1146, #966).
**Isolation:** independent branch based on `main` `e73b7445c87ad239bdb03c50a99078ef93163b02`. Exactly two *new* files under distinct paths. No edits to `src/`, existing tests, workflows, runner, real grants or production assets.

## Actual finding versus required behavior

The installed `ToolCall.arguments_dict()` uses `dict(self.arguments)`. Repeated argument names consequently collapse to the **last** value before `ToolDefinition.validate_arguments()`. This is an input-integrity defect, **not evidence of a real target authorization bypass**. The production owner—not this reference branch—must enforce exact unique names at the outer ToolCall admission boundary prior to type/schema checks, handler lookup/invocation and evidence mutation, preserving trusted immutable identities.

The new Python `unittest` file exercises the **actual installed** `ToolExecutor` and a temporary **real SQLite** `StateStore` with a registered **inert ANALYSIS-only handler**, a fictitious `.invalid` asset, no grant and a proper temporary parent run.

Acceptance matrix:

1. Unique required + optional fields: one inert callback, exactly one durable matching evidence row.
2. Unknown argument name or incorrect argument type: `OrchestrationError`, **zero** callbacks, **zero** evidence.
3. Current-source ordinary **PASS unsafe witnesses**: (a) two valid values for the required name, (b) invalid first / valid last, (c) two optional values, (d) two identical values and (e) nonadjacent triple duplicates all collapse to the last value. For each, prove **one** callback and exactly one durable row; an unrelated crash cannot count as a meaningful RED.
4. Five separate **intentionally expected source RED** requirements: duplicate required/invalid-first/optional-key/identical/triple-key values must raise `OrchestrationError` **before** any callback or evidence. Their expected-failure status is a statement of the *unfixed* current source, not a successful security fix.

No network operations, subprocesses, real target metadata, active interaction, customer consent or privileged access are requested in these tests.

## Handoff / release boundary

Do not merge or deploy this diagnostic draft to claim a production security improvement. Owner must reject duplicate names **before collapse** while retaining unique-key behavior, consider noncanonical argument name types under separate #1094 and existing tool contract, and run ordinary PASS assertions of zero handler/evidence for all formerly expected RED cases. Retire or invert the five original-source unsafe PASS witnesses after owner repair.

Require immutable exact-head Python 3.11/3.14 hosted tests and **separate genuinely assigned permanent registered VPS runner** logs, plus independent security/privacy approval, current authorization and explicit human release. A workflow badge or queued self-hosted job is insufficient evidence. This independent branch must remain DRAFT/HOLD until owner integration and approval. Source owner #107 and the older isolated #1146 are **not modified**.

## First exact-head CI observation (now superseded by additional tests)

At former immutable `853443d358203c5ad76c552d384d8e1e2677ce29`, original GitHub-hosted [preflight #38808214137](https://github.com/Zennay/Lightup/actions/runs/38808214137) Python 3.11 and 3.14 checkout logs explicitly showed **all nine then-own tests correct (six ordinary PASS and three deliberately expected installed-source RED)**. Each entire unit run executed **1,246 tests, 26 expected failures and exactly one unrelated pre-existing #301 fixed-calendar-window test FAIL** (line 111). This failure is real and not masked. Because units failed, real producer integrations were skipped: do not claim end-to-end green. The separate registered [VPS CI #38808214030](https://github.com/Zennay/Lightup/actions/runs/38808214030) remained queued with no demonstrated runner assignment. Those logs are **NOT** exact-head verification for the later four added duplicate/identical/triple-key tests (13 methods, eight ordinary plus five expected RED). Re-check both versions and registered VPS on the new immutable head.

## W4 — explicit pre-schema policy ordering and denied-target controls

Independent additive source-test commits:
- `1191597255cd115267eb9ddd4d9d06abb0f34673`: seven extra installed-`ToolExecutor` tests. Positive proof counts the real schema-validator and policy calls; negative controls require malformed-last and duplicate unknown keys to stay denied. The actual unsafe duplicate witness proves **both** validation and policy get an already-collapsed dict. The exact fail-closed requirement is deliberately expected SOURCE RED: zero validator calls, zero policy checks, zero handler calls, zero evidence when a duplicate exists. A separate ordinary witness proves a duplicate call after one successful call creates a **second** durable row; its expected-RED counterpart demands no ledger mutation on denial.
- `d6ae9c39d359af8a863c049e7bc5853a8ea90df5`: original source preserves order-dependent last-value-wins behavior; **independent no-grant TARGET_ACTIVE** synthetic control verifies the product policy still prevents execution/evidence with no actual authorization. This is **not** an authorization bypass demonstration.
- `9f8ddd53a3807746f27b1fa1157ff29cb591fe13`: order-dependent reject contracts split into **two independent expected-RED test methods** so Python `unittest.subTest` cannot obscure whether one permutation was actually exercised.

Total **24 individual executable test methods** on the current original source: **15 ordinary expected PASS** (including eight source-vulnerability witnesses and seven safe/denied controls) + **9 intentionally expected SOURCE RED** (unrepaired authorization-input integrity requirements). Exactly the same two self-owned file paths, no edits to installed orchestration, parallel owners, runner, workflows, actual consent, real customers or scan surfaces.

**CI claims must be pinned to the final document commit, not to a superseded SHA.** Previous head `a7017057087bf790c712a8a56ddcb16f6ff6429b` hosted #38808541453 independently proved **13/13** original tests as designed on Python 3.11/3.14, with one pre-existing #301 expired-window failure in each full suite; producer skipped. The 11 new methods are not certified by those older logs. Require exact-HEAD original 3.11/3.14 logs and true permanent assigned VPS-run evidence for W4. Do not treat an intentional expected failure, queued run or hosted success as a repaired security issue or release authority.

## Owner handoff precise source invariant

The production owner must reject repeated *exact* argument key names before lossy `dict(self.arguments)` projection and before validation, policy decisions, or handler execution. For every rejected duplicate, handler count and newly persisted action evidence count must remain exactly zero, including after a previous valid call. Preserve positive unique-key behavior and independent denial for unauthenticated TARGET_ACTIVE. Independently resolve #1094 non-string/alias field identity rather than silently normalizing ambiguous caller identifiers. Finally invert/remove current-source-unsafe witnesses and promote all nine expected REDs into ordinary PASS. Preserve existing tenant/grant/risk/approval/revocation/asset gates; do not broaden permission in pursuit of fixing a test.

## W5 — fail-hard no-network invariant across the entire synthetic suite

Commit `ddf9246c40a70bd1b8eec5b66be0ffec13e1a589` adds **actual per-test hard-stopping network tripwires** in the self-owned test harness: `socket.socket`, `socket.create_connection` and `socket.getaddrinfo` are each patched to raise `AssertionError` if installed source or future changes try a socket/DNS call. The ordinary positive-control test checks all three guards remain uninvoked while exactly one matching SQLite evidence row is produced. Patch cleanup is ordered before temporary-state cleanup. No socket connection or network query is attempted to self-test the guard. All targets stay fictional. A future network regression cannot be silently accepted as a normal PASS control.

The own suite is now **25 methods total**: **16 ordinary PASS controls/source-behavior witnesses + 9 intentionally expected original-source RED**. Every original-source unsafe diagnostic PASS witness will need inversion/removal on actual source repair. The initial W4 matrix of 24 tests and prior CI evidence do **not** certify this final 25-test head. Source, runners and release restrictions remain unchanged. The final GitHub checkout and original 3.11/3.14 job logs must be checked on the immutable final SHA; self-hosted permanent VPS proof remains separately required. **INCUBATE M3/M7 · DRAFT/HOLD**.

## W6 — original-source RED oracle and real OS-process HOLD receipt

A normal Python `unittest.expectedFailure` can report success for **any** error, including a broken SQLite setup, an exception in a supposedly inert handler or a vanished actual source weakness. New entirely OWNED `tests/test_scope_1147_expected_red_integrity_20261015.py` reruns the exact installed 25-method matrix with a private `TestResult` and fails unless:
- precisely **nine named original-source RED cases** fail with **`AssertionError: OrchestrationError not raised`**, NOT an arbitrary exception;
- precisely 16 ordinary tests pass, all 25 execute, none skip, no unexpected successes, test errors or failures;
- extra independent mutant acceptance tests prove runtime crashes, unexpected successes and dropped-RED cases cause ordinary FAIL, not false source evidence.

Implemented a standalone **non-authorizing** original-source diagnostic: `python -m scripts.scope_1147_red_receipt_cli`. No arguments, no customer data, no real targets, no activation. It imports only installed local synthetic tests, blocks socket creation/connect/DNS throughout, uses disposable SQLite, suppresses potential untrusted text and emits exactly one bounded static JSON line. A confirmed existing flaw results in **exit 2** and `{"status":"HOLD","reason":"KNOWN_SOURCE_RED_CONFIRMED",...false permissions}`; an indeterminate error or any unexpected CLI argument is **exit 3**, `status=HOLD`, all six permission/action flags false. **Exit zero and GO/authorize/deploy/scan are NEVER possible.** This is a source-review receipt, not approval.

Three **real child-OS-process** acceptance tests in `tests/test_scope_1147_red_receipt_process_20261015.py` invoke the exact documented `python -m` entrypoint with/without invalid args and twice consecutively; require nonzero exit, single JSON line, empty stderr, static HOLD flags and no echo of a fictional privacy-sensitive marker. Repeating must give byte-for-byte same output.

**Own CI discovered methods now 32**: 25 prior original-source matrix + four expected-RED-integrity oracle tests + three actual subprocess E2E tests. The integrity oracle's additional *internal* replay of 25 methods and each CLI's own internal replay are not extra top-level CI method counts. Exact-head Python 3.11/3.14 logs and separate permanent assigned self-hosted VPS proof are required; earlier 25-case hosted verification is not proof for W6. No `src/` files, workflow/runner changes, other worker files, real grants, targets, deploys or release. DRAFT/HOLD pending source owner #107/#1146, existing #301 owner #1452 and independent security/privacy/operator human GO.

## W7 — prove opaque HOLD under faults in the review process itself

Added two **ordinary real CLI in-process acceptance tests** after W6's actual child-process tests. They deliberately replace only this **test process's** source-test loader using `unittest.mock.patch`; no installed LightUp code, customer data, target or external service changes:
1. A mocked internal diagnostic crash contains a fictional sensitive marker. The CLI must exit **3**, emit exactly one JSON line with `status=HOLD`, `reason=UNVERIFIED`, **all six action flags false**, empty stderr and **never echo the marker**.
2. A broken loader silently returns an empty suite of tests. It cannot be mistaken for evidence of a repaired source: again exit **3**, static HOLD and all six false flags.

The owned suite now has **34 top-level methods** (25 installed executor cases, 4 strict source-RED integrity methods, **5** CLI/OS-process/error-path controls). Deliberate internal replays are not counted as new top-level tests. No production change or authority; all original `#1147` source RED still unrepaired. CI at the new immutable head remains required on Python 3.11 and 3.14, with genuinely assigned permanent registered VPS evidence separately, followed by owner/security/privacy/human approval. DRAFT/HOLD.

## W8 — discovered unittest auto-collection duplication and repaired it

After independently inspecting both original W6 checkout logs, the full unit summary **1,294** was discovered to include **25 extra top-level repetitions** of our original source matrix. Root cause: the expected-RED oracle imported `DuplicateArgumentKeysInstalledSource1147` as a module-global `unittest.TestCase`. Python's ordinary `unittest discover` also auto-collects imported TestCase classes in a module, so the same 25 source cases ran once from their actual test module and again from the oracle module, in addition to the deliberate independently counted private `TestResult` replay. This was an OWN TEST-HARNESS DISCOVERY BUG, not production-source evidence.

We repaired only our independent oracle test file:
- Moved the original source test class import **inside** the explicit private replay method, so it cannot be seen at global/module discovery time.
- Added an actual regression case that asks Python's **real** `unittest.defaultTestLoader.loadTestsFromModule` to discover the oracle module and asserts exactly five own oracle methods and no 25 imported source classes. If someone accidentally moves the source test class back to module scope, this will fail.
- Preserved the deliberately independent single 25-method replay inside the strict source-RED oracle, all nine exact missing-denial signatures, and HOLD-only CLI/no-network behavior.

Now **35 unique owned top-level methods** (25 original source, 5 strict oracle including discovery regression, 5 CLI/E2E/fault-path). With unchanged main/base assumptions, the **expected full top-level suite count becomes 1,272** (previous 1,262 including 25 source methods, plus 10 genuinely new oracle/CLI methods); expected intentional original-source RED count **32**, not artificially double-counted 41. These counts are *forecast only until exact-final-head CI independently confirms them*. Previous W6/W7 1,294-test original hosted output should remain transparently recorded as observed and affected by this duplicate discovery. No production, workflow, other-worker, target or permission changes. Need new Python 3.11/3.14 original job logs on final immutable commit, genuine registered VPS execution, owner fix and security/privacy/human GO. **INCUBATE M3/M7 · DRAFT/HOLD.**

## W9 — process-state restoration and strict no-process safety

This additional independent author-owned improvement hardens the existing opt-in `scripts.scope_1147_red_receipt_cli` review (not the runtime executor or source owner's production permissions):

1. The imported `main([])` **previously mutated `sys.path` and `sys.dont_write_bytecode` permanently**, even after a CLI error. Added a `finally` restore of the caller's original import path contents and bytecode preference. Three new ordinary acceptance cases confirm exact before/after equality on a confirmed local HOLD receipt, a simulated internal failure and a rejected unexpected CLI argument. This prevents one scope diagnostic from affecting unrelated future test modules in the same Python interpreter.
2. Both the full 25-case installed-executor synthetic fixture and the CLI import/execution scope now intercept **`subprocess.Popen` and `os.system` as hard failure**, in addition to `socket.socket`, `socket.create_connection` and `socket.getaddrinfo`. No direct subprocess or shell process may be launched while a source test is executing; the original positive canary requires all **five** guards remain unused.
3. A new ordinary acceptance case deliberately calls a fictional subprocess and fictional shell command **only while patch mocks are active**; both are caught before reaching the OS and neither a handler call nor an SQLite evidence row occurs. Guard cleanup is guaranteed.

**Top-level method count on this W9 source**: 25 installed ToolExecutor + 5 strict RED/discovery oracles + **9** subprocess/CLI state/negative controls = **39 unique tests**. With main unchanged, forecast full `unittest discover` is **1,276 tests, 32 intentional original-source RED and the separate unrelated #301 expired fixture failure**. These are expected counts, not evidence until original exact-HEAD hosted 3.11/3.14 job logs confirm. Existing source weakness remains open. The standalone review still always reports HOLD, exit 2 on precisely verified ORIGINAL source RED, 3 for unverifiable/invalid invocation, and cannot confer authorizations or deployment. No source owner, existing CI workflow, permanent VPS runner or live data changed; DRAFT/HOLD.

## W10 — fail-closed expected-RED provenance and working-directory independence

More independent quality work, still isolated to self-owned `#1147` files only:

- **Important actual validation hole found:** the first strict oracle used substring `"AssertionError: OrchestrationError not raised" in traceback`. A different exception such as `ValueError("AssertionError: OrchestrationError not raised")` might be falsely treated as evidence of the known source bug. The source oracle now requires the **exact final traceback exception line**, and provenance linking the *specific named test method* to the *original installed-executor test module*. This is a stricter diagnostic, never runtime authorization.
- Added **three independent negative oracle tests**: a spoofed `ValueError` embedding the expected text, an assertion containing the expected string plus a nonmatching suffix, and the same final assertion forged from an unrelated test file. All must be ordinary PASS only when the oracle rejects the spoof. The actual Python `unittest.TestLoader` discovery guard was updated to reflect eight unique oracle methods; it continues forbidding silent rediscovery of 25 source tests.
- Added **two real OS-process tests** for the no-authority `python -m scripts.scope_1147_red_receipt_cli` entrypoint when invoked from an unrelated temporary working directory using explicit repo-local `PYTHONPATH`. One verifies byte-identical HOLD-only JSON compared with the repository-root invocation and no new files; another leaves a fictional `.invalid` marker in that working directory and requires it remain unchanged, be excluded from output, and never confer a single permission flag. This is an explicit test of cwd-independent safety, NOT permission to accept any caller-supplied target.
- **Top-level test count W10** is **44 unique methods**: 25 original installed source, 8 strict original-source RED integrity / discovery checks, 11 CLI / true OS-process / fail-closed checks. Current original-source `9` required RED remain unrepaired by production owner #107/#1146. Since 1,276 tests were previously observed at exact W9 immutable SHA, the next full suite *should* discover 1,281 tests and exactly 32 intentionally expected source RED; this is only a forecast until new exact-HEAD Python 3.11 and 3.14 original job logs prove it. Separate permanently assigned registered VPS evidence and real producer integrations are still mandatory before any GO.

Do not convert any `HOLD` receipt to a grant, use runtime targets, merge, deploy, or modify another worker's paths. **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**.

## W11 — positive-control roster integrity (avoid source RED false confidence)

The W10 source RED oracle now rejects fake traceback text and provenance. An independent second integrity problem is that checking only **nine named RED tests + total 25** would still accept a harness where one of the **16 ordinary safe/unsafe diagnostic witnesses** silently disappeared and another, meaningless PASS replaced it. Such a counterfeit could keep the same numerical totals and give a false statement about verified safe and unsafe source effects.

Added explicit immutable **all-25 test-identity roster**, composed of **16 pinned positive-control names +9 pinned original-source RED names**, checked against the actual installed matrix via Python's `unittest.TestLoader.getTestCaseNames` **before running the raw source matrix**. Both the strict test oracle and the independently callable non-authorizing `python -m scripts.scope_1147_red_receipt_cli` now invoke this gate. The existing `TestResult` return value alone does not record successful test identities and is therefore insufficient to detect this loss.

Material negative controls:
- The oracle proves the exact original current 25 method names and refuses a substitution that preserves the total test count and all nine RED names but swaps out one required positive control.
- The actual CLI test injects a failed roster decision into the local isolated reviewer and requires **nonzero 3, opaque `HOLD/UNVERIFIED`, all six action flags false, exactly one JSON line, and no echoed fictional sensitive marker**.

Including the W10 forged-exception and unrelated-cwd tests, the branch now has **47 unique top-level owned methods**: **25 raw executor +10 integrity/discovery +12 real CLI subprocess/fault/isolation tests**. The *expected*, not yet certified exact-head full-suite count is **1,284 tests and 32 deliberately expected original-source RED** assuming unchanged `main`. Old original source `#1147` remains unrepaired and the original executor source owner #107/#1146 must integrate pre-`dict` duplicate rejection. The existing independently owned #301 expiring fixture, permanent registered VPS runner assignment, producer integration and security/privacy/customer/operator human GO remain unsatisfied. **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**, no changes to production, target permissions or release.

## W12 — independent proof of the source-owner repair transition

A separate new self-owned `tests/test_scope_1147_synthetic_owner_fix_transition_20261015.py` does **not modify production source, policy, grants, permissions or branch-owned files**. It uses a temporary in-memory `unittest.mock.patch.object(ToolCall, "arguments_dict", _strict_preprojection)` solely within tests to emulate a hypothetical owner-side pre-projection exact-duplicate rejection; this is a **synthetic contract**, not a deployed source fix, release review or prescription about separate #1094 type/alias handling.

The new acceptance matrix concretely verifies:
1. **All nine** expected-original-source RED methods become **ordinary, directly invoked PASS assertions** under the bounded synthetic fix, with the original installed `ToolExecutor` and temporary real SQLite evidence store. They are called without unittest's expectedFailure machinery, so this is evidence for post-fix promotion to ordinary PASS, not a superficial xfail report.
2. **All seven ordinary controls compatible with pre-schema duplicate rejection** remain genuine PASS under the hypothetical fix; the eighth existing safe control itself contains duplicate keys, so its original `ToolDenied` expectation must be superseded by an earlier `OrchestrationError`. A distinct **unique-key no-grant installed-executor** control verifies that the real policy still denies unauthorized target-active dispatch, with zero handler calls and zero SQLite evidence.
3. **All eight positive witnesses describing the CURRENT unsafe last-value-wins behavior** now raise the correct `OrchestrationError`, demonstrating why these must be inverted/retired after the real source-owner repair rather than assumed evergreen green.
4. On exiting the scoped patch, the installed original method's identity and present last-value-wins behavior remain **unchanged**. Nothing from this PR is a production repair.
5. An ordinary unique-name projection preserves parameter ordering and value **object identity** under the patch, proving this synthetic contract does not blindly coerce or rewrite otherwise valid unique input.
6. The existing CLI's `KNOWN_SOURCE_RED_CONFIRMED` must become an **opaque `HOLD/UNVERIFIED` exit 3 with all six action flags false** while source is hypothetically fixed; a red-only diagnostic is never release approval and must not treat real repair as a green permission signal.

The eight new synthetic-transition tests raise **55 unique top-level self-owned methods** (25 current installed source, 10 exact-source-red/positive-control oracle, 12 standalone offline CLI, 8 synthetic owner transition). The nine deliberate ORIGINAL source RED remain open on actual main and are unrelated to the expected behavior of the scoped reference patch. Based on previously verified 1,284 original full suite methods, **1,292** full-suite methods with unchanged main is a forecast, not an asserted exact-HEAD CI outcome. Require original hosted Python 3.11/3.14 checkout/jobs and separately actually assigned registered VPS proof. Existing independent #301 expiring fixture and genuine producer integration remain outside this lane. **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD, never merge/deploy/scan/authorize from these simulated tests**.

## W13 — precedence regression found during real Python 3.14 CI

The first hosted Python 3.14 original-run on immutable pre-fix W12 SHA `6cca86f55195a50bb06c540a4183c21b1732e985` found **one actual mistake in the new synthetic integration test**: the existing `test_target_active_without_grant_stays_denied_even_with_duplicate_keys` (which was **a correct ToolDenied case on the original unsafe source**) contains TWO identical keys. After a correctly placed pre-schema duplicate rejection, **`OrchestrationError` must take precedence over the no-grant policy `ToolDenied`**. The earlier "eight safe cases remain identical" assertion was incorrect. The original Python 3.14 test log specifically identified this test as ERROR; the full suite also had the separate pre-existing #301 expired-time FAIL. This is **our own QA contract mistake**, not an assertion of new product vulnerability.

Actual fix in self-owned synthetic test path:
- Test **seven** compatible safe controls directly as ordinary PASS under temporary in-memory repair.
- Require the **eighth legacy control containing duplicate keys** to switch from a `ToolDenied` to the earlier expected `OrchestrationError`. Keep a separate explicit call validating no handler or evidence.
- Add a NEW distinct no-grant **unique-key** target-active test invoking the real installed `ToolExecutor` and `ExecutionPolicy` with fictional `.invalid` asset, no AuthorizationGrant, and inert target callback. It MUST still raise `ToolDenied`, invoke zero callbacks and create no persisted SQLite evidence under the synthetic patch.
- The nine pre-schema source RED→ordinary-PASS expectations, eight unsafe witness inversions, original runtime method restoration and offline HOLD-after-fix invariants remain intact.

This adds **two** independent methods and repairs one incorrect expectation: W13 now **55 unique owned top-level CI methods**, projected **1,292** full-suite with otherwise unchanged main, 32 expected ORIGINAL source RED and the previously known separately owned #301 fixture failure. Wait for original exact-head hosted Python 3.11/3.14 job logs and actual permanent VPS assignment; do not borrow prior SHA proof. **DRAFT/HOLD.**
