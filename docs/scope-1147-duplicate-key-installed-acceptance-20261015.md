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
