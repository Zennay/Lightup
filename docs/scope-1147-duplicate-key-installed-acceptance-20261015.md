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
