# Scope authorization #1094 — optional strict ToolCall field identity (2026-10-13)

## Source observation
The original `ToolExecutor.execute()` in `src/lightup/ai/orchestration.py` reads `call.tool_id` before exact-type validation and uses `dict(call.arguments)` before validating argument names. Annotated `str` fields and tuple keys are not runtime identity constraints. The existing RED field-identity test branch `chatgpt/scope-toolcall-field-identity-red-20261009` and open [#1094](https://github.com/Zennay/Lightup/issues/1094) track the source-owner acceptance boundary. This is a **synthetic parser/identity risk, not proof of real-world compromise**.

## Implemented — opt-in only
New `src/lightup/strict_toolcall_identity_optin.py` adds `require_canonical_toolcall()` and an explicit `StrictFieldIdentityExecutor` adapter. Before any original executor, registry lookup, lossy projection or evidence write, it:
- requires exact built-in `ToolCall`, exact built-in `str` tool id and exact built-in `str` argument-name keys (never invokes subclass equality/hash);
- enforces a documented intentionally restrictive ASCII identifier grammar and 128-character limit, rejecting whitespace, control characters, Unicode lookalikes, leading numerics and empty names;
- enforces exact tuple container and two-element tuple pairs; rejects duplicated keys before last-value-wins conversion;
- issues a fixed privacy-safe rejection reason and snapshots an ordinary `ToolCall` containing a structurally immutable argument tuple;
- delegates *all* allowed calls to the existing unchanged `ToolExecutor.execute()`, including its mode/risk/policy checks and original evidence handling.

No default imports or wiring use the adapter. The default/source-owner executor **still lacks these new checks**. No new grants, target authorization, risk-level promotion, lab permits, DNS, HTTP, scans or deployment are introduced. Argument **value** exact types (#1095), `asset` type identity (#575), duplicate-input source ownership (#966/#1147), live grant revalidation (#107), tenant provenance and all actual execution sinks remain independent unresolved owner obligations.

## Verification contract
`PYTHONPATH=src python -m unittest tests.test_scope_toolcall_field_identity_optin_1094 -v`

This isolated synthetic suite uses real `ToolExecutor`, ordinary inert ANALYSIS handler and **disposable SQLite `StateStore`**. It checks denial **before** original executor invocation, zero handler calls and zero evidence writes across type-subclass, malformed name/container/pair, duplicate, and non-string cases. One canonical positive control must create exactly one evidence row through original policy. Original schema denial must still take effect for an invalid argument value. These tests prove only the explicit adapter, **not installed routes**.

## Collision and release boundary
- Separate new branch from unchanged default `main`. Only three new paths: this runbook, opt-in source, opt-in tests. No source-owner file, previous branch, existing CI workflow, ingress or default behavior changed.
- Existing RED acceptance branch for #1094 is not modified or superseded. Original owners of #107/#156/#966, plus current #1289 and #1284 workers, keep their existing source ownership.
- **INCUBATE M3/M7 PLAN/LAB ONLY; DRAFT/HOLD; NO MERGE; NO DEPLOY.** Require source owner + independent security review, every actual entry point wired fail closed, full latest-main/CI on exact reviewed SHA, separately registered permanent VPS proof and explicit human release authorization. Neither a green offline test nor this opt-in adapter is consent or proof of production security.
