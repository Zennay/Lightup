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
3. Current-source ordinary **PASS unsafe witnesses**: (a) two valid values for the required name, (b) invalid first / valid last, (c) two optional values all collapse to the last value. For each, prove **one** callback and exactly one durable row; an unrelated crash cannot count as a meaningful RED.
4. Three separate **intentionally expected source RED** requirements: duplicate required/invalid-first/optional-key values must raise `OrchestrationError` **before** any callback or evidence. Their expected-failure status is a statement of the *unfixed* current source, not a successful security fix.

No network operations, subprocesses, real target metadata, active interaction, customer consent or privileged access are requested in these tests.

## Handoff / release boundary

Do not merge or deploy this diagnostic draft to claim a production security improvement. Owner must reject duplicate names **before collapse** while retaining unique-key behavior, consider noncanonical argument name types under separate #1094 and existing tool contract, and run ordinary PASS assertions of zero handler/evidence for all formerly expected RED cases. Retire or invert the three original-source unsafe PASS witnesses after owner repair.

Require immutable exact-head Python 3.11/3.14 hosted tests and **separate genuinely assigned permanent registered VPS runner** logs, plus independent security/privacy approval, current authorization and explicit human release. A workflow badge or queued self-hosted job is insufficient evidence. This independent branch must remain DRAFT/HOLD until owner integration and approval. Source owner #107 and the older isolated #1146 are **not modified**.
