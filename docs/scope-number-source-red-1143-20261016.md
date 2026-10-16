# #1143 — original NUMBER admission expected-RED, isolated scope owner slice

**Release status: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.**
This document does not approve or enable active tools, scans, real targets,
grants, handlers, deployments or a merge.

## Why this exists

On immutable starting `main` `e73b7445c87ad239bdb03c50a99078ef93163b02`,
`src/lightup/ai/orchestration.py` accepts `NaN`, positive/negative infinity
and arbitrarily large Python integers for `ParamKind.NUMBER`. It checks
`isinstance(value, (int, float))`, not a finite, bounded canonical schema.
This is an **input/resource policy gap**, not evidence of remote exploitation
or a permission bypass.

Current `src/lightup/finite_number_offline_review.py` already offers a
separate *optional*, pure preview that rejects these inputs. Its use is NOT
wired into the original `ToolExecutor`; do not confuse a passing preview
with actual pre-dispatch rejection. Existing #1142 source characterization
covers other typed arguments and has an independently owned PR.

## New independently-owned evidence

`tests/test_scope_number_source_red_1143_20261016.py` uses the real
`ToolRegistry`, `ToolDefinition`, `ParamKind.NUMBER` and `ToolExecutor`
against a synthetic fixture tool. Only policy, handler and evidence persistence
are mocks; no external asset or live authorization is ever involved.

* Four explicit `@unittest.expectedFailure` contracts require the original
  executor to reject `NaN`, `+Infinity`, `-Infinity` and a >4096-bit
  integer **before** the mocked handler, ledger or policy decision.
  These must remain deliberately unresolved until a genuine source-owner fix.
* An ordinary positive control proves canonical finite values can reach only
  the synthetic analysis fixture and its mocked evidence ledger.
* An ordinary denial test proves the already-existing *opt-in* finite snapshot
  fails closed before dispatch; it does **not** imply source enforcement.
* An ordinary, temporary source-characterization witness records the current
  underlying `ParamKind.NUMBER` behavior; this witness must be removed/changed
  when the security source owner fixes the defect.

The dedicated CI workflow runs only this isolated test module on both Python
3.11 and 3.14, with pinned read-only checkout, no persistent credentials,
minimal permissions and no secrets. A SUCCESS including expectedFailures is
**NOT** a green source security verdict.

## Ownership and handoff

Own new paths only. Do not change original `ai/orchestration.py`,
`execution_policy.py`, original CI workflows, #1142, #1095, #107/#156 owner
patches, other workers or default branch.

Source owner must determine per-parameter finite/bounded policy (if unbounded
integers are intentionally needed, document opt-in semantics), enforce it in
the original pre-handler path, update/remove the temporary source behavior
witness, and convert all expected REDs to ordinary tests only after original
denial and zero side effects are verified.

Require independent tenant/asset/capability/risk/window consent, live
revocation immediately before actual I/O, security/privacy review, full
exact-head original hosted and **named permanently registered VPS**
`vps-bb300bba` GREEN, and explicit human GO. No merges, deployments or real
asset actions on the basis of this branch.
