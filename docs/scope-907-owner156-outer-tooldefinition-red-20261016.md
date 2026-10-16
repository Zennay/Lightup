# #907 — exact outer ToolDefinition admission on source owner #156

**INCUBATE M3/M7, PLAN/LAB ONLY, DRAFT/HOLD.** No live tool handlers,
targets, scans, client grants, merge, deployment or production change.

## Actual source boundary

The original unchanged source-owner is [PR #156](https://github.com/Zennay/Lightup/pull/156)
at exact SHA `e84f2cd74d24f143c02b38cc05cb1c4c64352966`.
Its installed `ToolRegistry.register` validates individual
`definition.interaction`, `definition.min_risk`, capability presence/state
and LAB_ONLY coherence, **before establishing the outer object type**.
Any structurally compatible object or subclass may therefore be stored as
a tool definition; `ToolExecutor` later trusts the stored object's
`validate_arguments` method. A subclass overriding that method could
sidestep the mandatory `ToolParameter` argument contract. This is
synthetic in-memory proof, not an actual successful target/tool execution.

## Our strictly additive isolated acceptance

New file `tests/test_scope_907_owner156_outer_definition_red_20261016.py`
contains **16 methods**:

- Ten ordinary controls prove exact canonical registration and identity,
  required parameter validation, duplicate-ID denial, LAB_ONLY capability
  interaction denial, malformed inner interaction denial, rejected unknown or
  ill-typed parameters, allowed canonical LAB_ONLY registration and atomic
  rejection of an unknown capability.
- Five **deliberately still open expected source REDs** require denial
  of plain ToolDefinition subclass, overriding-validator subclass,
  duck-typed definition, a property-spy before any getter is invoked,
  and a non-definition object that must raise a typed OrchestrationError
  rather than an arbitrary AttributeError.
- One ordinary replay oracle enforces exactly five genuinely reproduced
  expected failures, zero missing/skipped, unexpected-success or unhandled
  error cases. Owner fixes must consciously promote RED tests to green.

The stored test handlers are permanently throwing sentinel functions and
**never invoked**. No network, DNS, filesystem mutation, target,
grant issuance, scan or real handler execution.

## Required owner repair and release gates

1. On `ToolRegistry.register`, reject any input for which
   `type(definition) is not ToolDefinition` **before the first member read**.
2. Fail with a controlled `OrchestrationError`; leave registry unchanged.
3. Keep exact canonical registration, existing capability state/LAB_ONLY,
   interaction/risk, argument typing, duplicate-ID and policy gates intact.
4. Verify real installed source on exact child and owner SHAs, hosted
   Python 3.11+3.14 and separately genuine permanent registered VPS jobs.
5. Obtain original source-owner approval, independent security/privacy
   review, verified real-client/operator permission and human release GO.

No source in `src/lightup/ai/orchestration.py` is modified here.
Uninstalled separate #1174 strict-request handling is not a registry fix.
No GO, merge, deploy or active target authorization arises from this test.

## Witness integrity and false-green controls

Every expected source RED now requires a distinct **synthetic source-defect marker** in the actual failure traceback, checked by the ordinary replay oracle. A generic exception, unrelated assertion, skipped RED, or newly corrected admission cannot be counted as proof of the original defect. For override and duck objects the witness checks that `ToolRegistry` really stored the object, retained the non-invoked handler sentinel and allowed the object's **in-memory** `validate_arguments({})` despite a mandatory `query` parameter. The getter-spy witness proves an untrusted getter was used before type admission. The handler is never called. Three additional ordinary canonical controls pin typed arguments, lab-only lab registration and unknown capability atomic denial.

## Mutation-tested replay integrity

Two further ordinary offline unit controls run the **actual replay oracle** with a temporary in-memory patch of `ToolRegistry.register`: an unrelated `RuntimeError` must NOT count as one of the five known source REDs, and a simulated correct typed `OrchestrationError` for every noncanonical definition must be recognized as a source-owner change needing deliberate RED-to-PASS migration. The patch never changes production files, grants or invokes a tool handler.
