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

## Additional isolated, working opt-in registration boundary

The strictly **unwired** new module
`src/lightup/scope_907_registry_admission_optin.py` now exposes
`register_exact_tool_definition(registry, definition, handler)`. It checks
the **exact** built-in `type(registry) is ToolRegistry` and
`type(definition) is ToolDefinition` before reading any caller-controlled
properties or calling a polymorphic registry method. Noncanonical objects
receive controlled `OrchestrationError` without touching the registry.
Canonical inputs delegate to the **original installed source-owner**
`ToolRegistry.register` unchanged; no handler is called or scope widened.

This is a real opt-in functional implementation, **not production integration**:
no app/worker/ToolExecutor imports it, and it does not itself authorize tool
execution or validate all nested fields. It must not be considered a replacement
for the source-owner fix at `ToolRegistry.register` itself.

A further independent file
`tests/test_scope_907_registry_admission_optin_20261016.py` checks
**24 ordinary tests** across exact canonical registration, allowed synthetic
lab registration, malformed risk/interaction/capability rejection, parameter
type enforcement, duplicate IDs, forged ToolDefinition subclasses, duck
metadata with getter spies, forged ToolRegistry objects, and two new denial-atomicity cases where an already-registered valid tool stays untouched after malformed subsequent input. All handlers
are explicit never-call sentinels; tests exercise **registration only**.

The separate original owner-source 16-method packet continues to carry
five deliberately **OPEN** real source REDs. Passing the new opt-in tests
does not convert these into source PASS or remove DRAFT/HOLD gates.

## W11: exact registry instance method-shadow closure (opt-in only)

Exact `type(registry) is ToolRegistry` checks the outer type but cannot
prevent an instance from acquiring `registry.register = forged_registrar`
because owner registry instances are writable. The **unwired** opt-in helper
now rejects any shadowed `register` instance binding with controlled
`OrchestrationError` before calling any user-supplied method; only canonical
instances without the shadow invoke `ToolRegistry.register(registry,
definition, handler)` directly. Four new synthetic tests prove (1) no forged
registrar invoked for valid metadata, (2) no forged bypass for unknown
capability, (3) owner registration restored after deleting the synthetic
shadow, and (4) pre-existing valid registry entries remain unmodified after
rejection. No handler is ever executed.

Source owner `src/lightup/ai/orchestration.py` is unchanged, and this does
not fix production lifetime-binding issues #940 or owner-source #907 REDs;
caller-controlled nested `ToolParameter` contents and mutable internal
registry state remain distinct source-owner review topics. Do not wire to
production without owner review/security and permanent VPS evidence.

## W12: frozen outer definition is not a frozen instance validator

Python's frozen dataclass declaration is not a security boundary against
`object.__setattr__`. A caller can attach `validate_arguments = forged`
to an otherwise **exact** `ToolDefinition` instance, which will hide its
original owner class method after registration. The isolated opt-in admission
helper now inspects the exact object's ordinary `__dict__` and fails closed
with typed `OrchestrationError` when `validate_arguments` is shadowed,
**before** a potentially unsafe validation method could be stored or called.
The helper still does **not** invoke the tool handler.

Three new ordinary tests show (1) the injected validator is never called
and never stored, (2) rejection cannot change an already populated
registry, and (3) removing the synthetic shadow restores canonical
required-argument validation and registration. This is an opt-in guard only;
owner #156 still owns `ToolRegistry.register`, and the installed source
continues to have five observed source REDs. Arbitrary changes to nested
mutable metadata, `registry._tools`, or a global owner class monkeypatch
are **not covered** and must not be accepted as safe/authorized by this test.
