# Scope issue #1095 — real ToolExecutor polymorphic value admission (RED)

**2026-10-14 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/DEPLOY**

## Purpose and immutable ownership boundary

This branch starts from original ToolRegistry owner [PR #156](https://github.com/Zennay/Lightup/pull/156) exact head `e84f2cd74d24f143c02b38cc05cb1c4c64352966`. Only four newly introduced paths belong to this work: two isolated unit suites, this handoff and an optional offline primitive snapshot helper. **No modifications** to `src/lightup/ai/orchestration.py`, original registry/executor, default deployment, workflows or other workers. Parent PR #156 remains owner of production source; [issue #1095](https://github.com/Zennay/Lightup/issues/1095) describes the mismatch.

The real source implementation uses `isinstance` in `ParamKind.accepts`. Accordingly STRING currently admits subclasses of `str`, INTEGER admits subclasses of `int` and `IntEnum`, and NUMBER admits subclasses of `int`/`float` and `IntEnum`. Builtin `bool` is correctly excluded from INTEGER and NUMBER. Subclass admissibility is **unfixed** until the original owner installs strict exact-builtin checks.

## Concrete test coverage

`tests/test_scope_1095_real_executor_typed_values_red_20261014.py` has two independent layers:

1. Standard-library built-in positive and negative controls on all four ParamKind choices, a no-coercion numeric-protocol control and seven clearly marked expected RED checks for exact primitive identity.
2. Real `ToolRegistry` + `ToolDefinition` + `ToolExecutor.execute`, genuine `ExecutionPolicy`, `RunContext` in **ANALYSIS_ONLY**, disposable `StateStore` SQLite and synthetic `ToolOutput` through an in-memory recording handler. Positive exact built-ins are expected to run as a **synthetic analysis-only control**. Canonical invalid arguments must deny without handler calls or persisted evidence. Seven additional expected RED checks require subclasses/IntEnum to be refused before both the handler and evidence ledger (including a late bad call after an accepted control).

Expected RED tests are decorated `@unittest.expectedFailure` individually so CI can characterize the unresolved defect without falsely claiming a repaired authorization boundary. **Unexpected success** is not green: Python unittest treats XPASS as a signal that tests need reevaluation and relabelling. To close #1095, original production source owner must convert these explicit expected RED cases to ordinary passing requirements and inspect absence of side effects.

Run after review, via hosted workflow and permanent registered VPS on the exact final commit:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1095_real_executor_typed_values_red_20261014.py' -v
```

## W2–W3: opt-in non-authorizing exact-primitive batch snapshots

New **optional, uninstalled** `src/lightup/primitive_admission_optin_1095.py` rejects subclass/IntEnum runtime values *before* creating canonical immutable-value snapshots, and only accepts exact built-in `str`, `int`, `float` or `bool` according to the original parameter kind. `snapshot_exact_primitive_values` validates one ordinary dictionary, required/unknown arguments and duplicate parameter declarations. `snapshot_exact_primitive_batch` validates **all 1–32 rows before returning any results**. It performs no handler, authorization, network, policy, SQLite or other I/O.

`PrimitiveValueSnapshot`/ `PrimitiveBatchSnapshot` expose read-only `authorization_verified`, `permit_issued`, `execution_enabled` properties that always evaluate to `False`. They are NOT dataclass constructor parameters and cannot be set via ordinary assignment or even `object.__setattr__` because they are read-only properties. A normal `as_arguments()` call creates a fresh ordinary dictionary from immutable built-in values, so mutating caller input after preflight cannot alter its snapshot. This is a shape-preserving synthetic reference, **not a security authorization token**. The caller of any eventual executor retains all existing issuer, customer consent, tenant, asset, live revocation, risk, and pre-I/O policy responsibilities.

A distinct new `tests/test_scope_1095_optin_atomic_primitive_snapshot_20261014.py` exercises exact built-in and hostile polymorphic values; no-custom-callback canaries; required/optional/unknown keys; ordinary `dict` admission; copy-on-admission; immutable false authority flags even under attempted caller construction/mutation; batch shapes and upper bound; atomic late-error refusal; and actual `ToolExecutor` + disposable SQLite analysis-only positive controls that run only **after** explicit synthetic preflight. This **does not** fix the original `ParamKind.accepts`: the prior 14 expected RED must remain visible until the source owner repairs them.

**W4 mode/name fence:** The optional preflight now refuses all TARGET_ACTIVE, LAB_ACTIVE, PASSIVE_PUBLIC, and elevated-risk ToolDefinitions even when supplied with valid primitive values. Only built-in `synthetic-*` tool names with `InteractionKind.ANALYSIS` and exact `RiskLevel.ANALYSIS_ONLY` can enter; a second row containing an active tool invalidates the entire batch without returning partial receipt. New tests prove this explicit non-active-only boundary. The checks do not imply trusted tool-definition provenance or customer consent.

The opt-in check intentionally **does not** attest ToolDefinition provenance/lifetime or parameters (separate source-owner #911/#913), tenant authorization, cryptographic binding, canonical tool IDs/argument key lineage (#1094), nor finite numeric value requirements (#1143). Passing a primitive snapshot to an active tool is neither supported nor a valid authorization. Synthetic fixtures use only `synthetic.invalid` in ANALYSIS_ONLY mode.

Execute opt-in tests offline after review:

```sh
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_1095_optin_atomic_primitive_snapshot_20261014.py' -v
```

## W5–W6: metadata and direct receipt constructor admission

The independent opt-in helper now requires the original `ToolDefinition.parameters` to be an **exact built-in tuple** of at most **32** parameter objects, every parameter to be the exact `ToolParameter` class, with built-in string `name`, exact `ParamKind`, and exact built-in `bool` for `required`. This rejects hostile callback-bearing parameter impostors, tuple/list subclasses, truthy/falsy non-bool required fields and oversized argument mappings *before* their contents are interpreted. Real synthetic executor/SQLite tests assert a late-invalid metadata row does not cause any handler or evidence side effects.

Public `PrimitiveValueSnapshot` and `PrimitiveBatchSnapshot` constructors now also validate their exact tuple containers, exact primitive keys/values, duplicate keys, capacity limits and exact child snapshot objects via `__post_init__`. Direct receipt construction cannot launder subclass values, malformed records, oversized batches or forged child objects into a purported canonical snapshot. Immutable read-only release/permit/execution flags remain false and no live authorization is ever issued. A constructor-valid receipt still **does not** prove matching parameter kinds, origin of a tool definition, tenant, risk level, consent, revocation or trusted authority; those remain with the original production owner.

All added tests use ordinary `unittest`, only synthetically named tools, isolated analysis-only SQLite where applicable, and intentionally do not alter the inherited **14 expected RED original-source defects**. Changes continue exclusively in four new PR-owned paths; existing source, deployments, main and other workers are untouched.

## W7: tuple-backed receipt immutability and forged tuple defense

The prior opt-in `@dataclass(frozen=True, slots=True)` receipt design could still have its `items` or `entries` field replaced with `object.__setattr__` from in-process code; therefore the earlier literal immutable-field claim was too strong. W7 replaces only those two **new diagnostic-only** receipt classes with `collections.namedtuple`-derived slotless tuple subclasses, preserving public constructors, `items`, `entries`, `as_arguments()`, `count` and the three false-only nonauthority flags. Tuple-backed fields now resist both regular and `object.__setattr__` mutation. The field mutability regression runs on real constructed snapshots and verifies no effects on synthetic invocation arguments.

Direct receipt constructors continue rejecting malformed/duplicate/polymorphic and oversized records. More critically, a deliberate `tuple.__new__(PrimitiveValueSnapshot, ...)` bypass of ordinary class construction is checked again when `as_arguments()` is called and when constructing a canonical `PrimitiveBatchSnapshot`; forged nested primitive values cannot silently become ordinary synthetic arguments. The new tests never use live target tools.

**No in-process Python object should be treated as an authorization token**: hostile code with native/reflection capabilities can bypass userland invariants. These are defensive data-shape diagnostics only; original production type-admission defects remain **14 expected RED** and require source-owner repair. No runtime registration, target dispatch, network or authorization is introduced.

## W8: real synthetic executor post-validation tampering acceptance

Two additional **ordinary** in-process tests join the isolated synthetic-only `ToolRegistry`, `ToolExecutor`, `ExecutionPolicy` and temporary `StateStore` SQLite producer. A permitted built-in `str` is snapshotted, then both the original input dictionary and a direct `object.__setattr__(receipt, "items", ...)` attack are attempted. The original exact canonical string must be the **only** handler effect and one evidence row must be persisted. A deliberately forged `tuple.__new__` receipt containing a hostile `str` subclass is rejected at `as_arguments()` and at batch construction with **zero handler calls and zero SQLite writes**. These positive and negative effects are confined to dummy `synthetic.invalid` ANALYSIS_ONLY calls, not production target tools.

These tests characterize a narrow, non-authorizing data-shape boundary and **do not fix** the 14 expected RED original source owner tests. Never treat receipt validity as authorization, tenant scope, consent or live revocation proof.

## W11–W12: order-independent primitive admission and bounded batch proof

The source-owner RED acceptance tests now exercise all **24 deterministic key insertion orders** of a four-parameter synthetic ANALYSIS_ONLY ToolDefinition. Each canonical ordering must produce exactly one real in-memory handler call and one disposable SQLite evidence record; ordinary type mismatches in any of the four fields must be denied with zero side effects for every ordering. Three additional individually marked expected RED regressions require the original `ParamKind.accepts` source to reject string, integer-enum and floating-point subclasses across all 24 orderings. These RED tests remain deliberately unresolved until the source owner corrects exact built-in type admission.

The separate uninstalled opt-in helper has five new ordinary tests for the same 24 input orders, canonical schema-order snapshots, rejected noncanonical/builtin-mismatch values, rejection of each subtype, and batch-wide all-or-nothing admission of 24 canonical requests. It must reject the final malformed entry of the maximum **32** synthetic requests without returning any partial result. Two further real synthetic ToolExecutor / disposable SQLite tests assert zero handler/evidence effects from a 32nd-entry failure and that 24 accepted preflight snapshots each keep their canonical argument values when deliberately passed to the existing ANALYSIS_ONLY executor.

All fixtures are local synthetic strings, never real targets. The opt-in helper issues **no authorization**, changes no installed source, and is not a substitute for revocation, tenant/customer scope, privacy review or release approval. The owner of production source remains [PR #156](https://github.com/Zennay/Lightup/pull/156); all expected RED tests require ordinary passing treatment after its repair.

## Limits and required release gates

All sample names are synthetic and are not queried over DNS. No network, scan, target interaction, customer data, grant, persisted authorization mutation, attack path, CI workflow edit or deployment. Even real SQLite and handler controls provide **typed-value input diagnostics only**; they do not establish customer consent, revocation coherence, live tenant scope, or real-target dispatch safety.

Remain DRAFT/HOLD with both owner-level and independent privacy/security review. Require latest-main compatibility, unmasked ordinary security tests after original owner repair, exact-head Python 3.11/3.14 hosted and independently **permanently registered vps-bb300bba** results (not merely queued jobs), and explicit human release approval before any merge/deploy. No automatic activation.
