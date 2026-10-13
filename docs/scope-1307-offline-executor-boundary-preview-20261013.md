# Issue #1307 — offline executor trust-boundary preview

**Current project posture: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO MERGE/NO DEPLOY.**

## Scope and real delivery

This **additive, opt-in, non-authorizing** module is pinned to original source-owner [PR #107](https://github.com/Zennay/Lightup/pull/107) exact `c37ee27d922a7dd400eee1db39268f4a6269e431`; it changes **no** existing source, `main`, other worker branch, deployment, scanning adapter, or CI workflow.

`OfflineExecutorBoundaryPreview.capture(executor).preview(context, call)` inspects only canonical in-process object shape and a read-only snapshot of a synthetic ToolRegistry. It **never** calls `ToolExecutor.execute`, tool handler, `ExecutionPolicy.decide`, live authorization resolver, database method, model, network, DNS, target or scanner. It accepts only `synthetic.invalid` and a strictly analysis-only registry and context. It emits a frozen, aggregate-only `OfflineBoundaryReceipt` whose three flags are always **permit_issued=false, execution_enabled=false, authorization_verified=false**. Errors use constant opaque text, without user fields or traceback in the message.

## Offline observable contracts

1. The outer executor must be exactly `ToolExecutor`, with exact `ToolRegistry`, `StateStore`, and `ExecutionPolicy`.
2. At capture time the resolver must be absent, and the executor's `execute`, registry's `get`, policy's `decide`, and StateStore's `add_evidence` cannot be instance-shadowed.
3. At each preview the captured executor's original references must still be identical, and the resolver must still be absent.
4. The registry's exact built-in dict must have 0–64 entries with exact canonical `ToolDefinition`, inert-only `InteractionKind.ANALYSIS`, exactly `RiskLevel.ANALYSIS_ONLY`, canonical immutable `ToolParameter` tuples and bounded metadata; the complete handler-identity and typed-field snapshot must be unchanged.
5. The outer input types must be exactly `RunContext` and `ToolCall`; deny duck objects/subclasses **before** accessing their getters.
6. Only canonical `ANALYSIS_ONLY`/risk-0 context with no grant, no lab and reserved synthetic asset is accepted.
7. Strict canonical argument names, finite numeric/byte-size limits and declared exact kinds are checked without calling potentially rewirable schema methods. No handler, evidence writer, or authorization policy invocation occurs even on a positive preview.

## Independent tests and limitations

`tests/test_offline_executor_boundary_preview_1307.py` creates a **real disposable SQLite StateStore** and inert registered handler, asserts evidence count and handler side effects remain unchanged across positive/rejected previews. It probes canary getters, subclasses, retained reference swaps, shadowing, registry handler and schema mutation, active metadata, auth/mode changes, URL/public assets, malformed arguments and identity/time fields.

**This is a diagnostic reference, not a production fix or an active authorization check.** The inspector learns its baseline *at capture*, so it cannot identify tampering that happened before capture or simultaneous mutation/revert. It cannot guarantee arbitrary Python reflection resistance, concurrent state atomicity, caller-provided handler purity, network isolation or that a real customer granted consent. `StateStore` is a synthetic test fixture; no production data or targets. Green tests only prove opt-in metadata inspection.

Source owners [#107](https://github.com/Zennay/Lightup/pull/107), #100 and #156 still own actual dispatch hardening, including the 14 inherited unresolved ordinary failures in [DRAFT #1306](https://github.com/Zennay/Lightup/pull/1306). Before any promotion, require real source owner integration, all expected RED becoming ordinary PASS, exact SHA hosted Python3.11/3.14 + registered permanent VPS, independent scope/security/privacy reviews, latest-main composition and explicit human authorization. No merge or deploy.

## W2 — bounded atomic batch plan preview

The same optional inspector now exposes `preview_batch(context, calls)` for a **canonical tuple of 1–64 ToolCall objects**. It invokes only the offline `preview` metadata checks on each element and returns a single frozen **non-authorizing** `OfflineBoundaryBatchReceipt` after *every* item passes. Duplicate tool IDs, unknown tools, active modes/risks/grants, malformed elements and non-synthetic targets deny the **whole batch** without producing a partial receipt. A final snapshot comparison detects changes observable at the end, but is not a concurrency isolation guarantee.

Ten independent new disposable-SQLite batch tests prove positive one/two-tool preview, immutable false-flag receipt, late deny, duplicate reject, bounded input, untrusted getters, binding swap rejection, replay determinism and zero handler/evidence effects. This batch preview is **not** a queue, scheduler, assessment approval, execution permit or authorized scope expansion. Its all-or-nothing **receipt emission** is an in-process synthetic property only; there is no persisted transaction or production authorization.

## W3 — bounded lexical admission and timezone callback safety

The offline inspector now short-circuits oversized identity strings **before** the compiled identifier regex, requires exact `str` (no polymorphic `__len__` or `__eq__`), bounds the reserved asset before comparing contents, and requires **exact `datetime.timezone.utc` identity** before any caller-owned timezone callback can run. Synthetic-only UTC is deliberately narrower than arbitrary aware timestamps. This is particularly important because `datetime.utcoffset()` can dispatch a custom `tzinfo.utcoffset` method even on an exact `datetime` object.

Seven new genuine disposable SQLite regression methods probe hostile `tzinfo`, string subclasses with throwing `__len__`/`__eq__`, one-million-character identifiers, 64-bit integer ceilings, non-finite floats and otherwise valid UTC synthetic paths. In every denial the handler and persisted evidence stay untouched. The original source-owner executor and default authorization have **not** been modified.

## W4 — actual synthetic-only CLI + bounded external JSON review

Invoke explicitly with `python -m lightup.offline_executor_batch_cli_optin --input ./plan.json`, where the **entire UTF-8 file** (maximum 4096 bytes) must contain exactly `{"version":1,"tools":["offline-check-001","offline-check-002"]}`. A set of 64 immutable synthetic `offline-check-NNN` internal tools (001–064) is registered into a disposable SQLite-only analysis run; only tool IDs and the precise version can appear in input. No external target, URL, capability, parameter, policy, risk, grant, handler, user code or network destination is loaded from the file.

The CLI refuses invalid byte size, wrong UTF-8, JSON duplication at **any depth**, unknown envelope fields, nonfinite constants, unknown/duplicate synthetic tool names, oversized lists, alternate CLI flags and non-regular input file descriptors. It exits 2 with a constant generic denial, **no stdout** and no JSON data/filename echo. On success a single allowlisted, deterministic one-line JSON result gives only `status="reviewed"`, `tools_reviewed` and permanently false `permit_issued`, `execution_enabled`, `authorization_verified`. A temporary SQLite run is created and removed internally, and its test-only `ToolExecutor.execute` and handler **are never invoked**.

`tests/test_offline_executor_batch_cli_1307.py` executes the real module in isolated subprocesses, both positive 1/2/64-item plan reviews and malformed/adversarial JSON variants; it also patches production `ToolExecutor.execute` and `ExecutionPolicy.decide` to throw if the in-process CLI review ever calls them. This is a **non-authorizing local demonstration**; neither a production API nor proof that the original live authorization is fixed. Input file opening reads local user-designated data, but no external services or real targets are contacted. DRAFT/HOLD, no automatic deployment or merge.

## W5 — non-authorizing synthetic baseline/proposal comparison

An additional opt-in CLI mode can quantify only **synthetic toolset drift**, not live authorization. Invoke `python -m lightup.offline_executor_batch_cli_optin --compare baseline.json proposed.json`, each file using the same exact versioned/bounded schema as `--input`. Both 1–64-item plans are independently fully parsed and validated through the actual offline metadata inspector **before any output**; invalid baselines or late-invalid proposals deny the entire request. Duplicate JSON keys and unknown fields are denied by the same canonical loader. Comparison is set-based (order changes do not expand a plan); receipts expose only aggregate `added_tools`, `removed_tools`, `unchanged_tools`, and `expansion_detected`, alongside permanently false permission/execution/authorization flags. No synthetic IDs, targets, original plans or paths are echoed. This is an **offline difference indicator**, not approval, not an active grant and not authoritative persisted scope.

`tests/test_offline_executor_plan_compare_1307.py` runs genuine subprocess comparisons for identical/reordered/expanded/narrowed/replaced sets, up to 64 synthetic IDs, malformed/duplicate files, late failure privacy, and patches live executor/policy methods to assert they are never invoked. This changes only the optional CLI and adds a new independent test file; original #107/#100/#156 production source and other workers remain unchanged.
