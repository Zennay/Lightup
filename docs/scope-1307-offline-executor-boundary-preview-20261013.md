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

## W6 — safe local plan-file descriptor admission

Real review of W4/W5 uncovered an OS-level issue: `Path.open("rb")` can **block before the file-type test** when a user points to an unconnected named pipe (FIFO). Even a metadata-only offline tool must not be allowed to hang indefinitely on untrusted local path types.

The CLI now opens each file only with required `O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC`, **failing closed** if these flags are unavailable. It checks the descriptor's actual type using `fstat` **before** reading; nonregular files and files with `st_size > 4096` are rejected. It reads at most 4097 bytes from a bounded regular stream, compares `fstat` file size before and after reading, always closes descriptors, and refuses final-component symlinks. There is no claim that this detects same-length concurrent rewrites, hard-link substitution or symlinks in ancestor directories; it is an offline local CLI, **not an atomic trust boundary for arbitrary hostile filesystems**.

The additional **real subprocess + disposable filesystem regression suite** `tests/test_offline_executor_fd_admission_1307.py` validates nonblocking FIFO refusal including a late-invalid proposed plan, final-component symlinks, dangling links, local special devices, directories, sparse oversized files, exact 4096-byte positive controls, non-authorizing receipts and exact OS open flags. Synthetic-only inputs; no external target, network, grant, live ToolExecutor execution or deployment. All owner/security/VPS/human release gates remain unchanged.

## W7 — strict kernel read budget and partial-read completion

The CLI no longer uses a buffered Python file object to read untrusted synthetic JSON. It calls `os.read(fd, remaining_budget)` directly, starting with `MAX_BYTES+1 == 4097` bytes, decrementing the budget after every chunk, and continuing until EOF or the byte cap. Therefore kernel reads themselves are **never requested above the remaining bound**, buffered prefetch is impossible, and a short kernel read cannot cause a valid JSON prefix to be silently accepted when trailing bytes remain. The original descriptor is always closed even when read raises. The existing opening/fstat/symlink logic and fixed, opaque denial remain unchanged. This is still not a claim of atomic snapshot resistance against same-size concurrent modifications.

Nine new tests in `tests/test_offline_executor_kernel_reads_1307.py` exercise actual Linux file descriptors with simulated short kernel reads, exact read-size observation, trailing invalid bytes, concurrent append, before-read size refusal, FD close on OSError, a full 4096-byte positive plan and avoidance of buffered `Path.open`. All activity uses disposable local synthetic files, zero handlers or network, and every preview receipt remains strictly non-authorizing. Separate final-head hosted and permanent VPS evidence is required; earlier W6 success cannot validate this new W7 code.

## W8 — optional fail-closed synthetic-only no-expansion check

The baseline/proposal comparator now offers an **explicit** strict CLI variant:
`python -m lightup.offline_executor_batch_cli_optin --require-no-expansion baseline.json proposed.json`. The same strict bounded JSON parser and complete independent offline checks validate **both** 1–64 synthetic-only plans before any output. On a proposed addition or replacement of a synthetic tool ID, the CLI fails **closed with exit 2**, **no stdout**, a fixed error string, and no success/partial receipt. Unchanged, reordered or narrowing proposals receive the same minimal aggregate-only receipt as `--compare`, with hardcoded `permit_issued=false`, `execution_enabled=false`, `authorization_verified=false`. The original `--compare` remains informational for observers; its success status has never been a security permit.

A new **14-case real CLI subprocess regression suite** `tests/test_offline_executor_no_expansion_1307.py` verifies narrowing, order changes, full 64-item negative delta, 63→64 expansion, replacements, late-invalid proposal, duplicate JSON keys/tools, missing files, unrecognized flags, comparison's informational-only distinction, and in-process traps asserting neither real executor nor policy is called.

**Important:** This catches changes only in a synthetic list of `offline-check-NNN` example IDs, **not** customer scope, granted capabilities, live AuthorizationGrants, risk ceilings or target-active execution. A successful run is **not proof of authorization**. Not wired into normal production or deploy gates. Preserve project DRAFT/HOLD/NO MERGE/NO DEPLOY until actual source-authority owner and independent reviews plus VPS proof.

## W9 — detect same-byte-length local file substitution

W6/W7 guarded non-regular inputs, bounded reads and **file size** changes, but a valid synthetic JSON file could still be rewritten to a different plan of the **same byte length** while the CLI was reading it. The opt-in loader now compares both fstat snapshots on the **same open descriptor** for `st_dev`, `st_ino`, `st_mode`, `st_size`, and nanosecond `st_mtime_ns` and `st_ctime_ns`. Any mismatch fails closed with no success receipt. These are normal filesystem metadata checks with a fixed constant-denial CLI; they do **not** prove atomic snapshots against malicious timestamp restoration, network filesystems, same-metadata rewrites or changes made before opening. Production authorization is **not** affected.

Seven independent disposable local file tests in `tests/test_offline_executor_same_size_mutations_1307.py` cover a same-length synthetic plan rewrite during a direct OS read, permission change after open, explicit synthetic metadata mutation canaries for `mtime`, `ctime`, inode and device, plus a positive unchanged file. No network, scanning, real target, model, customer authorization or execution. This remains a **synthetic metadata review**, not a production active gate; held PR owner review and registered VPS CI still required.

## W10 — all-component nofollow local plan traversal

A local path can hide a symlink **in a parent directory**, even when the final filename is a regular file and is opened with `O_NOFOLLOW`. The opt-in CLI now uses `_open_plan_fd_without_symlink_ancestors(path)`: it starts from an explicitly opened `/` or `.` directory descriptor, and resolves **each parent component with `os.open(name, O_DIRECTORY|O_NOFOLLOW|O_CLOEXEC, dir_fd=parent_fd)`** before opening the last file with the existing nonblocking/no-follow flags relative to that pinned parent. Every directory descriptor is closed on success or error; special files and FIFOs still fail closed. It denies `..` traversal components, excessively long paths/components, and platforms without the required native flags/dir_fd support rather than falling back to weak opening.

A **new 14-test real temporary-filesystem and subprocess suite** `tests/test_offline_executor_ancestor_nofollow_1307.py` verifies absolute and relative nested valid plans, ancestor symlinks in both modes, final symlinks, late-invalid proposed comparison, baseline symlink refusal, parent traversal, excessive components, non-directory parents, exact native per-component flags, descriptor cleanup and opaque no-output failure. No real customer target, grant, authorized tool invocation or network.

**Limitations:** this rejects path symlinks under a trusted starting root/cwd, but is NOT a complete sandbox, does not freeze cwd, prevent a malicious filesystem or hardlink tricks, or certify file contents against all races. This is optional synthetic-only PLAN preview; no production source integration. Previous W9 hosted CI success is not validation of this new W10 head.

## W11 — reject multiply-linked or shared-write synthetic plan files

Even a symlink-free, descriptor-pinned regular file can be written through *another hardlink* or by group/other users. This optional local JSON loader now refuses files whose native fstat link count is not exactly 1 or whose mode has group/other write bits (S_IWGRP/S_IWOTH). It verifies the conditions both before and after bounded OS reading. This applies equally to --input, --compare and --require-no-expansion without any partial receipt, grant or dispatch.

Added 12 genuine disposable filesystem/subprocess tests in tests/test_offline_executor_link_mode_admission_1307.py: one-link and owner-only positive controls, readonly positive, two-link denial from original and alternate hardlink, late proposal rejection, hardlink removal positive, group/world-writable rejection, hardlink addition or chmod during read, late fstat link-count mutation, and existing symlink refusal. Only synthetic offline-check IDs, no actual customer target, no network, no scanner or permission.

**Limits:** nlink==1 plus mode bits do not establish trusted file ownership, trusted parent permissions, absence of same-file concurrent writes or atomic immutable snapshots. This check intentionally rejects otherwise valid shared-edit local fixtures and does not modify real authorization source or runtime. Project remains INCUBATE M3/M7 PLAN/LAB ONLY; DRAFT/HOLD/NO MERGE/NO DEPLOY, with separate original source-owner issues and registered VPS approval outstanding.
