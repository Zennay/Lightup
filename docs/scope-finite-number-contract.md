# Finite NUMBER inputs — offline authorization-adjacent contract

Status: **Draft / HOLD**, source-owner decision required. This is not permission to run any active assessment.

The `ParamKind.NUMBER` branch currently accepts built-in `NaN`, `+Infinity` and `-Infinity` because `isinstance(value, (int, float))` accepts them. Such numbers are hazardous if downstream code interprets input as budgets, limits, weights or risk thresholds. This is **not** a demonstrated authorization bypass.

## Regression contract

- Ordinary finite built-in integers/floats, positive, zero and negative, remain accepted subject to independent per-field rules.
- Booleans remain rejected as numeric values.
- Non-finite floats should be rejected **before handler dispatch**. Three independently marked expected failures expose this current gap without falsely claiming that enforcement exists.
- When source owner implements the policy, remove the `expectedFailure` decorations: unexpected success should be considered a release-review prompt, not proof of complete safe execution.
- Separate end-to-end ToolExecutor handler/evidence-tripwire tests are required before treating this as enforced; a schema-only check cannot prove zero real side effects.
- This file does not change registry-owned network destination extraction or grant/revocation requirements tracked in #107, #1092 and #1093.
- Exact-type/subclass policy remains owned by #1095 and its source owner; these tests deliberately use built-in primitives only.

## Collision and safety boundary

This change adds a standalone test module and this document. No production source, tool execution, network/DNS calls, target I/O, approval change, merge or deployment.
Source-owner coordination: #1143. Existing test-only PR #1142 is untouched.

## Real-executor integration fixture (follow-up)

`tests/test_scope_number_real_executor_contract.py` registers a local-only LAB_ACTIVE tool with the real `ToolRegistry`, `ToolExecutor`, and a temporary SQLite `StateStore`. A finite positive control must call the handler once and write one evidence row; boolean rejection must have zero handler/evidence effects. NaN/+Inf/-Inf each have a separately marked `expectedFailure` intended to turn into a passing hard assertion once the source owner changes validation. No socket/network API is used. This is **not** proof of durable authorization or real-target safety. Owner retains the source change.

## Invalid primitive and alias coverage

The real-executor integration fixture now also rejects numeric-looking strings, null values, absent required parameters, unexpected field aliases and unexpected extra fields before synthetic handler invocation or evidence writes. The valid finite-number positive control remains in place. These checks concern argument validation only; they do not establish trusted destination resolution, durable consent, or pre-I/O revocation enforcement.

## Network-isolation tripwire

The offline real-ToolExecutor fixture now patches Python's `socket.getaddrinfo`, `socket.create_connection`, and `socket.socket` to raise on any attempt. One valid synthetic lab invocation and one rejected malformed argument must complete with zero socket/DNS calls. This prevents the test fixture from silently becoming a real-target test, but does not claim that production network-capable handlers have trusted destination bindings.

## Duplicate tool argument keys (#1147)

`ToolCall.arguments` is a tuple, but `ToolCall.arguments_dict()` constructs `dict(self.arguments)`; duplicate keys are silently overwritten before validation. Two **expected-failure** real-executor regressions now require both duplicate-value orderings to be rejected without handler calls or evidence. This is an integrity ambiguity, not a demonstrated authorization bypass. The orchestration owner must reject duplicate keys before dictionary conversion, then promote tests to ordinary passing assertions and validate with exact-head CI. No production code is modified in this branch.

## Repeated invocation / ledger stability

An additional real-ToolExecutor regression verifies that after one accepted synthetic finite-number call, a later ambiguous duplicate-key call must be rejected without adding handler invocations or evidence rows. It is marked `expectedFailure` until production source handles duplicate tuples before `dict()` construction. Reference-only tests are not a release gate. See #1147.

## Nonfinite replay and evidence invariants

Additional `expectedFailure` coverage now models one successful finite lab invocation followed by a NaN invocation. Required behavior is a denial with no new handler call and no additional evidence, preserving the earlier valid evidence row. This supplements the single-call NaN/+Inf/-Inf tripwires; it is still RED characterization rather than enforcement. The test formerly mislabeled an unknown-key check as an optional parameter is renamed to describe its required-parameter contract accurately.

## Repeated-denial persistence stability

Two regular (not expected-failure) real-ToolExecutor regression methods repeat malformed calls 20 times each. They verify zero evidence on an otherwise empty isolated run, and exactly one unchanged evidence row when a prior finite control succeeded. These canaries establish that the existing malformed-value rejection has no accumulating evidence side effects. They are not substitutes for fixing NaN/Infinity or duplicate-key inputs, which still require owner changes (#1143, #1147).

## Exact evidence identity preservation

A normal regression now snapshots the persisted evidence identity and provenance columns (`evidence_id`, `run_id`, `capability_id`, `kind`, `source`) after an allowed offline finite-number invocation. A subsequent rejected numeric-looking string must leave the exact row unchanged, not merely preserve row count. This checks existing denial behavior and does not close the separate pre-I/O consent/destination gaps.

## Full persisted row equality

A further offline real-ToolExecutor test snapshots all columns in the existing evidence row using SQLite schema metadata, then submits three malformed values (numeric-looking string, null, boolean). None may mutate or replace any stored column, invoke the handler, or append a row. This assertion covers the whole evidence row rather than selected provenance fields. It is a local regression, not a substitute for durable consent/revocation or destination checks.

## SQLite reconnection proof

A dedicated passing-contract integration test reopens the evidence database through separate `StateStore.connect()` contexts before and after three rejected calls. It compares the persisted row tuple and total row count after reconnecting, so the test does not rely solely on an in-memory counter or a shared cursor. This is local evidence integrity only, not grant persistence or durable revocation proof.

## Distinct positive evidence lineage

A new actual ToolExecutor lab-only regression performs two valid finite-number calls, checks both result evidence IDs are unique and two rows are stored, and then verifies an invalid numeric string cannot append a third row or invoke the handler. This guards against a test harness that would silently collapse valid trace records while checking denial. It remains isolated and does not grant target authorization.

## Interleaved valid and denied calls

The offline actual-ToolExecutor fixture now alternates three accepted finite inputs with three rejected malformed values and compares the complete set of evidence IDs stored in SQLite to the IDs from accepted calls. Denials must not contaminate or delete evidence lineage, even when interleaved. These are local lab-only contracts and do not constitute production authorization approval.

## Intervening denial cannot inject evidence

A normal ToolExecutor regression now executes valid finite → invalid string → valid finite, then compares the persisted evidence IDs in insertion order against the two successful results. This proves an intervening rejected argument cannot insert an invisible action-evidence row in the local isolated fixture; real-target authorization remains out of scope.

## Release gate manifest enforcement

`tests/test_scope_known_red_gate_manifest.py` now requires the manifest to remain `DRAFT_HOLD` with `activation_permitted=false`, with all four same-head hosted/VPS Python gates, source-owner pre-I/O revocation and registry-owned network destinations, independent review, and at least one unresolved risk. This intentionally fails if required release conditions are removed or the reference PR is prematurely marked activated. Successful manifest tests do **not** prove those conditions have been met.

## No stale or invented red gate names

The manifest checker also parses both owned test modules and verifies every declared known-red method actually exists and is a `test_*` function, with integer issue references and nonempty gate keys. Combined with the decorator parity check, this prevents accidental stale references or invented known-red names in the machine-readable release ledger.

## Unambiguous known-red issue registry

The manifest checks now reject duplicate GitHub issue numbers and duplicate gate keys, and require each unresolved list to contain explicitly named `test_*` methods. These constraints prevent accidental shadowing of an open authorization gap in the draft release ledger. This is bookkeeping enforcement, not proof that the corresponding runtime issue is fixed.
