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
