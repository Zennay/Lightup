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
