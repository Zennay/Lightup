# Finite-number boundary for typed tool arguments (offline reference)

## Finding and risk

Numeric tool parameters must not admit `NaN`, positive/negative infinity, booleans, `IntEnum`, numeric subclasses, or arbitrary objects with coercion hooks. Non-finite values can undermine comparisons (e.g. `NaN <= limit` is false) and downstream JSON/evidence interchange. This is an input-integrity requirement, **not** a grant, scope, target or execution authorization.

## Proposed fail-closed contract

- NUMBER accepts **exact built-in** `int` and finite exact built-in `float`.
- INTEGER accepts only exact built-in `int`, never `bool` or `IntEnum`.
- Reject `NaN` and `±Infinity` **before** policy arithmetic, handler dispatch, evidence persistence, retry or network access.
- Preserve finite positive/negative numbers, zero and large finite floats. Numeric range bounds remain parameter-specific and independent.
- No implicit `float(value)` or `int(value)` conversion on untrusted inputs.
- JSON producers and readers should also disable/deny non-standard non-finite number syntax.

## Ownership and acceptance

`tests/test_scope_tool_finite_number_reference.py` is a standalone pure stdlib reference model, not a production integration test. Its positive result must never be presented as active-tool protection. ToolRegistry/ToolDefinition owner PR #156 and exact value-typing finding #1095 own production validation and eventual handler-boundary tests. No source changes here. Integrate only after coordinating with those owners; on exact production head prove that malformed numeric arguments trigger a denial **before** the handler or evidence writer is called.

No DNS, sockets, targets, scans, authorization grants, capability invocation or deployment in this branch. Shared VPS CI lane is not retriggered by this reference-only branch.

## JSON ingress/egress proof slice

`tests/test_scope_tool_finite_json_reference.py` adds five offline stdlib tests:
- reject non-standard `NaN`, `Infinity` and `-Infinity` tokens on JSON ingress, including nested ToolCall argument envelopes;
- reject non-finite Python values on JSON egress (`allow_nan=False`);
- preserve ordinary finite JSON round trips and quoted string literals;
- explicitly demonstrate that duplicate keys remain an **independent** admission concern (#966), and that permissive JSON parsing must not be mistaken for a complete ToolCall validator.

Production owner integration must apply strict decoding/encoding at the actual interface, and retain independent duplicate-key, exact type, authorized asset and live-grant checks. The tests contain no production imports or effectful calls. No CI, hosted or VPS success is claimed for the new head.
