# Scope authorization: trusted-clock failure gate (offline contract)

Status: proposed M7/ST5 acceptance contract. This document grants no permission to test any target. Executor implementation belongs to PR #107.

## Threat model

Authorization windows are authority boundaries, not scheduling hints. An unavailable, malformed, non-finite or non-UTC-aware wall clock must not default to the process start time, the previous successful check, the timestamp from a request, or an AI-generated time. A backward clock step must not revive expired authority; a forward clock step must not preactivate future authority. Monotonic time alone cannot establish calendar validity.

## Required executor behavior

1. At admission **and immediately before each active dispatch/retry**, evaluate the existing typed grant against a trustworthy fresh UTC wall-clock reading; do not cache a prior allow decision.
2. Reject unavailable clock, exception, naive datetime, non-datetime value, and ambiguous timezone inputs. On clock uncertainty, deny active work and emit a minimal non-secret reason; never coerce to now.
3. Compare against both snapshot and live-grant windows; a live-grant extension must not lengthen snapshot authority.
4. An observed wall-clock rollback relative to the last trusted check for the same run must suspend active work pending an independently trusted clock reconciliation; it must not resurrect expired grants.
5. Detecting uncertain time between multi-step actions must suppress the next action. Any currently in-flight cancellation behavior must follow the executor-owned revocation/cancellation contract; this document does not claim cancellation exists.
6. All denials must preserve tenant isolation. Audits must not log tokens, secrets, full request headers, or request bodies.
7. No new network time lookup or public target interaction is authorized by this contract. A clock source must be explicitly trusted and injectable in offline tests.

## Integration acceptance matrix

| Case | Expected admission or next-step result |
| --- | --- |
| UTC within both grant windows | Only clock gate may allow; all other authorization gates still apply |
| Exactly at valid_until (exclusive) | Deny |
| Exactly at valid_from (inclusive) | Clock gate may allow |
| Missing/throwing source | Deny |
| Naive datetime, string, NaN epoch | Deny |
| Trusted clock rolls backward after a previous observation | Deny/suspend until reconciliation |
| Live valid_until extends snapshot | Deny after original snapshot expiry |
| Step 1 admitted, step 2 clock unavailable | Step 2 never dispatches |
| Another tenant presents a valid timestamp | Tenant and grant checks remain mandatory |

## Evidence required before merge

- Executor-owner PR #107 integrates or explicitly rejects this contract with rationale.
- Deterministic fake-clock tests show dispatch, retries and multi-step boundaries deny on failure, including rollback and expiry boundaries.
- Exact-head hosted and permanent self-hosted VPS tests pass before an active production change is promoted.
- No real targets, public probes or production scans are used in acceptance tests.
