# #1143 — finite NUMBER structural review (offline-only)

Status: **LightUp Incubate M3/M7, PLAN/LAB only — DRAFT / HOLD / NO MERGE / NO DEPLOY**.

## Observation and non-overlap

As of `main` `05b80319cd0581fed21fe9d8f565bcb0a56cd2df`, `ParamKind.NUMBER.accepts()` in `src/lightup/ai/orchestration.py` accepts NaN, +Infinity and -Infinity as built-in floats; it only performs an `isinstance(..., (int, float))` check and excludes booleans. This is an input-shape / numeric-integrity problem, **not proof of unauthorized access**.

Issue: https://github.com/Zennay/Lightup/issues/1143

This independent branch changes **three new paths only**. It does not edit `ai/orchestration.py`, `execution_policy.py`, the actual authorization/consent/grant or destination-resolution code, any test owned by #1142/#1146, current `main`, or parallel #297/#1128/#346 work.

## New offline reference and acceptance conditions

- `lightup.finite_number_review.review_finite_number` is **uninstalled**: it never calls a tool or creates an authorization decision.
- Accept only exact built-in `int` and exact built-in **finite** `float`. Arbitrary-precision built-in integers remain valid without a lossy float conversion. Preserve +/-0.0 and finite signed fractions.
- Reject NaN, positive/negative infinity, booleans, `IntEnum`, numeric subclasses, custom numeric objects, byte strings and non-numeric input before any coercion or custom method invocation.
- Failure is deterministic `FiniteNumberRefused` with a generic no-value message: no untrusted object contents in an error.
- The successful result intentionally raises `TypeError` on truthiness to prevent it being mistaken for an execution permit; success is merely structural.
- Offline `tests/test_scope_finite_number_review_20261012.py` contains synthetic controls and **actual ToolExecutor** tests with in-process ephemeral SQLite, evidence-count tripwires and a no-network analysis handler. Its three `@expectedFailure` methods deliberately record the still-unfixed NaN/Inf producer path; a passing suite containing those XFAILs **is not real runtime enforcement proof**.

Reproduce:

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_finite_number_review_20261012.py' -v
```

## Required separate owner acceptance

1. The ToolRegistry/ParamKind source owner (#156 / #1095) must agree on a globally finite NUMBER contract or on explicit per-field opt-ins for non-finite analytical values.
2. Integrate rejection in **the actual runtime argument validation before handler invocation**, with strict type boundary from #1095 and duplicate-key handling from #1147; no test-only helper is runtime protection.
3. Replace the three expected failures with normal GREEN rejection tests; independently verify non-finite handling never invokes a handler or persists evidence, while valid synthetic controls dispatch exactly once.
4. Verify registry-owned network destination, live persisted consent, tenant/grant scope, risk, time-window and pre-I/O revocation (#107/#1092/#1093) independently; NUMBER integrity must never substitute for them.
5. Obtain exact-final-head hosted Python 3.11/3.14 unit and real-producer integration logs, **separate permanently registered** self-hosted VPS CI proof, compatibility with current `main`, original source-owner plus independent security/privacy review and explicit human approval.

No client data, external DNS/HTTP, target probes, real grants, scans, executed remediation, merge, deployment or verified retest. Even a green hosted run remains **DRAFT/HOLD**.


## W2 independent batch acceptance — 2026-10-12

Separate opt-in `review_finite_number_batch` adds **all-or-nothing** screening of at most 64 exact-tuple entries. The atomic result is `FiniteNumberBatchReview`; both scalar and batch results raise `TypeError` when tested as a Boolean. Invalid inputs never yield a successful partial result and rejection messages never interpolate input values. A caller may inspect a structural `items` tuple only after every element passed. Oversized/non-tuple iterable inputs are denied before invoking user-defined iteration or coercion.

New independently checkable lab module: `tests/test_scope_finite_number_batch_w2_20261012.py`, with a 64/65 boundary, mixed finite + huge-integer positives, three non-finite values in early/middle/late positions, custom-object method traps, a late failure purity check, non-bool result, and **real ToolExecutor** proof that a perfectly valid numeric shape cannot override the missing target authorization grant or produce evidence.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_finite_number_*20261012.py' -v
```

Batch preflight is a **lab-only reference**, not installed runtime enforcement and not a consent/authorization decision. The 64-member cap is a reference-side resource guard, not yet a production tool parameter count policy. In particular, success does not bind registry-owned destination parameters, grant issuer/tenant, active target, current approval, exact time or revocation. Original `ParamKind.NUMBER` remains unsafe for non-finite values; **three existing real-executor expected-RED cases still document that defect**. Exact-final-head hosted 3.11/3.14 and registered permanent VPS acceptance must be separately revalidated after every change. No source-owner, deployment or ingress changes.


## W3 binary64 and strict-serialization controls — 2026-10-12

Added `tests/test_scope_finite_number_ieee754_w3_20261012.py` (6 offline unittests) with exact bit-pattern controls for signed zeros, positive/negative subnormals, smallest normal, largest finite IEEE-754 values and NaN payload variants. Also covers `math.nextafter` finite boundaries, exact-type refusal of bool/numeric subclasses, and a separate strict `json.dumps(allow_nan=False)` consumer comparison. No packed-byte float conversion or user-defined numeric coercion is introduced into the reviewer.

**Important limits:** finiteness of an arbitrary-precision integer does not itself prove bounded encoded-byte length, downstream JSON acceptance or runtime memory ceilings. The positive JSON controls are **not** an endorsement of unbounded integer payloads. The production owner must set size/range budgets independently for risk/ports/limits/weights and refuse over-budget values before expensive downstream processing. JSON acceptance does not confer any authority; no live scan or target I/O occurred.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_finite_number_ieee754_w3_20261012.py' -v
```


## W4 resource-size distinction — 2026-10-12

A structurally finite built-in integer can still be arbitrarily large: passing `review_finite_number()` is **not** proof of bounded memory, safe JSON output or a safe downstream cost. New optional `review_bounded_finite_number(value, max_integer_bits=4096)` rejects exact built-in integers above the configured bit length without invoking string conversion or untrusted numeric dunder methods. Budget type must be an exact built-in `int` in the inclusive range 1–4096. The offline W2 batch reviewer now applies this bound to every member before yielding an all-or-nothing review result.

`tests/test_scope_finite_number_budget_w4_20261012.py` adds nine synthetic cases: 4096/4097-bit positive and negative boundary, strict smaller per-field budget, type-confused or excessive budget, NaN/±Infinity, float control, late outlier atomicity, scalar/bounded contract distinction and a malicious int subclass. **This is an optional post-decoding lab check only**. It cannot prevent a JSON/input parser from allocating an oversized object *before* this validator runs, and cannot replace a full pre-read byte limit, field-specific integer ranges, issuer/tenant/grant validity or live pre-I/O permission gates. The production source owner must decide explicit safety limits per field; no source/producer behavior has changed.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_scope_finite_number_budget_w4_20261012.py' -v
```
