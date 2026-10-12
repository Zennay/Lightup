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
