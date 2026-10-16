# LightUp #1484 — offline review of fictional permit claims

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Do not merge, deploy, scan, issue real grants, or invoke handlers.**

An opt-in, unwired helper lives at `src/lightup/permit_claim_review_1484.py`. It accepts a bounded tuple (1–64) of exact `ExecutionPermit` instances with an explicit UTC review cutoff. Only fictional targets (`localhost`, `127.0.0.1`, or `*.example.test`) are admitted for shape inspection. All possible outputs include `execution_allowed=False`, `release_allowed=False`: **REVIEW_ONLY is never a permit, evidence of consent, or permission to execute.**

## Acceptance implemented

- Exact dataclass/enum/string/datetime values, no duck typing, generator invocation or mutable list input.
- Canonical 32-character legacy URL-safe token text, conservative synthetic capability and reference identities, and fictional-only target names.
- Duplicate token detection **only inside one input tuple**; fail-closed atomic HOLD (zero inspected) on malformed/oversized/duplicated input.
- Explicit timezone.utc timestamps, no ambient-clock reads; future-dated claims HOLD.
- Error codes only; do not echo input fields, claim provenance, identities or arbitrary object representations.
- No issuance (`ActivationGate.issue` is never called), no provider callback, DNS, socket, SQLite, subprocess, scans, credential handling or authorization.

## Run targeted tests

```bash
PYTHONPATH=src python -m unittest tests.test_scope_permit_claim_batch_1484_20261016 -v
```

The tests are solely in-process, synthetic and offline. No real asset or operator account is involved.

## Isolation and unavoidable hold

Post-issuance review **does not overlap** original ActivationGate producer remediation or pre-issuance scope decision #1482, issued-at linearization #1480, policy binding #1476, legacy capability authority #726, or original gate owners #120/#122/#125/#126. None of those owner paths or CI/runner files were changed.

This tool cannot prove genuine permit origin, signed provenance, customer or operator consent, tenant/asset/capability authorization, one-time use across calls, durable replay tracking, persistent revocation, legal scope or safe runtime source. Its deliberately strict fictional lexical format is **not** the canonical installed production permit contract. Any future integration requires independent source-owner review, human approval, exact-head hosted tests, registered permanent VPS evidence and end-to-end security/privacy validation. Until then: HOLD.