# Evidence remediation #898 — opt-in remediation-advice gate (2026-10-13)

**Issue:** [#898](https://github.com/Zennay/Lightup/issues/898).  
**Stack:** immutable own tests/docs-only [branch `test/evidence-898-output-type-20261013`](https://github.com/Zennay/Lightup/tree/test/evidence-898-output-type-20261013), HEAD `f4cdfc92daca723ce91bd5ef019234168430c92f`; historical review-integrity pack parent `de205d1b898efb605897c65c7f084c8fa9cef80d`.  
**Posture:** LightUp Incubate M3/M7, PLAN/LAB ONLY; DRAFT/HOLD / NO MERGE / NO DEPLOY.

## Existing bug and ownership

The unchanged [#846](https://github.com/Zennay/Lightup/pull/846) `AssessmentReviewPipeline.review` forwards `ModelResponse.content` from the remediation advisor directly into a `ReviewedFinding` and then `REPORT_SYNTHESIZER`. A `str` type annotation is not runtime checking. Unchanged-pipeline diagnostics in the stacked parent require **7 intentional expected RED** cases for empty, ASCII/Unicode whitespace-only, None, bytes, integers and `str` subclasses, with two standard positive controls.

**We do not modify** the #846-owned `src/lightup/ai/pipeline.py`, the gateway, the report, original model logic, authorization, target-capable code, existing PRs, or `main`.

## Concrete optional adapter

`src/lightup/ai/remediation_advice_gate_optin.py` adds `CheckedRemediationAdviceProvider`, an **uninstalled `ModelProvider` delegate**. For evaluation only, a review harness may register this wrapper *instead of* its synthetic scripted provider; the existing real `ModelGateway` and `AssessmentReviewPipeline` remain unchanged.

It passes through non-advisor responses unchanged, but **immediately after REMEDIATION_ADVISOR output**, before the pipeline can dispatch the report role, requires:

- exact built-in `ModelResponse` with expected role;
- exact built-in `str`, non-empty after `.strip()`, no subclasses/type confusion;
- at most 8,192 Unicode code points and 16,384 UTF-8 bytes; malformed UTF-8 surrogates are refused with a generic `ValueError` instead of surfacing raw content;
- exact built-in integer configuration for any smaller character budget (boolean is refused);
- no mutation/normalization of accepted advice or caller's findings.

This adapter does **not** authenticate model providers, independently validate evidence, authorize target access or establish a verified security verdict. It is a narrow input-integrity demonstration; the installed pipeline remains unchanged and the #846 owner must integrate the final production boundary with correct source ownership.

## Independent acceptance

`tests/test_evidence_898_advice_gate_optin_20261013.py` adds **18** deterministic **real `ModelGateway` + `AssessmentReviewPipeline`** tests using *offline scripted provider* only. It covers Unicode success, every seven parent RED input variants converted into **plain PASS by the opt-in wrapper**, exact/over character and UTF-8 byte budgets, invalid Unicode surrogate refusal, late second-finding refusal before any report request, wrong model role identity, configuration type confusion, and no input mutation.

```sh
PYTHONPATH=src python -m unittest -v \
  tests.test_evidence_898_advice_type_red_20261013 \
  tests.test_evidence_898_advice_gate_optin_20261013
```

Important: the **parent expected RED** against the original pipeline must remain expected-failure until the owner actually repairs default review. A green hosted run with XFAILs is not production approval.

## Safety and release gates

No external model, network/target, live scan, credentials, clients, evidence collection, remediation/retest execution, grant or deployment. The complete chain stays uninstalled. Exact-head Python 3.11/3.14 hosted tests and **separate registered permanent VPS** CI are necessary, but not sufficient. Final acceptance requires owner #846 real pipeline integration; converting all seven RED diagnostics into ordinary PASS; independent evidence/privacy/tenant review, latest-main composition and explicit human release.

**DRAFT / HOLD / NO MERGE / NO DEPLOY.**
