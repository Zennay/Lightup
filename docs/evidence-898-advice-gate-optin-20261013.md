# Evidence remediation #898 — opt-in remediation-advice gate (2026-10-13)

**Issue:** [#898](https://github.com/Zennay/Lightup/issues/898).  
**Stack:** independent add-only clean-main diagnostic, complementary to the original [tests/docs-only #898 acceptance branch](https://github.com/Zennay/Lightup/tree/test/evidence-898-output-type-20261013), pinned HEAD `f4cdfc92daca723ce91bd5ef019234168430c92f`. No source dependency on that branch; original #846 pipeline owner retains production implementation.  
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

`tests/test_evidence_898_advice_gate_optin_20261013.py` adds **27** deterministic **real `ModelGateway` + `AssessmentReviewPipeline`** tests using *offline scripted provider* only. It covers Unicode success, every seven parent RED input variants converted into **plain PASS by the opt-in wrapper**, exact/over character and UTF-8 byte budgets, invalid Unicode surrogate refusal, late second-finding refusal before any report request, wrong model role identity, configuration type confusion, and no input mutation.

```sh
PYTHONPATH=src python -m unittest -v \
  tests.test_evidence_898_advice_type_red_20261013 \
  tests.test_evidence_898_advice_gate_optin_20261013
```

Important: the **parent expected RED** against the original pipeline must remain expected-failure until the owner actually repairs default review. A green hosted run with XFAILs is not production approval.

## Safety and release gates

No external model, network/target, live scan, credentials, clients, evidence collection, remediation/retest execution, grant or deployment. The complete chain stays uninstalled. Exact-head Python 3.11/3.14 hosted tests and **separate registered permanent VPS** CI are necessary, but not sufficient. Final acceptance requires owner #846 real pipeline integration; converting all seven RED diagnostics into ordinary PASS; independent evidence/privacy/tenant review, latest-main composition and explicit human release.

**DRAFT / HOLD / NO MERGE / NO DEPLOY.**

## Clean-main CI isolation

The review-integrity pack predecessor contains 7 **ordinary failing RED canaries** on unchanged #846 product files. The earlier stacked DRAFT #1269 therefore cannot be treated as all-green hosted acceptance, despite all 18 new opt-in tests passing. This isolated add-only branch starts on `main`, uses the same three independent source/test/docs artifacts, and intentionally does not copy the pack, modify its tests, suppress real failures, or change any #846 owner file. CI on this branch demonstrates only the optional adapter with baseline `main` gateway/pipeline; it is **not** approval of the unmerged review-integrity pack, issuer/tenant/auth, or the production pipeline fix.

## Oversized output fast refusal — 2026-10-13

The adapter now checks the exact built-in `str`'s `len(value)` **before** calling `.strip()`. The earlier expression evaluated `.strip()` first and could scan a very large text response before discovering the 8,192-character budget violation. New synthetic 8-MiB-string regression verifies fail-closed before REPORT_SYNTHESIZER; it is not an RSS/time benchmark and no production model was called. Total **27** real opt-in pipeline tests in this clean-main PR. Older CI receipts belong to superseded commits only: exact new-head hosted and permanent registered VPS evidence is needed.

## Advisor provider/model identity + exception opacity — 2026-10-13

The explicitly registered opt-in wrapper now **pins the delegate's provider ID once at construction**, and refuses an ADVISOR response if its exact built-in provider ID or model ID differs from the pinned provider identity / requested model ID. A wrong-role result remains rejected. These checks run **inside the wrapper, before** the unchanged gateway or report synth is invoked, and do not alter the original source owner module. The wrapper also converts exceptions raised by the ADVISOR provider into the same generic `ValueError` **after leaving** its `except` block, avoiding secret-bearing raw `__context__` and `__cause__` references. Other model roles are still transparently delegated; this is not an all-role security boundary.

Five genuine synthetic in-process acceptance tests cover swapped provider ID, swapped model ID, mutated provider identity after binding, private error text and exception-context sanitation, and non-advisor pass-through. **Total 24** optional adapter methods. A provider binding ID is only a declared string and is **not** a cryptographically authenticated origin, tenant approval, current permission grant, or signed model output. The comprehensive older [#1181](https://github.com/Zennay/Lightup/pull/1181) optional reviewer integrity pack remains a separate owner slice; no files/branches from it are edited. The final production #846 reviewer still needs independent source-owner integration, full privacy/auth validation, conversion of unresolved RED to plain green, latest-main and registered permanent VPS CI.

The prior hosted **4/4 success #38419804615** applies to the superseded `e4bda04b04b385b6a079842e81684df7095fcb4f` only. Do not claim green exact-head status until the new head's hosted Python 3.11/3.14 and independent registered VPS jobs finish. **DRAFT/HOLD/NO MERGE/NO DEPLOY**.

## Single-fetch provider ID and no hidden constructor secrets — 2026-10-13

A `ModelProvider.provider_id` property is arbitrary provider-controlled Python code. Reading it for type, whitespace, then again to bind permits inconsistent time-varying strings or raw failure messages. The opt-in adapter now reads it **only once**, validates the exact built-in `str` snapshot before binding, and maps getter exceptions to neutral `ValueError` outside the exception block (no retained secret-bearing `__context__`). Three more synthetic in-process tests prove a mutating property is read exactly once, a getter with a private error is sanitized and exact type rejects a `str` subclass. Along with the five previous origin/error scenarios, **27** independent optional adapter tests on this clean-main proposal. This is still NOT provider cryptographic identity or proof of approved external model disclosure.

All new work stays confined to this worker's three opt-in source/tests/docs paths, with no `src/lightup/ai/pipeline.py` or #1181 owner modifications. Superseded commits' hosted green results cannot validate this exact head. **DRAFT/HOLD; no merge/deploy; permanent registered VPS and source-owner integration still mandatory.**
