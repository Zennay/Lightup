# LightUp evidence-remediation #898 — provider-output type boundaries (2026-10-13)

This is a new **tests/docs-only branch**, pinned to immutable review-integrity pack v2 `de205d1b898efb605897c65c7f084c8fa9cef80d`, in the same #846 review lineage. No edit to the pack owner's source or existing tests/docs. No change to `src/lightup/ai/pipeline.py`, gateway/provider, labrun, report, auth, scope, main or any other worker branches.

## Narrow independent test gap

Issue #898 and the existing v2 pack require refusal of empty/whitespace remediation-advisor responses before REPORT_SYNTHESIZER. The model gateway defines `ModelResponse.content: str` as a type annotation but **does not enforce that field type at construction**. A provider can return malformed, otherwise truthy objects instead of an exact built-in `str`, and the current #846 pipeline does not explicitly validate the advisor output before report synthesis.

The new `tests/test_evidence_898_advice_type_red_20261013.py` uses an actual bound `ModelGateway` with a synthetic scripted provider, real `AssessmentReviewPipeline`, and a request-role spy. Six unittest methods:
- Two normal green controls: exact built-in Unicode advice accepted, and valid review leaves caller input unchanged.
- Four **intentional expected-RED** tests: `None`, `bytes`, `int`, and `str` subclass advisor response must be refused with a controlled `ValueError` **before** the report model call; input is preserved. These cases do not change the #898 blank-text acceptance contract, and are not proof of a fix.
- Important nuance: a bytes response can currently raise incidental `TypeError` downstream during JSON serialization. A source owner must fail early with a stable error contract rather than considering that incidental error a satisfactory gate.

## Validate after owner-approved composition

```sh
PYTHONPATH=src python -m unittest -v tests.test_evidence_898_advice_type_red_20261013
```

**Branch-only / no duplicate PR or VPS workflow** while existing #846 and the permanent runner queue remain active. No hosted or VPS exact-head CI claimed on this branch. A source owner should integrate strict exact built-in nonblank output validation before any report role call, preserve success ordering, convert RED to plain passing tests and obtain privacy/security review, latest-main compatibility, exact-head Python 3.11/3.14 hosted CI, separate permanent registered VPS CI, and explicit human release approval.

LightUp **Incubate M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY**. This is lab-only text-shaping integrity; no real target, scanning, evidence collection, authorized execution, remediation, retest or security verdict authority.
