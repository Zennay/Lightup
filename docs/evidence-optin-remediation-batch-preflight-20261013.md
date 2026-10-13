# Opt-in immutable remediation input preflight — evidence M3/M7

**State:** new callable, implemented but **NOT INSTALLED** in the default AI review pipeline. LightUp is **INCUBATE / PLAN-LAB ONLY / DRAFT-HOLD / NO MERGE / NO DEPLOY**.

## Why this exists

The current source-owner review pipeline (PR #846, issues #899/#901/#902) dispatches the first verifier model before validating a finding's `fix`, and accepts repeated evidence references. Fixing its existing source file directly would collide with its active owner and stacked review integrity packs. This deliberately distinct **additive module** provides a complete opt-in pre-model input gate that can be evaluated independently while those branches remain untouched.

Source: `src/lightup/ai/remediation_input_preflight_optin.py`; tests: `tests/test_remediation_input_preflight_optin.py`.

## Contract

`prepare_remediation_review_inputs(lab_result)` is a pure, non-network function. It only accepts exact built-in JSON-like `dict` and `list` containers. Each finding must provide canonical exact built-in nonblank bounded text fields: title, severity, impact, target display label, current remediation fix and evidence summary. It rejects noncanonical string subclasses and Unicode surrogate code points before downstream text serialization. Finding-local `evidence_ids` must be an exact list of unique, nonblank, bounded exact strings. If absent or explicitly empty, a canonical nonblank single-lane top-level `evidence_id` may be used. No sorting, trimming, coercion or repair is performed; canonical order and exact remediation whitespace remain intact.

Bounds: 64 findings, 64 evidence refs per finding, 256 characters per evidence reference, 4096 characters each per evidence summary or fix, **65536 characters across all current fixes**, and smaller explicit bounds for display metadata. The function checks input cardinality and fix lengths before snapshot creation; even one late bad finding rejects the entire batch with a controlled `ValueError` and no returned partial result.

The return type consists exclusively of frozen, slotted dataclasses and immutable tuples/strings. There are no aliases to mutable caller containers, no evidence payload bytes, no model role invocation, no auth/grant/decision status, no database writes, and no target contact. This output is **not** proof of verified evidence, an active grant, an authorization boundary, a verdict, or a real remediation.

## Validation and source-owner handoff

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_remediation_input_preflight_optin.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The 22 standalone tests require **22 ordinary PASS**, no expected RED. They cover atomic whole-batch input rejection, exact types/subtypes, fix budget and per-field length caps, canonical ordering and fallback, intra-finding duplicate references, cross-finding shared IDs, input preservation, immutable return snapshots, no raw evidence, and malformed Unicode.

This is a **new optional component** not wired to `AssessmentReviewPipeline.review()`. The #846 source owner must explicitly decide whether/how to admit the full batch *before any verifier/advisor/report dispatch*, compose legacy #899/#901/#902 acceptance, and preserve existing evidence/tenant/authorization checks. No claim that the installed review pipeline now rejects malformed inputs. Require exact-head hosted Python 3.11/3.14, separately registered permanent VPS CI, latest-main integration, security/privacy review, and explicit human release decision before any merge/deploy. Never send customer evidence or external target details through this reference fixture.


## Optional evidence-grounded review (separate from default)

The **new** `src/lightup/ai/review_admitted_batch_optin.py` exports `review_admitted_remediation_batch(pipeline, labrun_result)`. It first admits the full batch via the strict immutable preflight **before any model provider call**. It then uses the configured `AssessmentReviewPipeline.gateway` and existing model roles and return types, but **does not call the existing main pipeline's ungrounded `review()` method**: that legacy method omits finding-local evidence references and evidence summaries from advisor prompts. No existing source-owned `src/lightup/ai/pipeline.py` code is modified. This separate opt-in implementation deliberately sends exact validated metadata to the verifier, passes the exact verdict, evidence summary, evidence IDs and original remediation text to the advisor, and forwards the reviewed verdict/advice to the report synthesizer.

There are three **strict output gates**. The verifier must return a bounded exact string beginning with a canonical `CONFIRMED`, `UNCERTAIN` or `REJECTED` first-line status; the advisor must return bounded nonblank exact string content (including absence of Unicode surrogates); and the report content must also be bounded nonblank. A response impersonating another `ModelRole` is rejected. A rejected verifier response prevents advisor and report calls; a rejected advisor response prevents report calls. These checks **do not authenticate the model, prove the observation or produce an authorized security verdict**.

Each role gets freshly JSON-serialized accepted text metadata only. The wrapper rejects malicious caller object shapes before any dispatch and never carries caller raw evidence payload bytes, arbitrary unvalidated metadata, spoofed authorization claims or asserted coverage counts. Coverage is sent as **empty unknown counts**; current main has no independent coverage admission. Multiple targets are labelled as such in reports, while each finding retains its own exact target label. The immutable snapshot protects subsequent calls if the original caller mutates its dict/list/strings during an earlier model completion. Once admission passes, a caller's configured provider **may be remote if the caller intentionally bound it**; no model calls happen on module import, in default application routes, or from these deterministic tests.

`tests/test_review_admitted_batch_optin.py` executes **16** end-to-end synthetic scripted-provider cases: actual three-role dispatch, exact evidence-to-verifier/advisor propagation, malformed late-item atomic admission, provider-visible privacy boundaries, original-input post-admission mutation isolation, blank/incorrect model output rejection, forged model response roles, empty/unknown coverage semantics and preserved distinct findings.

```bash
PYTHONPATH=src python -m unittest discover -s tests -p 'test_remediation_input_preflight_optin.py' -v
PYTHONPATH=src python -m unittest discover -s tests -p 'test_review_admitted_batch_optin.py' -v
PYTHONPATH=src python -m unittest discover -s tests -v
```

The final acceptance target is **22 + 16 = 38** ordinary PASS in these new modules, plus complete exact-head hosted Python 3.11/3.14 and independent permanently registered VPS CI; no expected-failure decorators or default route activation. This work is still **DRAFT/HOLD / PLAN-LAB ONLY**. Source owner #846 and the #899/#901/#902 review-integrity pack retain ownership of default pipeline integration and release. A preflighted review **does not grant target authorization or evidence authenticity**, and user-provided text remains model-untrusted. A human must independently review privacy/security, exact main composition and deliberate provider opt-in before merge/deploy.
