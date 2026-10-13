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
