# ModelGateway response admission · #786

**LightUp:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. This is an isolated source-owner candidate, not permission to activate models or assessments.

## Product correction

An external or scripted provider can produce arbitrary Python objects. The shared `ModelGateway.complete()` previously trusted `ModelResponse.content` as a built-in string because of its annotation, even if a provider returned a string subclass with overridden `strip`, `encode`, containment or comparison operations. A downstream review, reporting or remediation consumer might then execute provider-controlled behavior rather than operate on ordinary text.

Now the gateway rejects any provider result that is not an exact ordinary `ModelResponse` instance and any `content` whose runtime type is not the built-in `str` **before returning the object to any consumer**. The existing exact provider/model identity gates from source-owner PR #574 remain intact and in order. Ordinary built-in string responses and role routing are otherwise unchanged. This code does not truncate, rewrite, sanitize or make decisions about the semantic correctness of provider output; each downstream consumer retains its existing content and output-size checks.

## Integration path

Based precisely on original shared gateway source-owner #574 head `3ae92d599832220598118b277383e3c667804287`; issue #786 and old acceptance-only #832 are preserved, not edited or claimed. Only `src/lightup/ai/gateway.py` plus this document are changed. Existing tests/QA/workflows remain unmodified and were not manually run.

Mandatory original exact-head hosted and permanently registered VPS CI, gateway source-owner acceptance, independent privacy/security review, genuine separately authenticated client and operator consent plus action-time revocation and explicit HUMAN GO must occur before merge or deployment. **DRAFT/HOLD · NO MERGE/DEPLOY/ACTIVE SCAN/GRANT/MODEL DISPATCH.**
