# LightUp #1289 W3 — opt-in atomic strict scope *planning* batch

**Phase:** INCUBATE M3/M7 PLAN/LAB ONLY · **DRAFT/HOLD / NO MERGE / NO DEPLOY**.

## What is implemented
A new **optional, non-authorizing** `src/lightup/strict_scope_batch_preview_optin.py` composes the existing [strict target lexical policy from source-owner draft #1290](https://github.com/Zennay/Lightup/pull/1290). It does not alter `scope.py`, `activation.py`, the #1290 parser, the #1291 independent permit-order tests, default CLI/UI/production wiring, or any other worker files.

`preview_scope_batch(strict_policy, targets)` accepts only **exact** `StrictTargetScopePolicy` and an exact immutable tuple with **1–64 exact `Target` records**. All target values are length-bounded, all labels are strict tuples of bounded canonical labels, and any optional authorization is an **exact `Authorization` record** with safe bounded ASCII owner/reference, fixed-offset aware timestamps and ordered validity. This check is only structural: it **does not authenticate ownership/consent, validate a real signatory, authorize a public target, or mint permits**. Source `ScopePolicy` remains the sole owner of actual legacy loopback/private/explicit-host/network and current authorization decisions.

It first validates the entire batch before invoking any policy decision, then evaluates every strict target without partial results. A malformed, unauthorized, duplicate-normalized-host, invalid or late-denied input refuses the **whole batch** with constant `ScopeBatchRejected("scope batch refused")`, never exposing private target, reference or traceback. On all-eligible input it returns only sorted aggregate category counts plus hardcoded `grant_issued=False` and `execution_enabled=False`; **no raw hosts or authorization text, no token, no executor hook and no network**.

There are no calls to `ActivationGate`, DNS, sockets, HTTP, scanning tools, model providers, database, risk-elevation approvers or real targets. Successful preview **must never be interpreted as ongoing or future authorization** and a caller must not adapt this receipt as an execution credential. Strict policy's time-of-check status can expire immediately; future active execution always requires new source-owner approval and live revalidation.

## Offline acceptance
New `tests/test_strict_scope_batch_preview_optin_20261013.py` has **19 regular** synthetic `unittest` methods (not expected failures): positive loopback/private/explicit authorized host aggregation, redacted receipt, original canonical-host collision and port duplicates, late malformed control characters, userinfo/bad ports/encoded authorities, absent/expired/outside public grants, private-lab policy restriction, empty/65/non-tuple input, fake policy/subclass, fake target/subclass, fake nested authorizations, invalid identity text/types, invalid/naive/reversed timestamps, malformed labels, pre-decision whole-input canonical validation, no-activation receipt and constant privacy-preserving refusal.

These are strictly offline `.test` synthetic domains/loopback/RFC1918 literals; the code never accesses or resolves any of them.

## Parallel ownership and release
This branch starts from frozen #1290 exact head `9d6041dbdac37a56462d2e0279416c052fe67908` and creates **only three NEW paths**: opt-in module, offline unit tests and these owner integration notes. Existing code/source owner/main/other workers untouched; independent [#1291](https://github.com/Zennay/Lightup/pull/1291) remains separate. Strict owner must review this composition before any potential integration. GitHub-hosted Python 3.11+3.14 and separate permanently registered VPS exact-final-head CI, current-main composition, independent privacy/security review, and explicit human merge/deploy authorization are mandatory.

**NO MERGE / NO DEPLOY / NO GRANTS / NO REAL TARGET INTERACTION**, regardless of hosted CI status.
