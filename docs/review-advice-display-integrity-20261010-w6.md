# LightUp M3/M7 — W6 opt-in remediation display-integrity acceptance

**Status: DRAFT/HOLD. Synthetic, no-target reference only.**

## Gap and scope

Issue #898 describes the default review pipeline's missing remediation-advisor output gate. W5 draft PR #1180 introduces a non-authorizing full-batch preflight and advisor identity/content guard, but its opt-in guard accepts otherwise bounded nonblank content that includes bidi overrides, control bytes, invisible format characters, surrogate code points and misleading/private-use Unicode.

These code points can corrupt or visually reorder rendered remediation advice and its surrounding evidence context. This W6 child now checks **every forwarded presentation field across the entire finding batch, before the first model call**, including root/per-finding targets, title, severity, impact, fix, evidence summary/reference IDs and coverage-count keys. It also checks **all three model replies** for correct role/model/provider identity and display-safe nonblank content, before a verifier verdict can influence the advisor and before the report is returned to callers. Three canonical role bindings and their registered provider object identities are pinned before the first request and checked again before/after each model response; a mutable gateway cannot silently redirect a later role or swap in a different same-ID provider object mid-batch. It does **not** alter the canonical pipeline or report publisher.

## Implemented

- `src/lightup/ai/review_advice_display_integrity.py`: an opt-in strict text validator and gateway delegate composed over W5 admission + advisor response checks.
- `tests/test_review_advice_display_integrity_20261010_w6.py`: real offline `AssessmentReviewPipeline` + `ScriptedProvider` synthetic tests for the role ordering, invalid first/second advisor output, malformed later finding title/impact/severity/evidence/target/fix (zero model calls), duplicate evidence, invalid root/coverage keys, spoofed verifier/report identity, mutable role/model rebinding, same-ID provider registry swaps, unsafe model text, redacted errors, byte-vs-character bounds, exact-type confusion, untouched caller input and valid international/multiline advice.
- This document is the third **add-only** file. W5 source, issue owners and production entrypoints are not edited.

Both input and output checks permit tab and LF for human-readable multiline guidance, and otherwise reject Unicode category C (control, format, surrogate, private-use, unassigned). It does **not** strip or normalize accepted advice, rejects invalid UTF-8, and enforce both 8192 characters and 16384 UTF-8 bytes on each checked field. This is deliberately conservative: compatibility of presentation clients must be reviewed before any adoption.

## Trust and implementation restrictions

A passing result means only that synthetic remediation **display text** has a safe presentation shape. It **does not** prove the finding, evidence, remediation, provider, tenant, or outcome are real; it **does not** approve a fix, grant target interaction, verify a retest, or authorize publication. The W5 batch checker is only a snapshot preflight and is **not** trusted authentication or revocation. The W6 wrapper does not undo model disclosures already made to the verifier/advisor: source owners must enforce trusted action-time tenant consent before ANY real external provider call.

Do not merge or deploy as a replacement for source-owner #846/#843 pipeline, review #900/#902/#1179, canonical evidence #828/#856/#886, or future release gates. Human/source-owner integration, ordinary passing production-entrypoint regressions, independent privacy/security review, exact-head hosted CI, **registered permanent LightUp VPS CI**, and actual disclosure authorization are still required.

No customer data, live target, real provider, external network, scanning, evidence collection, permission grant, remediation or retest execution, security verdict, proxy/runner mutation, production SQLite, merge, or deployment was used.

## Offline tests

```bash
PYTHONPATH=src python -m unittest tests.test_review_advice_display_integrity_20261010_w6 -v
```

Base: W5 draft #1180 at immutable `acfe8767c4985b94afe8a8f6ee1443bd2b722ccb`. This is a reviewable opt-in child, not a source-owner replacement.

## Next owner-controlled gates

- Run final exact-HEAD offline preflight + real-producer integrations on Python 3.11 and 3.14. Earlier green runs on older SHAs do not validate the new admission checks.
- Keep the default `AssessmentReviewPipeline.review` untouched until source owner #846 integrates the whole review-integrity composition and converts every relevant upstream `expectedFailure` into an ordinary PASS against the real entrypoint.
- The reviewer must not confuse display-safe verifier strings with **verified** evidence: none of these presentation checks prove source authenticity or retest success.
- Confirm any consumer's rendering/Unicode compatibility and authenticated tenant-bound provider disclosure policy. Do not treat this opt-in wrapper as an authorization or XSS sanitizer.

## W6 extension — offline metadata admission

- Every model response must carry exact built-in nonnegative `input_tokens` and `output_tokens` counters from 0 through 1,000,000. Booleans, custom int subclasses, negative/over-limit integers and other types fail closed at the role response boundary. These are **untrusted provider-reported usage metrics**, not billing evidence or authentication.
- Every finding's severity label must match an exact canonical `Severity.value` string from the installed model enum (`info`, `low`, `medium`, `high`, `critical`). Mixed case, padding or made-up severity labels deny the **whole batch before any provider call**. No coercion/repair or severity recalculation happens.
- Synthetic offline tests exercise each failure across all three model roles, rejecting downstream dispatch and preserving canonical positive examples. The rejection code never echoes private finding input.
- Independent of the per-answer 8192-character/16384-byte limits, cumulative accepted remediation-advisor text is capped at **32768 UTF-8 bytes across a whole batch**; an over-budget later reply fails before the report-synthesizer model request. This limits runaway prompt growth but cannot reverse earlier verifier/advisor requests; synthetic 4-item positive and 5-item negative tests cover ASCII and multibyte byte accounting.
- A separate opt-in gateway wrapper converts provider/gateway exceptions into a fixed non-revealing `review model provider failed` error, suppressing private provider/credential/prompt detail in the exception display. Deliberately invalid advisor output remains handled by the dedicated, deterministic W5 validation error. This does not cancel a provider request already attempted.
- These optional checks are **not** a finding validation service, permission to call external providers, authenticity attestation, evidence verification or remediation/retest proof. Source-owner composition and independent review remain mandatory.

The binding snapshot is a **consistency check only**, not a cryptographic identity proof, provider trust root, target authorization or a defense against mutations **inside** the same provider object or modifications to provider implementation code. The consuming application must own its trusted provider registry and disclosure decision.
