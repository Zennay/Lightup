# LightUp M3/M7 — W6 opt-in remediation display-integrity acceptance

**Status: DRAFT/HOLD. Synthetic, no-target reference only.**

## Gap and scope

Issue #898 describes the default review pipeline's missing remediation-advisor output gate. W5 draft PR #1180 introduces a non-authorizing full-batch preflight and advisor identity/content guard, but its opt-in guard accepts otherwise bounded nonblank content that includes bidi overrides, control bytes, invisible format characters, surrogate code points and misleading/private-use Unicode.

These code points can corrupt or visually reorder rendered remediation advice and its surrounding evidence context. This W6 child now checks **every forwarded presentation field across the entire finding batch, before the first model call**, including root/per-finding targets, title, severity, impact, fix, evidence summary/reference IDs and coverage-count keys. It also checks **all three model replies** for correct role/model/provider identity and display-safe nonblank content, before a verifier verdict can influence the advisor and before the report is returned to callers. It does **not** alter the canonical pipeline or report publisher.

## Implemented

- `src/lightup/ai/review_advice_display_integrity.py`: an opt-in strict text validator and gateway delegate composed over W5 admission + advisor response checks.
- `tests/test_review_advice_display_integrity_20261010_w6.py`: real offline `AssessmentReviewPipeline` + `ScriptedProvider` synthetic tests for the role ordering, invalid first/second advisor output, malformed later finding title/impact/severity/evidence/target/fix (zero model calls), duplicate evidence, invalid root/coverage keys, spoofed verifier/report identity, unsafe model text, redacted errors, byte-vs-character bounds, exact-type confusion, untouched caller input and valid international/multiline advice.
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
