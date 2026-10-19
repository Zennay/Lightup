# LightUp — PRIVATE Evidence Handoff Inbox

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No main merge or production deployment.**

## Use the offline product

This working offline human-coordination companion reads two existing source-owner exports without modifying either owner:

1. [Evidence Artifact Ledger PR #1642](https://github.com/Zennay/Lightup/pull/1642): export the original unified PRIVATE human evidence workspace v2 JSON.
2. [Human Response Reconciliation PR #1643](https://github.com/Zennay/Lightup/pull/1643): export the original PRIVATE human response register backup v1/v2 JSON. Do not substitute individual owner-request or owner-reply packets.

**Portable single-file version:** [Open or save standalone.html](standalone.html). This published offline HTML has embedded JS/CSS pinned by exact SHA-256 CSP hashes, with all network connections disabled. It is the simplest human preview; no local build or third-party dependency is necessary.

Development source remains split into three editable files. Obtain the three product files together from this directory: [index.html](index.html), [app.js](app.js), and [style.css](style.css). Open index.html locally in a browser; no installation, credentials, server or network connection is required. Choose both privately obtained JSON files and click **Inspect human handoff**.

The inbox matches the *declared* original source SHA-256, exact source contract, self-declared client and engagement labels, all-twelve-false non-authority flags, and complete original HUMAN request identity. It refuses ambiguous JSON duplicate keys, invalid UTF-8, oversized files, duplicate or orphan owner replies, stale original human instructions/kinds/dates/assignee and incomplete review records. Rejection does not replace already imported in-memory HUMAN state.

**Important:** Matching self-declared source labels does not independently verify the original exported five-column CSV, real client/recipient identity, provenance, fresh consent, active scope or remediation. Original source and sender must be separately authenticated through the approved channel. No original source migration is performed.

### Concrete human workflows

The integrated table shows exact original finding/request IDs; declared owner; original request kind; unverified HUMAN response state; local file fingerprint count; and follow-up prompts for unanswered HUMAN requests, HUMAN replies needing changes, absent LOCAL fingerprints, request-linked local SHA missing from this LOCAL ledger, and past tentative HUMAN dates. Search, filter, individual selection and select-all-visible keep review focused.

Outputs require explicit human confirmation and are deliberately separated:

- **PRIVATE selected reviewer JSON:** selected original HUMAN request/finding IDs, original instructions, unverified response text, human notes and only locally recorded SHA/size/name metadata. All twelve authority flags remain false. File contents are never included.
- **PRIVATE human discussion agenda:** selected original HUMAN request IDs and unverified local human context, as plain text.
- **Anonymous aggregate CSV:** counts grouped only by original HUMAN request kind, unverified HUMAN reply stage and LOCAL fingerprint presence. It excludes original IDs, SHA fingerprints, declared client/engagement, notes, names, local file names and individual date stamps.

An apparently anonymized small cohort can still be sensitive. The receiving person, channel, storage policy and disclosure must be checked separately. Missing LOCAL evidence does not prove evidence absent globally. A response, file hash or human review is not proof a fix occurred or a retest passed.

**Forget** clears imported private source objects, selections and file-picker references in browser memory. It cannot erase files already downloaded to disk.

### Security and release boundaries

- Only new files under the independent remediation-handoff-inbox directory; no original source owner files, scanner, webapp, authorization, grants, CI configuration or other worker claims changed.
- CSP limits resources to local scripts/styles and forbids connections and external assets. No server, fetch, XHR, model request, network target, browser persistence or cookie use.
- Untrusted private strings are rendered only with textContent; no untrusted HTML is executed.
- No actual remediation, retest execution, authenticated client/operator consent, action-time revocation claim, source-verification claim, release approval or security verdict.

**DRAFT/HOLD until existing mandatory gates are satisfied:** exact-head hosted AND permanently named VPS CI, original source-owner and independent security/privacy reviews, original #177/#182/#829, genuine separately authenticated client and operator consent including action-time revocation, and explicit HUMAN GO. This product is not to be merged into main or deployed in production without those gates. No QA/regression/test suites were created or run for this work.
