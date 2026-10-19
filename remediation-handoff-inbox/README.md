# LightUp — PRIVATE Evidence Handoff Inbox

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No main merge or production deployment.**

## Use the offline product

This working offline human-coordination companion reads two existing source-owner exports without modifying either owner:

1. [Evidence Artifact Ledger PR #1642](https://github.com/Zennay/Lightup/pull/1642): export the original unified PRIVATE human evidence workspace v2 JSON.
2. [Human Response Reconciliation PR #1643](https://github.com/Zennay/Lightup/pull/1643): export the original PRIVATE human response register backup v1/v2 JSON. Do not substitute individual owner-request or owner-reply packets.

**Portable single-file version:** [Open or save standalone.html](standalone.html). This published offline HTML has embedded JS/CSS pinned by exact SHA-256 CSP hashes, with all network connections disabled. It is the simplest human preview; no local build or third-party dependency is necessary.

Development source remains split into three editable files. Obtain the three product files together from this directory: [index.html](index.html), [app.js](app.js), and [style.css](style.css). Open index.html locally in a browser; no installation, credentials, server or network connection is required. Choose both privately obtained JSON files and click **Match evidence + HUMAN responses** for the paired workflow, or choose the evidence workspace alone and click **Inspect evidence-only finding coverage** for complete original HUMAN coverage when a native source overlay is present.

The inbox matches the *declared* original source SHA-256, exact source contract, self-declared client and engagement labels, all-twelve-false non-authority flags, and complete original HUMAN request identity. It refuses ambiguous JSON duplicate keys, invalid UTF-8, oversized files, duplicate or orphan owner replies, stale original human instructions/kinds/dates/assignee and incomplete review records. Where complete original Casework/Evidence Review overlays are present, original finding IDs in local attachments and request rows must belong to those overlays. Discordant unverified answers between existing human snapshots are shown as follow-up prompts, not silently resolved. Rejection does not replace already imported in-memory HUMAN state; selecting a different file clears the previous review and export controls.

**Important:** Matching self-declared source labels does not independently verify the original exported five-column CSV, real client/recipient identity, provenance, fresh consent, active scope or remediation. Original source and sender must be separately authenticated through the approved channel. No original source migration is performed.

### Full ORIGINAL finding coverage, including evidence-only mode

Click **Inspect evidence-only finding coverage** with the original unified PRIVATE HUMAN evidence v2 export selected. A response register is **not required**, and no original HUMAN request is generated. This is especially useful before owner requests or replies exist. The source-bound board requires at least one complete original native Casework or Evidence Review overlay so original finding IDs can be enumerated; if neither overlay exists, it explicitly refuses to claim complete source coverage.

The **Complete ORIGINAL finding coverage** view enumerates every original ID in the native source-bound overlay, including zero-request findings. Original Casework status, self-declared owner, tentative date, HUMAN blocker/next action and original Evidence Review stage/notes/declared reference fields are shown only as PRIVATE, unverified coordination data. Human prompts distinguish absent LOCAL file labels, no original HUMAN request, missing declared HUMAN owner, Casework blocked, tentative date passed, missing HUMAN reply, Evidence Review follow-up and contradictory *human* statuses. Neither a reported status of completed nor a human retest request is proof of remediation, verified evidence, authorization or approval.

The paired request table includes a direct **Inspect source-bound finding** action that opens the corresponding complete original HUMAN record. The finding board shows the exact declared source SHA/client/engagement visibly even in evidence-only mode. When the ledger has a source-authored HUMAN request not yet imported into the response register, it remains visible on the finding board as a separate unreconciled HUMAN context rather than vanishing or being presented as an authenticated owner reply.

Select individual or all visible original finding IDs and export **PRIVATE source-bound finding action JSON** (only selected original IDs, native HUMAN plans and local metadata labels, no original file bytes) or **anonymous original-finding coverage CSV** (counts grouped by human Casework stage, human Evidence Review stage, LOCAL fingerprint presence and HUMAN request presence; no source identifiers, notes, owners or file hashes). In paired mode, **Select existing HUMAN requests for chosen findings** transfers only already-original-requested rows to the earlier response board. In evidence-only mode this control is disabled. For any missing original HUMAN request, return to the original Evidence Artifact Ledger; this desk cannot create one.

The `package.py` script reproducibly rebuilds the full local standalone HTML with SHA-256-pinned inline CSS/JS and strict offline Content Security Policy. Packaging is not a QA suite and does not satisfy mandatory exact-head CI.

### Concrete human workflows

The integrated table shows exact original finding/request IDs; declared owner; original request kind; unverified HUMAN response state; local file fingerprint count; and follow-up prompts for unanswered HUMAN requests, HUMAN replies needing changes, absent LOCAL fingerprints, request-linked local SHA missing from this LOCAL ledger, and past tentative HUMAN dates. Search, filter, individual selection and select-all-visible keep review focused.

Outputs require explicit human confirmation and are deliberately separated:

- **PRIVATE selected reviewer JSON:** selected original HUMAN request/finding IDs, original instructions, unverified response text, human notes and only locally recorded SHA/size/name metadata. All twelve authority flags remain false. File contents are never included.
- **PRIVATE one-owner HUMAN handoff JSON:** choose the exact self-declared owner alias and export only selected original HUMAN requests belonging to that one owner. Other owners' selected requests are explicitly excluded from that file. No recipient authentication or permission is implied.
- **PRIVATE human discussion agenda:** selected original HUMAN request IDs and unverified local human context, as plain text.
- **Anonymous aggregate CSV:** counts grouped only by original HUMAN request kind, unverified HUMAN reply stage and LOCAL fingerprint presence. It excludes original IDs, SHA fingerprints, declared client/engagement, notes, names, local file names and individual date stamps.

An apparently anonymized small cohort can still be sensitive. The receiving person, channel, storage policy and disclosure must be checked separately. Missing LOCAL evidence does not prove evidence absent globally. A response, file hash or human review is not proof a fix occurred or a retest passed.

**Forget** clears imported private source objects, selections, file-picker references **and rendered visible/hidden original source labels, casework details, metrics and owner drop-down options** in browser memory. Choosing a different input file also clears the previous data/export view until the new pair is admitted. It cannot erase files already downloaded to disk.

### Security and release boundaries

- Only new files under the independent remediation-handoff-inbox directory; no original source owner files, scanner, webapp, authorization, grants, CI configuration or other worker claims changed.
- CSP limits resources to local scripts/styles and forbids connections and external assets. No server, fetch, XHR, model request, network target, browser persistence or cookie use.
- Untrusted private strings are rendered only with textContent; no untrusted HTML is executed.
- No actual remediation, retest execution, authenticated client/operator consent, action-time revocation claim, source-verification claim, release approval or security verdict.

**DRAFT/HOLD until existing mandatory gates are satisfied:** exact-head hosted AND permanently named VPS CI, original source-owner and independent security/privacy reviews, original #177/#182/#829, genuine separately authenticated client and operator consent including action-time revocation, and explicit HUMAN GO. This product is not to be merged into main or deployed in production without those gates. No QA/regression/test suites were created or run for this work.
