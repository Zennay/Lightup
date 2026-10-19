## PRIVATE HUMAN workroom and exact-source continuity (19 October 2026)

The same offline [standalone.html](standalone.html) now includes a **real human triage workroom**, not just a check-count table.

- Select per literal source-declared capability/check group: HUMAN-only **stage** (needs review, queued, discussing, documented as a human note, blocked), **review group** (unassigned, scope, findings, evidence, remediation, privacy), and next proposed **HUMAN question**. None is a verified finding state, engagement authority, risk reduction, remediation or client consent. Source fields and source bytes are immutable.
- Search and page the private workroom (64 work items/page), filter on local HUMAN status, and open the original untrusted declaration on demand. The main comparison matrix independently renders **100 rows/page**, to avoid a large file set freezing the interface with thousands of DOM rows. Count exports still include **every currently filtered row**, not merely the visible page.
- **Bulk HUMAN routing** applies chosen stage/group/action to up to 512 locally filtered groups after an explicit human confirmation. A complete group larger than 512 is refused, never silently truncated. **Undo last bulk change** restores those local choices; manual updates, reset or private resume invalidate bulk undo.
- **Save PRIVATE plan** downloads original SHA-256-byte-bound source-slot fingerprints, the exact anonymous original sorted matrix row count, and only non-default categorical HUMAN choices indexed by source-local row ordinal. It contains no target addresses, raw findings, source labels, evidence, tenant/client or file path. **It is private and not encrypted**: SHA digests may be identifying; do not publish. File contents are neither encrypted nor signed, and matching the bytes is not proof of authentic original producer, operator identity, ownership or consent.
- To **resume**, first manually re-open the **same original source files in the same selection order**. Then select the saved PRIVATE plan. Every original input hash must match byte-for-byte; the entire plan must have the exact bounded schema, false authority flags, sorted unique canonical row ordinals and enum values. If not, the whole restoration is held and current HUMAN choices remain intact. Even when valid, an explicit second human confirmation is required before replacement. Browser environments without WebCrypto continue to allow in-memory HUMAN planning and source-free briefing but disable byte-bound save/resume rather than inventing a digest.
- **Counts-only HUMAN briefing** produces a self-contained `.txt` with stage/group/question totals **without original source labels, SHA hashes or targets**. A separate human-confirmed **PRIVATE read-only HTML handoff** includes up to 512 explicitly filtered HUMAN-planned source capability/check labels, local row ordinals and categorical choices. That scriptless document uses a restrictive no-network CSP, escapes source-supplied text, excludes target/evidence/raw result bytes and is not source-authenticated or an executable instruction. It **is PRIVATE** because original check labels may reveal sensitive information; exchange separately using an approved protected channel. Missing declarations never imply a fix or clearance.
- **Forget local data** clears the in-memory original files, fingerprints, human notes and selected views. No user accounts, localStorage, browser persistence, cloud sync or networking were added. The application warns on navigation away from a loaded workroom.

### Standalone packaging

`build_standalone.py` now embeds both `human-board.js` and `app.js` (in that order) plus `style.css` into the one-file offline HTML, pinning the **combined** JavaScript and CSS with SHA-256 Content Security Policy hashes. The generated `standalone.html` is committed in this held draft branch. This integrity convenience is **not an independent security audit, review verdict or provenance signature**.

### Non-negotiable posture

**Incubate · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD** remains unchanged. Original source owner, independently reviewed privacy/security/browser source, complete exact-head hosted AND named permanent VPS CI, #177/#182/#829, separate genuinely authenticated current client/operator consent including revocation at action time, and explicit HUMAN GO still remain mandatory before any main merge, live scan, grant, client action, deploy or release. No QA, regression or test suite created or executed as part of this implementation; only production JavaScript syntax and source packaging were inspected directly. No real lab result or target was used.

---

# LightUp · PRIVATE Original Lab Declaration Matrix

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD — human source-declaration review only.**

[Open the standalone offline app](standalone.html) · [Source HTML](index.template.html) · [Source JavaScript](app.js) · [Source style](style.css)

This is an **independent add-only** assessment-runtime product in `assessment-coverage-matrix/`. It does not change the original source owner, held [lab-assess #1610](https://github.com/Zennay/Lightup/pull/1610), the [one-result review desk #1639](https://github.com/Zennay/Lightup/pull/1639), [benchmark comparator #1515](https://github.com/Zennay/Lightup/pull/1515), an active worker claim, the scanner, grants, CI, domain model, deployment or a real target.

## Operator workflow

1. Download **`standalone.html`**, keep it on a trusted private device, and open it locally with a browser. The package contains all styles and logic. No server, dependencies, account, API, fetch, fonts, trackers, source files, test runner or internet is necessary.
2. Obtain **2–8 already-generated original private lab-assess JSON results** from a separately approved lab owner. This tool does not produce, authorize or run lab assessments. Files must be distinct declared run IDs, each ≤8 MiB, and claim the **same literal scenario ID and exact declared endpoint set** (target order may differ). They must follow the pinned original result schema. Same declaration does **not** prove shared ownership, permission, genuine isolation or source integrity.
3. In the browser, select all originals in your desired left-to-right order. Import is **whole-batch**, strict UTF-8 / bounded depth / duplicate-property-rejecting JSON / original evaluation / finding / plan / benchmark-shape admission. An invalid, duplicate or incompatible original holds the *entire new selection*, leaving the prior opened batch intact.
4. Inspect the **literal capability-ID + check-ID matrix**. For each locally selected source, the cell contains only the count and highest source-declared severity for that literal tuple. Click to see private finding statements, endpoint ordinals, source mitigation and source retest proposals. This is not a verified check-run or finding identity comparison. Source-provided text is rendered with `textContent`, never interpreted as HTML.
5. Review the **separate source-reported adverse numeric panel**: the original evaluation claims valid, invalid, missed, unknown coverage, scope violations, policy violations and human interventions for each local source ordinal. Positive adverse values are prominent. **Zero is a source assertion, never evidence of a compliant assessment or policy approval.**
6. Search source literal tuple labels or filter by original severity and endpoint ordinal. **An empty filtered cell means only “not declared under this filter.”** It cannot be interpreted as success, absent vulnerability, full coverage, remediation, valid evidence or a missing scanner check. All original target literals are kept out of the visible matrix. Unmatched original `finding.target` strings receive an *unmatched* endpoint label rather than a guessed assignment.
7. With deliberate human confirmation, download **counts-only JSON or CSV** for the currently filtered rows. Exports contain anonymous row ordinals, counts and (JSON) source-declared severity counts **plus original unverified adverse-counter arrays**, without source IDs. They contain **no** original run/scenario IDs, target URLs, capability/check IDs, finding titles, evidence details, source hashes, file paths or reviewer identities. Small-cell aggregates can still be sensitive; downloads are unencrypted. CSV contains strictly generated nonnegative integer digits, so does not include source-supplied spreadsheet formulas.
8. Choose **Forget local data** to discard all original source objects from this browser workspace. The app has no localStorage, cookies, worker, analytics, DNS, requests, outbound communications or automatic retention. Separately delete any explicit downloaded artifact according to your private retention policy.

### What this is not

The matrix groups untrusted literal labels and the original source-reported adverse metric counters across **already-produced** sources. It does not infer chronology, authenticity, evidence match, completeness, ground truth, negative tests, coverage assurance, client permission, assessment authorization, scanner effectiveness, vulnerability persistence or remediation. A missing source declaration is **never** a fixed issue. Endpoint membership comparison is literal, not DNS-resolved. Severity is source-reported, not independently verified. If original source files disagree on declared scenario/endpoint membership, the app refuses the comparison rather than silently reconciling.

There is **no scan, grant, target probing, model call, dispatch, client contact, human consent collection, file upload or client-facing publication**. This review capability is intentionally useful only for human analysis of already-authorized privately held lab artifacts.

## Rebuild from committed source (optional)

With Python 3 standard library, run from repository root:

```sh
python3 assessment-coverage-matrix/build_standalone.py
```

The builder embeds exactly `index.template.html`, `style.css`, and `app.js` and pins inline JS and CSS hashes in a strict network-free Content Security Policy. The generated `standalone.html` is included in this draft branch. CSP hashes make accidental mismatches visible; they are **not a security audit or provenance signature**. A maliciously supplied complete application could choose its own CSP hashes. Use trustworthy code distribution.

## Original gates — DRAFT/HOLD

LightUp's Notion project phase is **Incubate; M3/M7 PLAN/LAB ONLY**. There is **no green release assertion**, main merge or deployment from this branch. Complete existing original **hosted AND permanent named VPS exact-head CI**, owner acceptance, independent source/security/privacy/browser review, issues **#177 / #182 / #829**, actual distinct authenticated client/operator consent with action-time revocation before any future active work, and explicit **HUMAN GO** remain mandatory. **Do not** use this app to claim authorization, run a test, approve a finding or contact any target. No QA/regression/testsuites are added or run by this implementation.
