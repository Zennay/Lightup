# LightUp PRIVATE Assessment Retention Desk

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** Add-only, fully offline HUMAN operations companion. This is *not* part of an approved active assessment, release, authorization grant, consent workflow, delete automation or evidence verification.

## What the operator can actually do

1. Open \`index.html\` locally from this folder in a current browser on a trusted device. Keep \`desk.js\` and \`desk.css\` alongside it. No web server, backend, extensions or dependencies.
2. Select between 1 and 12 *already-produced* private assessment artifacts, each 1 byte–8 MiB, maximum 64 MiB total. Source bytes are hashed with browser WebCrypto SHA-256 and are **never put into the export**. No file content or filename is rendered by this tool; the file chooser itself naturally knows the selected filenames.
3. Give each sha-bound source an operator-selected alias, HUMAN-only proposal (review / retain / quarantine / propose delete), tentative review date and HUMAN action. Filter, adjust, remove in-memory rows.
4. Export a canonical, **unsigned PRIVATE** \`lightup-private-assessment-retention.json\` for subsequent human work. Includes SHA-256 digest and byte length of each original source plus HUMAN metadata and six literal false authority flags. It is sensitive even without source bytes.
5. Select the exact same original source files again; open the previous plan. The browser rejects the whole import on any changed/missing/extra/duplicated original SHA/size, malformed field or authority assertion. No status, date, action or alias carries unless the complete source set matches **and** the human confirms.
6. Separately export conservative HUMAN proposal totals as CSV or print a PRIVATE tentative overview on a trusted device. Small groups may still be identifiable, so the counts file is not certified anonymous.
7. For a source-bound *multi-plan history*, run the separate standalone \`history.py\` CLI with two to twelve existing private plans, in the user's intentionally ordered sequence; it creates a no-network, scriptless PRIVATE HUMAN change report. No source contents, active target work, proof of historical timestamps or deletion.

## Boundaries and tradeoffs

- All input files may contain client secrets. Only use assets that you may lawfully possess and review. This tool performs **no scanning, model calls, network requests, subprocess dispatch, source modification, deletion or remote sync**. Browser CSP prohibits network connections and externally hosted scripts; no tracking, localStorage, IndexedDB or service workers.
- SHA-256 checks only equality of the *selected bytes*. Hashes/JSON/HUMAN labels **do not authenticate an original creator**, grant, current tenant, engagement, finding, remediation, legal hold or genuine authorized deletion. Source-file names are never serialized, nor are source bodies.
- "Proposed delete" never removes anything or grants permission to do so. Real client retention, legal-hold, consent/revocation and independent approvals must occur outside this application.
- Date fields are tentative user-entered plain dates, not independently verified timestamps. File picking and browser memory are NOT secure erase; old downloaded exports and print spool data remain outside its control.
- Browser file origins may handle WebCrypto differently. If unavailable, the workspace fails closed rather than weakening SHA validation. Use a browser with \`crypto.subtle\` enabled; do not upload private files to another service to get around this.
- A receipt is valid only for the exact **complete** selected file set; an operator must intentionally create a new plan after any source revision. No automatic claim that absence means fixed/deleted.
- \`history.py\` is a read-only view of HUMAN plans. An input sequence is operator-declared, not trusted chronology or source provenance. It never edits receipts. The HTML output contains potentially sensitive aliases, statuses and source hash prefixes.
- No QA/testsuites created or executed by this module. Only permitted syntax / direct product inspection is within scope of this work.

## Browser files

\`index.html\`, \`desk.css\`, \`desk.js\` are the entire UI. Portable as a three-file folder; all resources are local and fetched from the same folder. There are no external dependencies.

## Offline native multi-plan history

\`\`\`sh
python3 assessment-retention-desk/history.py --output /private/operator/retention-history.html /private/operator/plan-01.json /private/operator/plan-02.json
\`\`\`

Output must be a **new**, non-existing file in an existing private directory. It is written privately (0600) using an exclusive create; no silent overwrite. Input plans must have identical original SHA-256 + sizes and the exact tool schema. Fails closed on source drift, duplicates, malformed/oversized/linked files or authority flag changes. It never opens original assessment source files or authorizes a retention action.

## Release boundary

Per Notion: LightUp **INCUBATE/M3-M7 PLAN/LAB ONLY**, all new work **DRAFT/HOLD**. Existing original hosted CI plus permanent named VPS CI, independent security/privacy/browser review, original source-owner acceptance, #177/#182/#829, genuine separately authenticated current client/operator consent with action-time revocation and explicit HUMAN GO remain mandatory. No merge to main, deploy, scan, grant or live target work from this artifact.