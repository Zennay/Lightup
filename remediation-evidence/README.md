# LightUp Remediation Evidence Review Board

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Never use this as permission to scan.

## Working product
Open remediation-evidence/index.html from a full checkout containing the original sibling casework/remediation-engine.js. Everything runs offline without cookies, network, storage, a server, credentials or runtime targets.

This new isolated implementation is **stacked on original Casework PR #1568**, pinned to immutable original commit 9c73e8468ce271bf8c6bef4cac071e5ad9c1806b. No original Casework source or active owner branch is changed.

1. Independently obtain the **real authenticated, tenant-restricted** five-column LightUp findings CSV using the existing export workflow. Import that source locally (1 MiB/350 findings maximum).
2. Optionally import the **original Casework v1 private JSON** (2 MiB maximum); separately acknowledge the same client and engagement, with exact canonical original source SHA-256 and every original finding field matched. The browser does not verify the independent human assertion.
3. See high-severity source findings, reported regressions, human blockers, reference gaps and contradictions with original locally completed Casework records. Source retest status stays read-only.
4. Coordinate a local human status (missing / submitted / needs_changes / ready_for_authorized_retest), descriptive private reference, reviewer and next step per finding. This never invokes a scan or completes an actual retest.
5. Save an unsigned private review JSON; resume it only with the exact original source SHA. Strict duplicate-key JSON parsing, hard file and nesting limits, exact non-authority flags, expected IDs and atomic rejection of incomplete or mismatched packets are applied.
6. Export only aggregate counts without original findings/people/notes, or consciously export a **private Markdown** human coordination brief containing original finding IDs and local notes.

## Trust boundaries
- The original Casework parser, source normalization, canonical content SHA-256 and draft v1 loader are **reused** from original owner source. SHA is an unsigned correlation fingerprint, **never authentication or a signature**.
- No external assets, network calls, file upload, browser persistence, real finding mutation, granted scope, client consent, scanner execution or verified retest.
- A local “completed” or “ready” status is not evidence of a fix. A source-reported “fixed” status remains historical, not an independently proven currently valid retest. Missing findings in later exports are not proof of repair.
- Real evidence files are intentionally **not** imported or stored. Leave sensitive artifacts in the authorized client workflow; never enter passwords, customer secrets or raw exploit evidence as references.
- Private source exports and Markdown handoffs may contain confidential details. Protect and share only via independently approved channels. Aggregate source hashes may correlate separate documents.
- Invalid source does not replace the current in-memory board. Human notes are kept only in the open tab until explicit private export.

## Release
The parent Casework source is DRAFT/HOLD, and this child remains DRAFT/HOLD. No merge into main or production deploy until original exact-head hosted and permanently named VPS CI, source-owner/privacy/security review, actual separately authenticated client/operator consent, at-use revocation throughout original runtime, existing scope/domain owner fixes #177/#182/#829 and explicit HUMAN GO. Existing security, evidence integrity and consent gates are unchanged.

No QA/regression suites added or run under the October 17 product-only execution policy.
