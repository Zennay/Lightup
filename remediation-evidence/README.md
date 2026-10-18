# LightUp Remediation Evidence Review Board

**Stage: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Never use this as permission to scan.

## Working product
**Quickest way:** download and open remediation-evidence/standalone.html locally. It is a complete single-file application with the exact original Casework parser and this review UI embedded under per-script SHA-256 CSP hashes. No checkout or local server is necessary. For source development, remediation-evidence/index.html also works from a full checkout containing the original sibling casework/remediation-engine.js. Everything runs offline without cookies, network, storage, a server, credentials or runtime targets.

The deterministic stdlib bundler remediation-evidence/package.py refuses a changed original Casework JS (pinned SHA-256 c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225) and writes standalone.html atomically. The produced one-file artifact was built with authorized zSSH on vps-bb300bba: 44,068 UTF-8 bytes, SHA-256 3d46fe94dab024c8581f031b4b65f847cf4619e7860feea4a6a44ec06a53be07.

This new isolated implementation is **stacked on original Casework PR #1568**, pinned to immutable original commit 9c73e8468ce271bf8c6bef4cac071e5ad9c1806b. No original Casework source or active owner branch is changed.

1. Independently obtain the **real authenticated, tenant-restricted** five-column LightUp findings CSV using the existing export workflow. Import that source locally (1 MiB/350 findings maximum).
2. Optionally import the **original Casework v1 private JSON** (2 MiB maximum); separately acknowledge the same client and engagement, with every original finding field matched and a matching canonical SHA-256 when the original draft includes one. The browser does not verify the independent human assertion.
3. See high-severity source findings, reported regressions, human blockers, reference gaps and contradictions with original locally completed Casework records. Source retest status stays read-only.
4. Optionally preview a newer separately authorized original CSV, explicitly confirm the same client/engagement and apply a source refresh atomically. Source-added or changed findings reset local review and Casework notes; only records with all five original fields unchanged retain local notes. Missing rows are NOT treated as fixed. Export the previous private draft before replacing the local view.
5. Coordinate a local human status (missing / submitted / needs_changes / ready_for_authorized_retest), descriptive private reference, reviewer and next step per finding. This never invokes a scan or completes an actual retest.
7. Optionally set one local human coordination stage or reviewer across the currently filtered findings. Confirm the affected count before bulk update; original source and retest state remain unchanged.
8. Save an unsigned private review JSON; resume it only with the exact original source SHA. Strict duplicate-key JSON parsing, hard file and nesting limits, exact non-authority flags, expected IDs and atomic rejection of incomplete or mismatched packets are applied.
9. Export only aggregate counts without original findings/people/notes, or consciously export a **private Markdown** human coordination brief containing original finding IDs and local notes.

## Trust boundaries
- The original Casework parser, source normalization, canonical content SHA-256 and draft v1 loader are **reused** from original owner source. A source-digest-compatible local SHA-256 fallback works when WebCrypto is unavailable on file:// offline pages. SHA is an unsigned correlation fingerprint, **never authentication or a signature**.
- No external assets, network calls, file upload, browser persistence, real finding mutation, granted scope, client consent, scanner execution or verified retest.
- A local “completed” or “ready” status is not evidence of a fix. A source-reported “fixed” status remains historical, not an independently proven currently valid retest. Missing findings in later exports are not proof of repair.
- Real evidence files are intentionally **not** imported or stored. Leave sensitive artifacts in the authorized client workflow; never enter passwords, customer secrets or raw exploit evidence as references.
- Private source exports and Markdown handoffs may contain confidential details. Protect and share only via independently approved channels. Aggregate source hashes may correlate separate documents.
- Invalid source does not replace the current in-memory board. Human notes are kept only in the open tab until explicit private export.

## Release
The parent Casework source is DRAFT/HOLD, and this child remains DRAFT/HOLD. No merge into main or production deploy until original exact-head hosted and permanently named VPS CI, source-owner/privacy/security review, actual separately authenticated client/operator consent, at-use revocation throughout original runtime, existing scope/domain owner fixes #177/#182/#829 and explicit HUMAN GO. Existing security, evidence integrity and consent gates are unchanged.

No QA/regression suites added or run under the October 17 product-only execution policy.
