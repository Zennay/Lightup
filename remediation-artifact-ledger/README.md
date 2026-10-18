# LightUp · Evidence Artifact Ledger (PRIVATE / offline)

**Status:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. No original source-owner takeover, main merge, CI bypass, scanner, live target, authorization or deploy.

## What this delivers

A complete offline browser workbench for attaching **local SHA-256 file fingerprints** to **exact original LightUp finding IDs**, with human-only review statuses/notes, exact-source private handoff, strict private restoration, on-demand file recheck, anonymous aggregate export and Forget All. It uses the original unchanged `casework/remediation-engine.js` import contract from the pinned source-owner commit `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b`, SHA-256 `c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225`.

1. Obtain a **separately authenticated original five-column LightUp findings CSV** for the correct client and engagement. This application cannot authenticate or establish that relationship. Enter private human-checked labels and import the CSV.
2. Choose an original finding and one or more local evidence files (up to 16 MiB/file, at most 120 records). The application hashes contents **only in browser memory**, discards the file content after fingerprinting and retains filename/length/digest/MIME/local timestamp.
3. When an independently authenticated revised original CSV arrives, use the **Original source revisions** preview and explicit same-engagement confirmation. This calls unchanged original `LightUpCasework.compareSource`: only exact unchanged five original columns retain human-only fingerprints. Added/changed/missing finding IDs are shown, with explicit **absent is never proven fixed**. Before applying, manually export the OLD PRIVATE ledger as a protected backup: fingerprints on changed/absent original rows are quarantined to the prior saved private version and are never silently transferred to a different source.
4. Select any filtered set of precise `finding_id + local file SHA-256` fingerprints. Stage human-review statuses and/or reviewer aliases, inspect exact old-to-new values and apply only after confirmation and a complete original human baseline comparison. Undo the last HUMAN batch up to 20 steps, refusing undo if original source or later human notes drifted.
5. Review each fingerprint. Set a *human-only* stage, reviewer alias and note; filter by finding, original title or human notes; reselect the original local file on demand to compare exact byte digest and length. A match never validates its provenance, truth, chronology or that an issue is remediated.
6. After explicit confirmation, export PRIVATE JSON. Re-import only after loading the independently validated same original five-column source and identical self-declared client + engagement context; strict duplicate-key checks and all-or-nothing schema and original source checks apply. Restoring replaces the entire in-memory human draft only after confirmation.
7. Review the **original-finding coverage desk**, which ranks critical/high original findings that have **no local artifact fingerprint yet**. Filter all unlinked findings or human follow-up requests and jump to the exact original finding to attach a file. Export a separately confirmed PRIVATE original-ID coverage CSV containing only original severity/source-retest *claims* and local fingerprint/human-review counts, never filenames or raw notes. Missing in this local ledger is NOT evidence missing globally or a verified security exposure.
8. Export an entirely separate counts-only CSV with severity and human-stage metrics (no source hash, client context, IDs, filenames, targets, notes or raw evidence). Explicit **Forget** clears the in-memory source and working draft; already-downloaded files must be disposed of according to the actual data policy.

### Portable file

Open `standalone.html` from an authorized local checkout or separately provided trusted build. It is a single offline file with inline SHA-CSP-pinned immutable original Casework parsing engine, own JS and CSS; `connect-src 'none'`, no remote dependencies, browser persistence, cookies, service workers, scanners or model calls. `index.html` + `ledger.js` + `style.css` are readable development sources and require the unchanged original adjacent `casework/` folder.

Build on the self-hosted trusted runner or permitted zSSH, without QA or regression:
```sh
python3 remediation-artifact-ledger/package.py
node --check remediation-artifact-ledger/ledger.js
```
The deterministic builder **fails closed** if original Casework JS differs from pinned SHA or if source injection patterns differ. The release is not claimed green because building does not replace existing exact-head hosted and permanently registered named VPS CI.

### Private data and security limits

Do not attach credentials, private keys or undisclosed client data to a public issue/PR. PRIVATE JSON includes sensitive names, file fingerprints, human notes and context labels; the tool never encrypts that export. A SHA fingerprint is neither a signature nor proof of consent, owner approval, source authenticity or verified remediation. The human stages `unreviewed`, `human_review`, `follow_up`, `archived` are not acceptance or authorization.

**Release HOLD:** original exact-head hosted and named permanent VPS CI; original source-owner review; independent security/privacy review; canonical issues #177/#182/#829; independently authenticated separate client/operator consent with action-time revocation; explicit HUMAN GO. No main merge, live deploy, scan, retest or client authority without all required gates.
