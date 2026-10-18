# LightUp · Change Window & Handoff Board

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. Offline human coordination, not a grant, deployment, scan, verified patch, retest approval, signed evidence, authenticated customer consent or release.

## Product behavior

Open [index.html](./index.html) in a browser from the LightUp repository checkout (keep the sibling `remediation-capacity/` folder, because this new app deliberately uses the original unmodified `casework-original-v1.js` source parser and original source digest). No server, local storage, network, external assets, backend credentials, or target contact is used.

1. Obtain the **original** private five-column CSV through separately authenticated, permitted LightUp access. Optionally obtain a **private original** Evidence Review v1/v2 JSON from the current Evidence Review Board. Independently confirm the same real client and *exact* engagement before joining the separate sources. A CSV/hash cannot prove an issuer.
2. The app strictly parses the original `finding_id,title,severity,retest_status,remediation` source with the unchanged original Casework parser. It binds an optional complete Evidence Review JSON to the canonical **exact source SHA-256**, rejects duplicate/unknown JSON properties, rejects true or absent authority flags, mismatched or missing review IDs, malformed human evidence fields, source drift and oversized files. Failed join removes any stale dashboard.
3. Propose **up to four UTC review/change windows** and allocate source findings to human discussion slots. View source severity/retest state, unverified local human stage, human change/deployment/rollback/retest-request reference gaps, original regressions, and high-risk/unscheduled counts. A locally filled reference is **not proof** of a verified fix or permission to execute; source `fixed` is not independently verified.
4. **Resume PRIVATE saved planning**: re-import the prior private JSON only after exact original source SHA, unchanged complete finding membership, original severity/retest fields, matching human review digest/gaps and all 12 literal-false authority flags. Conflicting counts, overlapping windows, changed notes, missing source rows and ambiguous fields HOLD the import **before** any local window selection is changed.
5. Prevent incomplete UTC window schedules, invalid durations or overlaps from leaving as exports. Explicitly choose one of three local exports:
   - **PRIVATE source-bound JSON**, containing original finding IDs, reviewer/next step, proposed assignments, original severity/retest status, gap labels, SHA-256 and all **twelve false authority flags**. Transfer only with a separately approved confidential channel.
   - **Identity-free .ics calendar**, containing only generic tentative meeting slots, duration and a fixed non-authorizing description. No finding, target, notes, customer, reviewer or asset metadata.
   - **Aggregate-only CSV**, containing only slot, UTC time, duration, counts by critical/high and locally incomplete reference counts. No original finding data or human evidence references.

The app has no browser storage: refresh or close discards private inputs and window assignments. "Forget" removes in-memory state and selected file inputs. The portable offline browser may use the original Casework WebCrypto digest, or an in-memory source-compatible SHA-256 fallback for file:// contexts.

## Integrity, ownership and release fences

- This is an **isolated add-only product** under `remediation-change-windows/` on top of a frozen, already held Remediation Cockpit PR #1627 snapshot, not a change to any original source-owner path, scanner, grant, STOP, CI, deploy or QA.
- The original Casework source in `remediation-capacity/casework-original-v1.js` is unchanged. Its parser also bounds individual CSV fields and findings; the extra review JSON intake is capped at 2 MiB.
- SHA-256 is only an unsigned content correlation check. Dates, counters, human notes and client/engagement checkbox are not approvals. All generated artifacts are **human-only unverified drafts**.
- Do not merge to main, deploy, contact targets, trigger scans, grant access or treat these as verified changes without original owner review, independent security/privacy review, both original exact-head hosted and permanent registered VPS CI, issue #177/#182/#829 authorization integration, actual separately authenticated client/operator consent with revocation-at-use, and explicit **HUMAN GO**.
- No QA, regression or test suite is part of this deliverable; verification may use only a short source syntax inspection.
