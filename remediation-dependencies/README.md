# LightUp · Human Remediation Dependency Board

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. **Human-only, offline.** This is a new isolated product component, stacked exclusively on original Casework owner PR #1568 SHA `9c73e8468ce271bf8c6bef4cac071e5ad9c1806b`. No original source, scanner, domain, casework, assessment, grant, security gate, CI or test files are modified.

## Workflow and delivered behavior

1. Obtain the **original** authenticated and authorized LightUp five-column finding export for the exact real client and engagement through the existing server-side operator workflow. In the original Casework app, create a PRIVATE Casework v1 JSON; do not substitute a synthetic file for actual client consent. Independently verify the source, engagement, recipient and secure handling permission; the browser cannot authenticate any of them.
2. Open `remediation-dependencies/index.html` with the repo's original sibling `casework/remediation-engine.js`, or build an entirely offline one-file version with `python3 remediation-dependencies/package.py` from a repository checkout. Packaging requires the **unchanged original Casework engine** with SHA-256 `c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225`. The single-file version pins each inline script and CSS using individual SHA-256 CSP and `connect-src 'none'`.
3. Import the original PRIVATE Casework v1. The exact original source findings, complete human cases, original SHA fingerprint and false-only authority flags are admitted. An offline SHA-256 of the complete original source **plus human Casework** binds dependency drafts to that precise baseline. A SHA/hash does **not** authenticate the author, current consent, tenant or approval.
4. Add `A must finish before B` links using the exact original finding IDs and a privately entered human reason. Links must be unique, non-self and acyclic. Every change is admitted against the full graph before being kept in local memory. The original finding or retest is never changed.
5. Change local human *effort estimates* (1–90 calendar days, initial **editable placeholders** of one day). These are neither contractual SLAs nor authorized change windows. The offline board computes a topological ordering, waiting human prerequisites, potentially ready human work, original severity/owner, longest illustrative dependency chain and optional indicative dates based on an operator-entered local start date. An originally `fixed` retest state and a human `completed` stage remain distinct; human completion is **not** proof of a repaired finding.
6. Filter the detailed board by blocked-on-human work, potentially ready work, high/critical source severity or illustrative longest path. Save a **PRIVATE source-bound JSON dependency draft**, reopen it against **exactly the same unchanged original findings and human Casework**, or export a **PRIVATE human work CSV**. The private CSV includes original finding IDs and may be sensitive; receiving channel confirmation is required and dangerous spreadsheet formula prefixes are treated as text. No external sending, workspace storage or calendar synchronization occurs.

## Privacy and authority boundaries

- Bounded input: max 2 MiB imported JSON, max 350 original findings, max 1,200 human links; duplicate object keys, unexpected payload fields, missing or duplicated original finding IDs, duplicate/self links, cycles, non-integer effort, and changed source/casework baselines cause HOLD.
- Reopening a draft requires exact `source_sha256` **and** `casework_sha256`. All original authority flags must remain **false**. No code may treat imported planning notes as a verified repair, authorized retest, source integrity attestation, grant, client/operator consent or an assessment action.
- No active scan, network operation, real target, secrets, grant issuance, modification of the original domain database, or autonomous change to an authorized client asset is performed.
- There are no new QA, regression, or test-suite files.

## Release HOLD

This is a development-only product candidate. Original exact-head hosted and permanently registered named VPS CI, source-owner and independent security/privacy approval, canonical original #177/#182/#829, separately verified current client/operator authorization including action-time revocation, and explicit HUMAN GO are still required before main merge or live deployment. The standalone HTML cannot substitute for those gates. The new branch deliberately does not take over concurrently active remediation PR #1627, #1631, #1635 or the original Casework PR #1568.

**Note:** when the authorized VPS worktree denies creation, do not modify VPS rights or invent a green build; source files are still committed through the separate authorized GitHub connector, and the pinned bundler can be run after ordinary file permissions are restored.

## Human bottlenecks and deadline conflicts

The board also computes **downstream human impact** for every open human finding using the transitive closure of its dependency edges. Its operator-visible bottleneck table ranks findings that block other human work. A row can be *potentially ready for human planning* only when no recorded local human prerequisite remains open. This does not claim authorization to work on a target or retest a finding.

The conflict table highlights existing HUMAN due dates where a prerequisite has a later date than a dependent finding. The separate illustrative date table compares manually entered tentative human effort against the current recorded human due dates, when the operator supplies an explicit scenario start. Neither changes the original Casework due dates. These displays use no active target, real scanner or external model.

The portable, network-disabled [single-file board](./standalone.html) is already built and published through authorized GitHub source assembly: **43,524 UTF-8 bytes**, SHA-256 `1f769362ac35ea47417ca35227d624fd7ad510591541cd7e2590e7067df1eafa`. Its unchanged original Casework owner engine was independently byte-checked against SHA-256 `c293c564ecb11434e45423d244b7beba599b6afe3ebbc85121882e91b8aa1225`; CSS and each inline script have source-byte SHA-256 CSP pins, `connect-src 'none'`. A standalone repository checkout is not needed to open this compiled HTML locally. These unsigned digests do not confer identity or consent. Source syntax/build on the VPS was not claimed or used after its permission refusal.

**GitHub branch only:** the connected VPS isolated worktree refused creating the new directory (`Permission denied`). No permission bypass, forced push, runner policy change, alternative SSH transport or QA cycle was attempted. This isolated GitHub directory is an independent DRAFT/HOLD product preview awaiting the original security, privacy and exact-head CI release gates.

## Exact human owner work queues and confidential handoffs

The board now includes an explicit **exact human owner/team** selection that keeps the full original dependency graph intact while narrowing the displayed human task list. Blank/whitespace-only owners are grouped as *unassigned*; other names retain their precise original label identity (not a substring match or an authenticated user identity). The owner filter composes with waiting/ready/critical/urgent filters and does not remove hidden upstream prerequisites from the cycle, readiness or longest-chain calculation. The human bottleneck list is computed across all original findings and filtered for the chosen view before showing the most impactful 20 records.

PRIVATE CSV export now has an explicit choice between *all original human work* and *currently visible owner + status filters*. If no original findings match, a filtered handoff is held instead of falsely generating an empty successful report. The full PRIVATE dependency JSON remains bound to the entire original source and Casework baseline and never drops hidden findings, dependency links or source metadata. Filtered CSV is a human handoff only and does not establish source identity, current consent or a verified fix.
