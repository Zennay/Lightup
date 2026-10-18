# LightUp Remediation Coordination Cockpit

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This product never authorizes a target, user, grant, retest, finding status change, deployment, scanner, agent or other action.

## Immediately usable product

- [Download one-file offline Coordination Cockpit](./standalone.html). Double-click the file to use it locally. No backend, keys, installation, network, browser storage, or raw evidence transfer.
- [Original Evidence Review Board](../remediation-evidence/standalone.html) — edit private local evidence-reference dossiers and create an unsigned `lightup.remediation_evidence_coordination` JSON.
- [Original Capacity Studio](../remediation-capacity/standalone.html) — prepare local hypothetical staffing and export a canonical `lightup.remediation_capacity_working_draft.v1` JSON.
- [Original private team reply desk](../remediation-evidence/team-reply-standalone.html) — reply to a single-team offline source-bound handoff.

This is a **new composition branch** based on an immutable original Evidence Review snapshot, not a modification of the original branches. Source lineage: [original Casework #1568](https://github.com/Zennay/Lightup/pull/1568), [Evidence Review #1623](https://github.com/Zennay/Lightup/pull/1623), [Capacity Studio #1583](https://github.com/Zennay/Lightup/pull/1583). The original Casework, Capacity Planner and Capacity Draft source scripts have exact bytes SHA-256 pinned by `package.py`. None of those modules has been edited in this integration.

## Workflow

1. **Independently authenticate elsewhere** and obtain the original tenant-/engagement-restricted LightUp CSV with exact headers `finding_id,title,severity,retest_status,remediation`. Keep it private. Do not use a CSV from an unknown source.
2. In the original Evidence Review Board, load that CSV, work on the local human dossier, and export **private review JSON**. Original source `retest_status` is read-only. Human references are not actual proof.
3. Optionally in Capacity Studio, import the **same exact original CSV bytes**, model 1–12 hypothetical weeks, and save a private working-draft JSON.
4. Open `remediation-workflow/standalone.html`. Select the original CSV, the evidence JSON, and optionally the original Casework private draft JSON and capacity working-draft JSON. Confirm the independently verified **same actual client and same engagement** before loading.
5. Inspect source severity, source-reported regressions, missing human reference fields, local review stages, optional original Casework blockers/overdue dates and separately modelled capacity/backlog. Filter the human queue. Download **aggregate-only CSV** or explicitly confirm an intended private recipient and download a **sensitive Markdown handoff**.

Original Casework import requires a non-null matching canonical source SHA-256, exact original finding fields and the original complete local Casework schema; unbound older drafts are intentionally held rather than linked. All local due dates, owner assignments, completed statuses and blockers are unverified planning statements.

The join will refuse partial/different source files, missing original findings, unknown extra authority fields, inconsistent row IDs, duplicated JSON keys, noncanonical capacity working drafts, stale snapshots, missing SHA-256 and invalid bounded payloads. Evidence fingerprints use the original Casework canonical ID-sorted, five-field source SHA-256. The optional Capacity Studio working draft independently binds the exact original **raw CSV bytes** and recalculates the original source-only capacity model; an evidence SHA alone is never accepted as a raw CSV match.

The current browser tab stores all imported private content **in memory only**. New imports clear the previous dashboard before evaluation. The private Markdown contains original finding IDs; protect the export. Aggregate CSV never includes finding IDs, titles, hosts, people, source text, evidence references or other personal case notes. Nothing is uploaded by this product, and nothing is automatically assigned or dispatched.

## Deterministic single-file packaging

From the checkout, run `python3 remediation-workflow/package.py` to create `remediation-workflow/standalone.html`. Its builder refuses changed original Casework/Capacity scripts, rejects unsafe closing script bytes, inlines all modules, and replaces the four external script allowances with immutable per-script SHA-256 CSP hashes while keeping `connect-src 'none'`, `object-src 'none'` and `form-action 'none'`. Packaging only builds static offline HTML. Generated artifacts are not proof of the original CI/security approval.

## Release fence

No one should merge to `main`, deploy, scan or infer real authority from this work while the parent Source/Evidence/Capacity composition remains DRAFT/HOLD. Independently review original source owners, privacy/security decisions, exact-head hosted and permanently registered named VPS CI, canonical request/grant integration #177/#182/#829, genuine separately authenticated client/operator consent and action-time revocation, and explicit HUMAN GO. No mandatory existing gate was waived or run manually. Original scope CI #301 remains a separate documented source-owner dependency, not a reason to bypass a required check.
