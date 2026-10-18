# LightUp Remediation Coordination Cockpit

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This product never authorizes a target, user, grant, retest, finding status change, deployment, scanner, agent or other action.

## Immediately usable product

- [Download one-file offline Coordination Cockpit](./standalone.html). Double-click the file to use it locally. No backend, keys, installation, network, browser storage, or raw evidence transfer.
- [Original Evidence Review Board](../remediation-evidence/standalone.html) — edit private local evidence-reference dossiers and create an unsigned `lightup.remediation_evidence_coordination` JSON.
- [Original Capacity Studio](../remediation-capacity/standalone.html) — prepare local hypothetical staffing and export a canonical `lightup.remediation_capacity_working_draft.v1` JSON.
- [Original Client Security Brief](../client-brief/standalone.html) — original finding summary, source comparison, private human remediation narrative and redacted client-facing handoff.
- [Original Remediation Funding Studio](../remediation-funding/standalone.html) — model hypothetical financing, release scenarios and urgent financial exposure using ONLY existing Capacity Studio aggregate JSON, no original finding rows or people.
- [Original private team reply desk](../remediation-evidence/team-reply-standalone.html) — reply to a single-team offline source-bound handoff.

This is a **new composition branch** based on an immutable original Evidence Review snapshot, not a modification of the original branches. Source lineage: [original Casework #1568](https://github.com/Zennay/Lightup/pull/1568), [Evidence Review #1623](https://github.com/Zennay/Lightup/pull/1623), [Capacity Studio #1583](https://github.com/Zennay/Lightup/pull/1583). The original Casework, Capacity Planner and Capacity Draft source scripts have exact bytes SHA-256 pinned by `package.py`. None of those modules has been edited in this integration.

## Native authenticated source-to-Cockpit export (private)

From a trusted checkout with an ORIGINAL existing LightUp account and existing authorized engagement, the newly integrated real-domain CLI can prepare a private HTML that opens already showing the original summary:

```bash
PYTHONPATH=src python -m lightup.remediation_workflow_handoff_cli \
  --db /trusted/private/lightup.sqlite \
  --email authorized-client@example.org \
  --client-id existing-authorized-client \
  --engagement-id exact-existing-engagement \
  --output /trusted/private/new-remediation-cockpit.html
```

The CLI prompts for a password interactively (no argv/env password) and uses original `DomainStore.authenticate`, persisted original role/tenant/engagement context and `render_client_findings_csv`. It consumes only the bounded existing five-field CSV export, deterministically rebuilds SHA-pinned static HTML, embeds the original summary as *passive base64 JSON*, and publishes a 0600 atomically fsynced no-overwrite private file via the upstream owner `_publish_exclusive_private` routine. It creates no authorization or scope assertion, grant, request, scan, evidence proof or retest. The preloaded HTML automatically shows source findings with empty unverified local evidence stages, then optionally accepts independently reviewed Evidence/Casework/Capacity drafts for that same original client and engagement.

**Crucially:** opening the saved HTML later does **not** authenticate the person opening it, re-check current client consent, refresh the source, or prove a verified fix. Never share it publicly: the original tenant findings text is embedded in cleartext and remains sensitive. Preserve the existing source owner's login, privacy, scope and release gates. The offline HTML has no network transport.

## Workflow

1. **Independently authenticate elsewhere** and obtain the original tenant-/engagement-restricted LightUp CSV with exact headers `finding_id,title,severity,retest_status,remediation`. Keep it private. Do not use a CSV from an unknown source.
2. In the original Evidence Review Board, load that CSV, work on the local human dossier, and export **private review JSON**. Original source `retest_status` is read-only. Human references are not actual proof.
3. Optionally in Capacity Studio, import the **same exact original CSV bytes**, model 1–12 hypothetical weeks, and save a private working-draft JSON.
4. Open `remediation-workflow/standalone.html`. Select the original CSV (or use an original authenticated-at-export HTML source), optional Evidence Review JSON, optional original Casework JSON and optional capacity draft JSON. Confirm the independently verified **same actual client and same engagement** before loading.
5. Inspect source severity, source-reported regressions, missing human reference fields, local review stages, optional original Casework blockers/overdue dates and separately modelled capacity/backlog. Filter the human queue. Download **aggregate-only CSV** or explicitly confirm an intended private recipient and download a **sensitive Markdown handoff**.

Original Casework import requires a non-null matching canonical source SHA-256, exact original finding fields and the original complete local Casework schema; unbound older drafts are intentionally held rather than linked. All local due dates, owner assignments, completed statuses and blockers are unverified planning statements.

The join will refuse partial/different source files, missing original findings, unknown extra authority fields, inconsistent row IDs, duplicated JSON keys, noncanonical capacity working drafts, stale snapshots, missing SHA-256 and invalid bounded payloads. Evidence fingerprints use the original Casework canonical ID-sorted, five-field source SHA-256. The optional Capacity Studio working draft independently binds the exact original **raw CSV bytes** and recalculates the original source-only capacity model; an evidence SHA alone is never accepted as a raw CSV match.

The current browser tab stores all imported private content **in memory only**. New imports clear the previous dashboard before evaluation. The private Markdown contains original finding IDs; protect the export. Aggregate CSV never includes finding IDs, titles, hosts, people, source text, evidence references or other personal case notes. Nothing is uploaded by this product, and nothing is automatically assigned or dispatched.

## Complete planning-to-funding handoff

The original [Remediation Funding Studio #1586](https://github.com/Zennay/Lightup/pull/1586), at source snapshot `b23b87e4797412053b006180239b8206f8708d09`, is copied without modification into the isolated composition branch and included in the offline workspace ZIP. This separately sourced original owner app is **not** merged into its active original branch or into main.

After optionally loading a canonical source-bound Capacity Studio **working draft** in the Cockpit, use **Export PRIVATE aggregate to Funding Studio**. The button exports only `LightUpCapacity.summary(plan)`, the existing original `lightup.remediation_capacity_draft.v1` schema. It is validated against the currently loaded original CSV and original working draft before export, and then rechecked by the original Funding Studio strict 64-KiB intake. No finding ID, title, owner, notes, original source bytes, asset or privileged identity is exported. The Funding Studio independently models internal/external rates, weekly cash releases, estimated funding gaps and conservative critical/high exposure. It is a hypothetical human discussion tool; no funds are moved, scans started, approvals issued or findings fixed.

## Original private findings to client brief

The complete original [Client Security Brief #1582](https://github.com/Zennay/Lightup/pull/1582) source at immutable head `f1a22e36d17711f6d2d6fff413cff277ddf4b94a` is integrated as an **unchanged frozen add-only source snapshot** and its SHA-pinned portable HTML is part of the workspace ZIP.

After opening the Cockpit (including through its authenticated-at-export private HTML), a human may intentionally select **Export PRIVATE original CSV**. This exact original five-field CSV contains finding identifiers, titles and remediation and is sensitive; the user must acknowledge the separately authorized private destination before any download. That exact CSV can then be imported into the original Evidence Review, Capacity Studio or Client Security Brief. The Cockpit does **not** automatically send a source to another tool, authenticate recipients or imply a still-valid original grant. The Client Brief has its own original privacy defaults and explicit operator review before exporting any narrative. If the private original CSV cannot be transferred securely, do not export it; continue with aggregate-only funding and local human coordination instead.

## Original source revision comparison (no inferred repair)

The Cockpit now accepts an additional previous, independently authorized five-column findings CSV. The user must manually affirm *same original client and exact engagement* before any comparison. The unchanged original Casework `compareSource` distinguishes added, changed (including exact changed original field names), unchanged and absent original IDs. A missing ID is **not** proof of remediation, closure, retention, source completeness, approved retest or consent. The Cockpit shows local revision labels in the human queue, a separate source-delta breakdown, absent-ID follow-up cards and privacy-minimal aggregate JSON; an explicitly acknowledged **PRIVATE** JSON contains exact IDs and changed field names for human review. The original findings, Evidence draft and Casework records remain unchanged. Two independent canonical five-field SHA-256 fingerprints are shown but never authenticate client identity.

For offline browsers that lack WebCrypto, the Cockpit reuses the original Evidence Review's source-compatible pure SHA-256 implementation for exact canonical and raw-source fingerprinting. This does not relax original Casework field matching, JSON guards or capacity draft schema acceptance. All actual client permissions and current grants remain external to this saved page.

## Deterministic single-file packaging

From the checkout, run `python3 remediation-workflow/package.py` to create `remediation-workflow/standalone.html`. Its builder refuses changed original Casework/Capacity scripts, rejects unsafe closing script bytes, inlines all modules, and replaces the four external script allowances with immutable per-script SHA-256 CSP hashes while keeping `connect-src 'none'`, `object-src 'none'` and `form-action 'none'`. Packaging only builds static offline HTML. Generated artifacts are not proof of the original CI/security approval.

## Release fence

No one should merge to `main`, deploy, scan or infer real authority from this work while the parent Source/Evidence/Capacity composition remains DRAFT/HOLD. Independently review original source owners, privacy/security decisions, exact-head hosted and permanently registered named VPS CI, canonical request/grant integration #177/#182/#829, genuine separately authenticated client/operator consent and action-time revocation, and explicit HUMAN GO. No mandatory existing gate was waived or run manually. Original scope CI #301 remains a separate documented source-owner dependency, not a reason to bypass a required check.
