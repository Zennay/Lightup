# LightUp PRIVATE Authenticated Engagement Brief

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an independently owned add-only child of original encrypted Casework source integration [PR #1653](https://github.com/Zennay/Lightup/pull/1653). Existing owner code and approval gates are unchanged.

## Four complete offline operator workflows

**Capture:** authenticate through the existing LightUp domain, tenant and engagement selector; validate the complete original five-column redacted findings; directly encrypt it to a NEW 0600 owner-private AES-GCM .ltv file, with no intermediate plaintext file. Uses the unchanged 600,000-round PBKDF2 and original vault.

**Inspect:** locally decrypt a previous source snapshot to view only aggregates of original severity/retest labels. Never claims current authorization. No original finding IDs, title, client or engagement identifiers are printed.

**Review-current:** independently authenticate the current user and re-select the exact original client/engagement before decrypting history. Compare original finding IDs and original field text against the live authorized read only. Report counts for added, absent, changed and unchanged rows; optional explicit 0600 PRIVATE human report records per-ID source text drift. Absence/fixed is not a verified fix.

**Open-current:** fresh original account authentication and exact same current original CSV SHA-256 plus finding count are required before creating a NEW 0600 PRIVATE Markdown original finding action brief. Shows source-labeled severity priorities, suggested remediations, missing human owners and unverified retest questions. Any source drift causes HOLD, with review-current available separately.

This is human discussion preparation ONLY. No target/network activity, scanner/executor/remediation action, fake grant, client consent, operator consent, verified security finding/fix/retest, deployment or release.

## Use in a real private TTY

Run on an approved private Linux workstation containing the original LightUp Python source and cryptography dependencies. Prepare your own trusted owner-owned mode 0700 folder for both encrypted and confidential outputs. Replace all placeholders locally; never paste real client credentials into shared commands.

Capture:

    python3 remediation-engagement-brief/brief.py capture --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --output /private/briefs/baseline.ltv

Show source totals:

    python3 remediation-engagement-brief/brief.py inspect --input /private/briefs/baseline.ltv

Reauthenticate and compare original revisions, writing a private human drift report:

    python3 remediation-engagement-brief/brief.py review-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/baseline.ltv --output /private/briefs/source-review.md --ack-private-markdown

Reauthenticate, require byte-identical current original source, and produce a private action brief:

    python3 remediation-engagement-brief/brief.py open-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/baseline.ltv --output /private/briefs/current-handoff.md --ack-private-markdown

The original encrypted input is never overwritten. Only a trusted owner-owned 0700 directory is accepted for new outputs. All passwords are requested interactively from a private TTY. Human Markdown contains confidential original findings; protect it and, if separately approved to share, encrypt using the existing original private vault first.

## Source lineage and permissions

Reuses original secure_export._authorized_summary to enforce current DomainStore login plus authorized client and engagement membership, original secure_export._strict_summary to validate all original source rows and SHA-256, and original remediation-ticket-vault/vault.py private AES-256-GCM handling. All metadata authority flags are explicitly false, and strict canonical JSON is rechecked after decryption. Source IDs/hashes provide local integrity only, NOT authenticated provenance or consent. All source-supplied findings and statuses remain unverified.

**Mandatory release HOLD:** no main merge or deploy until original exact-head hosted and permanently named VPS CI, source-owner and independent security/privacy/crypto review, original #177/#182/#829, truly separate current client/operator consent with action-time revocation, and explicit HUMAN GO. Do not bypass these gates.

## NEW: encrypted HUMAN handoff without intermediate plaintext

Use --sealed-markdown in place of --output on open-current or review-current (also pass --ack-private-markdown). The PRIVATE original-source HUMAN report is encrypted directly to a NEW .ltv using the unchanged vault and a new private TTY passphrase; no plaintext Markdown touches disk. It contains encrypted text/markdown, not an encrypted source snapshot. The original vault.py open action can recover the human report separately when authorized.

    python3 remediation-engagement-brief/brief.py open-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/baseline.ltv --sealed-markdown /private/briefs/private-handoff.ltv --ack-private-markdown

Review-current also supports --capture-current /private/briefs/revision-02.ltv to encrypt the just-authenticated NEW original CSV revision without a second login, preserving the old original encrypted baseline. This may be combined with one --sealed-markdown PRIVATE change report: all three paths must differ, original encrypted data stays intact, and no plaintext intermediary is created. Each file is committed to disk independently (not a multi-file transaction), so a later output failure does not undo a successfully sealed earlier artifact. Source fingerprints and successful authentication remain distinct from consent, grants, or verified outcomes.

## NEW: original-authenticated offline HUMAN Review Desk (browser)

Without touching any production scanner or consent path, both source-aware commands now support an interactive fully self-contained local HTML finding desk:

    python3 remediation-engagement-brief/brief.py open-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/baseline.ltv --private-html /private/briefs/current-desk.html --ack-private-html

    python3 remediation-engagement-brief/brief.py review-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/baseline.ltv --private-html /private/briefs/revision-desk.html --ack-private-html

These operations still require **fresh original account authentication, client/engagement read authorization and strict source admission before any file is emitted**. The first route rejects original CSV drift. The second route compares the actual prior encrypted snapshot with the current freshly authenticated source and shows NEW/CHANGED/UNCHANGED/ABSENT original finding IDs and field-level earlier/current source text. Absent always gets an explicit HUMAN HOLD, never a verified fixed label.

The private HTML is a responsive searchable/filterable HUMAN review interface with severity, unverified original retest labels, change-category filtering, critical/high priorities and browser print styling. All original title, remediation and historical text is HTML-escaped, inserted as literal content, and never executed. The generated HTML includes only SHA-256 CSP-pinned fixed local CSS and fixed local JavaScript; its Content Security Policy prohibits external resources, frames, forms and network connections. No browser storage, cookies, remote scripts or model access are used. The HTML is **unencrypted confidential plaintext**, intentionally emitted only after explicit --ack-private-html into a new owner-controlled 0700 directory as a 0600 file. Do not publish or send it unencrypted to others.

The --private-html option can accompany one human Markdown option or a --capture-current encrypted revision output; all paths must be distinct. Each file is written independently and is not a multi-file transaction. To keep all sensitive HUMAN text encrypted with no plaintext file, use --sealed-markdown instead of --private-html. HTML never represents current consent, verified findings, authorized remediation or a retest.

## NEW: authenticated PRIVATE multi-revision original finding continuity

The history-current command consolidates **1–12 existing original encrypted source revisions** (explicit earliest-to-latest order), plus a separately authenticated **current** LightUp client/engagement source read. It does not need a browser or scanner, and does not authorize any remediation. Historical vault passphrases are requested separately and privately through the original unchanged vault. Every original encrypted source packet must contain the same exact declared client/engagement identity as the current tenant-authorized source; malformed source, row duplication or empty evidence closes the whole review.

    python3 remediation-engagement-brief/brief.py history-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --inputs /private/briefs/01.ltv /private/briefs/02.ltv /private/briefs/03.ltv --ack-source-order --sealed-markdown /private/briefs/history-human-report.ltv --ack-private-markdown --aggregate-csv /private/briefs/anonymous-counts.csv

The human review follows original ID appearance/disappearance/reappearance and changes of all four original finding fields across each selected transition. It surfaces the source labels that changed to fixed as **UNVERIFIED ONLY** and maintains a distinct final list of historically seen IDs absent from the current source (HUMAN HOLD). Historical ordering is the operator's acknowledgement: no persisted source timestamp is treated as verified chronology.

Outputs: an optional fully encrypted original-vault HUMAN Markdown report (or an exclusive owner-private plaintext .md) and an independently optional 0600 numeric aggregate-only CSV containing fixed column names and counts, never customer names, IDs, hostnames, source hashes or evidence text. Exactly one of --output or --sealed-markdown can be selected, and all input/output paths must be distinct. All outputs require trusted 0700 private directories, and every actual source passes the original vault and strict CSV admission. This is human data review, not CI/QA, authorization, a verified fix or retest.

## NEW: PRIVATE historical lineage browser (scriptless)

The original authenticated history-current workflow now supports --private-html and --ack-private-html to generate a new owner-only 0600 standalone HTML original-source lineage explorer. Every historical source is decrypted independently and must declare the exact present authorized client/engagement. The operator explicitly confirms historical ordering. The UI compares per-revision source-labeled severity distribution, transitions among new/absent/changed/unchanged original IDs, field-level historical source text, original IDs reappearing after absence and currently absent historical IDs. All are HUMAN prompts, not verified security findings or fixes.

    python3 remediation-engagement-brief/brief.py history-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --inputs /private/briefs/01.ltv /private/briefs/02.ltv --ack-source-order --private-html /private/briefs/history-review.html --ack-private-html

The responsive local HTML has accessible expandable source sections and native severity meters. It uses zero JavaScript, no arbitrary inline style attributes, only SHA-256 CSP-pinned CSS. All external resources, forms, frames, scripts and network traffic are disabled. The HTML is confidential plaintext only after explicit acknowledgement on an approved owner-private device. For a confidential fully encrypted HUMAN handoff, select --sealed-markdown instead. Both can be paired with separate aggregate CSV if output paths differ. Source order and original retest status never authenticate consent or remediation.

## NEW: re-authenticated encrypted browser handoff (no plaintext HTML in transit)

Use --sealed-html with --ack-sealed-html on open-current, review-current or history-current. Instead of publishing a plaintext browser document, the tool creates a NEW owner-private encrypted .ltv using the unchanged original AES-256-GCM vault. Inside the ciphertext is **canonical original source information, not runnable HTML**: the freshly authorized original CSV SHA-256/count, the explicit self-declared client/engagement and, for historical comparisons, bounded original prior CSV records. All permission/grant/consent/execution/fix/retest flags are false. Existing original vault size and filesystem ownership/privacy limits apply, so oversized bundles fail closed.

After transporting this confidential ciphertext to an approved private workstation, run open-sealed-browser-current with the ORIGINAL current LightUp account and engagement, exact .ltv input, a NEW .html destination, and --ack-private-html. The original account must be authenticated again and the current authorized original source must match the stored **exact full CSV SHA-256 and row count**. The history sources are revalidated. Only then is the fixed local browser app rebuilt from original source data; no decrypted arbitrary HTML is used or executed. If the actual source has changed, this operation HOLDs without publishing any HTML. Plaintext browser files are produced only with separate explicit acknowledgement into an existing owner-private 0700 directory as new mode-0600 files.

Commands:

    python3 remediation-engagement-brief/brief.py review-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/old-source.ltv --sealed-html /private/briefs/compare-browser.ltv --ack-sealed-html

    python3 remediation-engagement-brief/brief.py open-sealed-browser-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/compare-browser.ltv --output /private/briefs/current-review.html --ack-private-html

For history-current, use the same --sealed-html and --ack-sealed-html flags with the original --inputs and --ack-source-order. The package size is bounded by the original 4 MiB vault, so large histories may need fewer snapshots. Fresh account login is READ permission only, never approved scanning, a client consent record, an actual security finding or a verified repair. All existing release gates remain unchanged.

## NEW: source-only escalation and regression attention in history

The original human-ordered history workbench additionally distinguishes two high-attention SOURCE-label changes for finding IDs present in adjacent original revisions: a severity change upward along critical/high/medium/low/info, and a transition into the original regression retest label. They appear in the scriptless offline lineage browser as expanded HUMAN attention sections, in confidential HUMAN Markdown with before/after source-severity labels, and as **anonymous numeric columns only** in the aggregate CSV. Terminal history-current shows those counts as well.

These indicators prioritize a human conversation; they are NOT risk-calibrated vulnerabilities, confirmed regressions, a verified retest, authorization or evidence of actual remediation. Only exact original IDs shared across adjacent snapshots are compared. Newly appearing original IDs remain new source rows and are not called regressions. Encrypted browser reopening regenerates these views only after the original present-day client/engagement authenticated source read passes its exact source hash gate.

## NEW: current-source HUMAN attention inbox across multiple revisions

The history-current workflow now composes a **single current original finding follow-up inbox** after reviewing the operator-ordered historical revisions. It keeps only finding IDs present in the freshly authorized CURRENT original source and sorts them by unverified original severity label and number of conversation prompts. It flags original Critical/High labels, source-severity escalations observed in any prior transition, new historical source regression labels, source-ID reappearances and records changed at the latest revision. It never carries an absent historical ID into the live inbox as a fake work order; those remain separately visible as HUMAN HOLD.

The scriptless offline history browser shows these current-source-only cases first, before the original per-revision drilldowns. PRIVATE HUMAN Markdown includes source IDs and reasons. The local CLI prints the count without exposing names or finding IDs. Each focus prompt is a strictly unverified human discussion aid, not a real customer work assignment, verified vulnerability, retest or authorized remediation. The currently authenticated source is rechecked on encrypted-browser release exactly as before.

## Original Ticket Desk from an authenticated sealed source snapshot

The original source-owning Ticket Desk from PR #1653 can now be opened through the independently authorized open-current route. The existing remediation-secure-export/ticketdesk.py::build_ticketdesk pins the original standalone bytes and validates its CSP; the original Ticket Desk JavaScript and user workflow remain unchanged. Its source-file preloading, human ticket/owner work and private offline workflows are reused, not copied or reimplemented.

Choose --original-ticketdesk-html /private/briefs/desk.html --ack-original-ticketdesk for a new owner-only 0600 confidential HTML on an approved device, or --original-ticketdesk-sealed /private/briefs/desk.ltv --ack-original-ticketdesk for a NEW encrypted source-bound AES-256-GCM vault with NO HTML intermediate. Reopen the encrypted browser packet with open-sealed-browser-current, the original current account/client/engagement authentication, the private vault password and --ack-private-html. The current original CSV must still match its exact SHA-256 and original row count before new local HTML is generated. An altered original Ticket Desk source SHA, drifted current findings or missing access result in HOLD.

No new source-owner code, original ticket-writing engine, scanner, grants or release policies were modified. Authenticated source reading does not imply scan authority or verified remediation.

## Original Ticket Desk for changed CURRENT findings, not just identical snapshots

The original unmodified source-owner Ticket Desk is also available from review-current, not only from open-current. When the original source changes after a snapshot, review-current reauthenticates with the real current LightUp account and selects the present client/engagement findings, compares original source revisions for HUMAN HOLD, and can directly send ONLY those currently authorized original CSV records into the original SHA-pinned Ticket Desk. Historical rows are not confused with present authorized source.

    python3 remediation-engagement-brief/brief.py review-current --db /private/lightup.sqlite --email operator@example.invalid --client-id YOUR_CLIENT --engagement-id YOUR_ENGAGEMENT --input /private/briefs/older-source.ltv --original-ticketdesk-sealed /private/briefs/current-desk.ltv --ack-original-ticketdesk --sealed-markdown /private/briefs/source-differences.ltv --ack-private-markdown

The output is a NEW owner-only AES vault packet for reopening the ORIGINAL full Ticket Desk and a separately NEW encrypted HUMAN source-diff report, with no plaintext HTML or source CSV. Later open-sealed-browser-current authenticates again and insists that this NEW original source has not changed before it emits standalone HTML. A changed-current response never reuses a previous finding as if it were still active, never supplies grant authority and never modifies the original owner Ticket Desk files. Output paths must remain separate and owner-private.

## Complete history-to-original Ticket Desk workflow

The existing history-current command can now produce a current original-source Ticket Desk in the same authenticated pass that compares 1-12 older encrypted source versions. Add --original-ticketdesk-sealed /private/briefs/current-human-tickets.ltv --ack-original-ticketdesk (or separately approved --original-ticketdesk-html for NEW private 0600 plaintext) alongside --sealed-markdown and/or --sealed-html. The historical source differences, source regression-label attention inbox and encrypted HUMAN history notes are produced separately; only the freshly reauthenticated CURRENT original client/engagement CSV is preloaded into the unmodified original Ticket Desk. An old ID absent in the latest original source is never promoted into the active Ticket Desk. All output paths are new, different, owner-private and previous encrypted archives are not overwritten. No QA, scanning, grant, status verification or retest is performed.

## ORIGINAL Casework fully integrated alongside ORIGINAL Ticket Desk

All source-bound workflows (open-current, review-current and multi-revision history-current) can also open the unchanged original source-owner Casework workspace. The option --original-casework-html /private/briefs/casework.html --ack-original-casework writes a NEW mode-0600 owner-private original HUMAN Casework HTML after the real current LightUp account/client/engagement admission. The recommended --original-casework-sealed /private/briefs/casework.ltv --ack-original-casework writes only a NEW AES-GCM source-bound encrypted package and NO plaintext browser file.

Opening that .ltv later through open-sealed-browser-current requires fresh original LightUp credentials and an identical current original source SHA/count, then delegates actual Casework HTML assembly and manifest validation to the original unchanged remediation-secure-export/secure_export.py _make_envelope / _read_envelope functions. This avoids any cloned or independently reimplemented Casework app. The existing original Casework owner still controls the application source. The Ticket Desk mode continues to use the original pinned Ticket Desk builder. Both modes remain offline HUMAN planning and never authorize scanning, grants, retests or real remediation.

For a combined original human workflow, use review-current or history-current with distinct --original-casework-sealed and --original-ticketdesk-sealed paths, plus explicit --ack-original-casework and --ack-original-ticketdesk; optionally add a separate encrypted HUMAN drift or history report. No historical missing ID is injected into the current original apps. All resulting ciphertext is exclusively new and local; no plain HTML needs to be written during transfer.

## Original app content pinned in encrypted browser handoff

New sealed original Casework or Ticket Desk handoffs are version 2 and include an AES-GCM authenticated SHA-256 of the complete exact original owner-generated browser document, created from the freshly authorized source. When open-sealed-browser-current reauthenticates and rechecks current original CSV SHA/count, it also rebuilds the corresponding unchanged ORIGINAL owner app and demands an identical HTML SHA-256 BEFORE releasing any plaintext. An original app code change thus HOLDs an earlier handoff rather than silently changing its behavior. The original Ticket Desk additionally preserves its independent source-code SHA-256 pin.

Previously sealed generic finding/history/compare browser packets remain in version 1 and continue to open with the same source admission rules. Earlier version-1 original Ticket Desk / original Casework packets (briefly emitted by the earlier integration head) are intentionally rejected until the operator reseals using the current original authenticated source; no unreviewed legacy original-app HTML release. This is an integrity property of the encrypted original HUMAN app, not a new scan grant, retest gate or consent claim. Existing source-owner apps are never modified.

## ONE sealed multi-view HUMAN workspace, directly based on original source apps

An operator can now carry a SINGLE new original-AES-256-GCM 0600 .ltv instead of separate passwords/files for Casework, Ticket Desk and the finding review desk. `open-current` supports --workspace-sealed /private/briefs/engagement-workspace.ltv --ack-workspace after original LightUp login and exact matching original source; `review-current` supports the same flags when the previous source differs; `history-current` supports the same flags alongside 1-12 historical encrypted snapshots and explicit --ack-source-order.

The encrypted workspace v3 stores strictly admitted current-original CSV SHA-256 and count, actual old source text only where history is supplied, self-declared tenant/engagement identity, **TWO separately pinned exact original owner-generated HTML SHA-256 digests** for the unchanged Ticket Desk and Casework apps, and all source-authorization/grant/consent/execution/retest/release fields explicitly false. There is NO executable HTML inside the .ltv. The same original owner apps are independently generated in memory to create the hashes; their source files are not changed.

On an approved private workstation reauthenticate the ORIGINAL current LightUp account/tenant/engagement and open exactly one view with `open-sealed-browser-current --input /private/briefs/engagement-workspace.ltv --output /private/briefs/REVIEW.html --ack-private-html --view review`. Choose `--view ticketdesk` or `--view casework` for the original owner apps; if the package contains historical revisions, `--view history` renders the existing scriptless historical workbench. Every chosen view first admits exact current original CSV SHA/count AND regenerates/rechecks **both** original app content hashes; original owner drift or current source change makes the whole workspace HOLD with no HTML. The chosen HTML is written as a NEW exclusive local 0600 plaintext file into an existing trusted 0700 directory; there is no browser storage or network transfer. For source review with multiple revisions the latest prior original snapshot is compared with the current source, never treated as current consent.

One .ltv and one passphrase therefore support original-source HUMAN finding review, the unmodified original Ticket Desk and Casework, and optionally historical source review, without creating four independent ciphertext archives. Explicit output paths may not collide with encrypted historical sources or any other output. None of this confers scanning, remediation, client/operator consent, finding verification, retest or production release rights.
