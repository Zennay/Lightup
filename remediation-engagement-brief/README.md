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
