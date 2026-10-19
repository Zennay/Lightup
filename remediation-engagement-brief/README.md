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
