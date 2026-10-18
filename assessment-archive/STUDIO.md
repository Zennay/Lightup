# LightUp · Offline Assessment Archive Studio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a private human review tool. It never scans a target, executes a model or worker, authenticates a client, makes an authorization grant, certifies source authenticity, or clears a security finding.

## Purpose

The separately owned original [assessment runtime composition](https://github.com/Zennay/Lightup/pull/1621) provides original comparator, Studio, lineage, candidate matrix and private human review sources. The isolated [archive and follow-up console](https://github.com/Zennay/Lightup/pull/1622) indexes multiple previously completed local artifacts and creates source-bound human JSON plans. Archive Studio bridges an exact original private archive to a readable, editable browser worklist.

### Create

First capture 2–64 original private lab source files using archive.py capture. Then render the existing private archive manifest as one new private HTML:

    python3 assessment-archive/archive_studio.py --manifest /private/ARCHIVE.json --output /private/NEW-studio.html

Open that HTML locally. It contains all its own CSS and JS with SHA-256 CSP pins and the original validated private archive manifest snapshot. It requires no network, server or installation. The CLI publishes exclusively new, fsynced mode-0600 HTML.

### Human workflow

1. View the private archive's claimed source classes, original byte fingerprints, ordinal slots and claimed record counts. These are NOT independently verified findings.
2. Search and filter the original sources by category, human review stage or neutral role.
3. Choose a human follow-up stage, neutral next role and optional review date for each source.
4. Export a private human follow-up JSON draft with the exact original manifest SHA-256 and immutable slot/fingerprint binding.
5. Optionally import a matching previous private browser draft. All source slots, original fingerprint, schema, roles, stage and dates are checked before the in-memory worklist is replaced.
6. Export de-identified stage counts or print a private worklist.

**Browser download security:** Browser downloads can be saved with permissions broader than mode 0600. Store these JSON drafts locally in a private directory, never upload them to untrusted online services, and use the original strict Python followup.py render to enforce canonical JSON with duplicate-key rejection, exact original manifest-byte binding and slot/source equality. Browser display and temporary edits have NO security authority.

### Complete with the original offline CLI

    python3 assessment-archive/followup.py render --manifest /private/ARCHIVE.json --choices /private/CHOSEN-followup.json --output /private/NEW-human-review.html

A REVIEW_ONLY (2) or HOLD (3) CLI exit is intentional. It never returns 0 for security approval. The owner-private review can subsequently be assembled into the independent private coordination ZIP using packet.py.

### Privacy & release boundaries

- The generated HTML contains original SHA-256 byte fingerprints and is **OWNER PRIVATE**. It intentionally contains no original target URLs, customer identifiers, findings, model prompts, private source paths, or original lab evidence.
- Strict CSP with SHA-256 pinned inline code only; no remote scripts/styles/fonts/telemetry, network requests, service workers, browser localStorage, cookies, iframe, runtime fetch or browser database.
- Edits exist only in browser memory until an explicit download. No Approve/GO/Start/activation controls exist.
- Browser JSON import is a human convenience, not the original strict parser or final admission boundary. Always pass its output to followup.py render.
- Mandatory original exact-head hosted + permanent registered VPS CI, original source-owner review, independent security/privacy, separately authenticated actual client/operator permissions, at-use revocation and explicit HUMAN GO remain required prior to merge or deploy.
