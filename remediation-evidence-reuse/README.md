# LightUp: PRIVATE Evidence Reuse & Drift Desk

**Quick entrypoint:** [desk.py](desk.py) integrates all three source-bound PRIVATE operator workflows: `python3 remediation-evidence-reuse/desk.py --help`, `desk.py review`, `desk.py inbox` and `desk.py timeline`. These delegate in-process to the unchanged individual production CLI modes; there are no subprocesses, target network calls or new authorization interfaces.

**Stage:** INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD. Independent HUMAN-only offline app, built as new-only remediation-evidence-reuse/ paths on the existing Evidence Artifact Ledger draft #1642. No original owner paths are edited.

## The product

Original LightUp Artifact Ledger files can associate the same local SHA-256 evidence file with several original finding IDs. This new standalone, networkless operator tool shows:
- Cross-finding fingerprint reuse, with source finding IDs, file labels, byte size, and HUMAN-only stage.
- Divergent HUMAN stages for one shared fingerprint and contradictory reported byte lengths.
- Exact same-source PRIVATE snapshot changes: new or no-longer-present local links, changed HUMAN review metadata, and new reuse relationships. Absence in a later local snapshot is never evidence of remediation.
- Scriptless private offline HTML workbench with reviewer aliases and exact local links; separate aggregate JSON with counts only and no source IDs, hashes, filenames, client labels, reviewer names, targets or notes.
- A third, explicitly PRIVATE source-bound advisory HUMAN action packet: exact finding ID / local SHA-256 links, proposed question codes for reuse, divergent stages, inconsistent byte lengths, new or missing local links and changed HUMAN metadata. It does not issue original-native Requests or Apply.
- All-or-nothing schema admission for native original private artifact ledger v1 and unified HUMAN v2 export. Duplicate JSON keys, unknown fields, non-false authority flags, unsupported sizes, duplicate finding/fingerprint pairs and inconsistent source/context fail closed. Original Casework/Evidence Review/HUMAN request overlays are treated as opaque private input, not proof of their authenticity.

Original exporter code and privacy controls are unchanged. This tool never opens evidence file bytes, connects to a target, performs a scan, grants consent, changes a case, authenticates a source, validates a vulnerability, verifies remediation, or signs a reviewer decision.

## Operator workflow (private device only)

Export the existing original Artifact Ledger PRIVATE ledger JSON or PRIVATE unified HUMAN JSON. Use a real owner-only private directory and owner-only input file permissions (0600). Example shell commands:

    install -d -m 700 "$HOME/lightup-private-review"
    # Move the downloaded PRIVATE export to current.json in that directory using your trusted file manager.
    chmod 600 "$HOME/lightup-private-review/current.json"
    python3 remediation-evidence-reuse/review.py "$HOME/lightup-private-review/current.json"
    python3 remediation-evidence-reuse/review.py "$HOME/lightup-private-review/current.json" --format html --output "$HOME/lightup-private-review/current-human.html"

For an independently obtained previous PRIVATE export from EXACTLY THE SAME original finding source and self-declared client/engagement:

    chmod 600 "$HOME/lightup-private-review/previous.json"
    python3 remediation-evidence-reuse/review.py "$HOME/lightup-private-review/current.json" --previous "$HOME/lightup-private-review/previous.json" --format html --output "$HOME/lightup-private-review/private-drift.html"
    python3 remediation-evidence-reuse/review.py "$HOME/lightup-private-review/current.json" --previous "$HOME/lightup-private-review/previous.json" --format counts --output "$HOME/lightup-private-review/anonymous-counts.json"
    python3 remediation-evidence-reuse/review.py "$HOME/lightup-private-review/current.json" --previous "$HOME/lightup-private-review/previous.json" --format actions --output "$HOME/lightup-private-review/PRIVATE-human-actions.json"

The inspect command prints only anonymized counts. The actions export is an entirely PRIVATE, non-native suggested HUMAN follow-up handoff; it includes exact source digest, self-declared context, human reviewer aliases, original finding IDs, artifact fingerprints and literal false authority flags, never underlying evidence bytes or free-text notes. It MUST NOT be passed to the original native Request Desk as an authorized request. PRIVATE HTML is for a human operator and contains sensitive original finding identifiers, local labels and digests; never attach it to public PRs/issues. The counts file is separately anonymized. Output is exclusive 0600 inside a real owner-private directory, published from fsynced private staging with an exclusive hard link; a crash can leave a PRIVATE pending file but not a partially written final. Strict scriptless CSP and HTML escaping prevent the report from loading remote or active content.

Exit code 2 = HUMAN review held (intentionally never a green pass); exit 3 = input/output HOLD. Neither is an authorization decision.

## Scope and limitations

- Supports up to 120 local fingerprint links and 4 MiB imported original private data. Only source claim metadata is available; the original CSV and evidence files are NOT revalidated here. Native HUMAN overlays in unified v2 are opaque and must be reviewed with original tools.
- Cross-source comparison is refused: changed source revisions require the original Ledger's source migration workflow and HUMAN review. Same-SHA reuse may be intentional, not a source vulnerability.
- Downloaded private files can carry personal data and must remain under original privacy/retention rules. A source digest, local fingerprint and HUMAN stage prove neither provenance nor authenticity nor client approval.
- Product compilation / built-in help only; NO QA/regression/testsuites, release-workflow changes or CI bypass.

Original exact-head hosted and permanently registered named VPS CI, independent source-owner/privacy/security/browser/crypto review, original #177/#182/#829, authenticated separate current client/operator consent with action-time revocation and explicit HUMAN GO are still required. This branch and its draft PR must NOT be merged to main, deployed or used for real targets without those external gates.


## Durable PRIVATE HUMAN inbox (new full operator workflow)

The standalone original-fingerprint reviewer above can now be followed by a **durable HUMAN-only session**, with an exact-byte-bound, owner-private record and an offline interactive command workflow in [triage.py](triage.py). It is not a native LightUp request, review signature, consent, deletion, retest, legal custody event, grant or verified remediation.

The session is bound to the **SHA-256 of both complete actual PRIVATE input JSON file bytes**, plus a digest of the source-derived proposed-human-question packet. Every command requires the original same input files again; changed bytes, added actions, source revisions or changed private human session structure HOLD before proceeding. A single-host flock guards local operations and source/session bytes are freshly checked before marking or exporting. Other devices, other paths and independent original LightUp tools are not locked.

First create a new session, then work through the original-provenance-labelled proposed HUMAN-only questions:

    python3 remediation-evidence-reuse/triage.py start --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json"
    python3 remediation-evidence-reuse/triage.py status --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json"
    python3 remediation-evidence-reuse/triage.py list --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json"

The first command creates new owner-only 0600 PRIVATE state. The list command deliberately prints sensitive source finding IDs and hashes **to the local terminal only**. The status command prints anonymous counts only. Every legitimate command exits status 2 (HUMAN HOLD), not 0.

Mark one proposed question as requiring the original HUMAN owner:

    python3 remediation-evidence-reuse/triage.py mark --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --ordinal 1 --stage needs_source_owner --note-prompt

The PRIVATE note prompt requires an interactive terminal and hides the note while typing; it is not passed via command-line arguments or recorded in shell history. You can mark `open`, `in_human_review`, `needs_source_owner` or `answered_human`, but **answered_human only means a local human has acknowledged the question**, not that LightUp repaired, closed, authenticated or approved any issue. Set `--clear-note` to remove an existing local HUMAN note for the selected ordinal.

Publish a new scriptless PRIVATE status HTML and a separately anonymous counts-only JSON:

    python3 remediation-evidence-reuse/triage.py html --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --output "$HOME/lightup-private-review/PRIVATE-reuse-inbox.html"
    python3 remediation-evidence-reuse/triage.py counts --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --output "$HOME/lightup-private-review/anonymous-progress.json"

For an exact same-source earlier snapshot, **pass the identical --previous PRIVATE file on every command**, starting with `start`. Never silently attach a previous packet to an already-started current-only session.

If another authorized local operator needs a copy of the HUMAN-only notes, use an explicitly new private file:

    python3 remediation-evidence-reuse/triage.py handoff --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --output "$HOME/lightup-private-review/PRIVATE-human-handoff.json"

The handoff is a copy of the exact current private session, **not** a delegated original-native request and not an approval. Receiving parties must separately obtain the **exact original packet bytes** and original source identity before reusing the state; a private hash never proves sender identity or client/operator authentication.

Security boundaries: strict native source parser and exact-byte hash binding, independent PRIVATE 0600 output, actual non-symlinked owner-only 0700 path, single-host exclusive file lock, fsynced atomic session state replacement, scriptless CSP HTML output, bounded 1200-character HUMAN notes, and no background persistence/network/service worker. Do not put PRIVATE HTML/handoff/session files in a public repository or hosted page. Only separately authenticated original LightUp sources, actual source-owner/security/privacy review and action-time dual-party consent can resolve original project release gates.


## 2–12 snapshot PRIVATE relationship timeline (new longitudinal product)

[The standalone timeline CLI](timeline.py) extends the same independent PRIVATE original Evidence Ledger v1 / complete unified HUMAN v2 interpretation to between **two and twelve different original PRIVATE exports** of the **exact same original findings source SHA and self-declared client/engagement**. It does not modify the original Ledger or any active owner. Each snapshot is fully admitted without duplicate JSON keys or authority claims; duplicated exact input bytes HOLD, rather than being misrepresented as a time progression.

Use the literal private 0600 export files inside the real 0700 private directory. Operators choose an order; that order **is not authenticated chronology**. E.g. (substitute your actual separate original PRIVATE files):

    python3 remediation-evidence-reuse/timeline.py --snapshot "$HOME/lightup-private-review/export-a.json" --snapshot "$HOME/lightup-private-review/export-b.json"
    python3 remediation-evidence-reuse/timeline.py --snapshot "$HOME/lightup-private-review/export-a.json" --snapshot "$HOME/lightup-private-review/export-b.json" --format html --output "$HOME/lightup-private-review/PRIVATE-evidence-timeline.html"
    python3 remediation-evidence-reuse/timeline.py --snapshot "$HOME/lightup-private-review/export-a.json" --snapshot "$HOME/lightup-private-review/export-b.json" --format counts --output "$HOME/lightup-private-review/anonymous-timeline.json"
    python3 remediation-evidence-reuse/timeline.py --snapshot "$HOME/lightup-private-review/export-a.json" --snapshot "$HOME/lightup-private-review/export-b.json" --format handoff --output "$HOME/lightup-private-review/PRIVATE-human-timeline-handoff.json"

The private **scriptless HTML** shows per-slot original finding × local file SHA references, HUMAN stages and exact human-only attention reasons: missing local reference in one or more slots, changed stage/reviewer aliases, shared fingerprint across distinct original findings and contradictory reported local byte lengths. The per-slot dashboard shows aggregate local link churn, shared fingerprints and changed human metadata. The separate counts JSON contains only slot ordinals and coarse aggregate metrics (never identifiers, SHA, client, filenames, notes, targets, raw evidence or sources). The optional PRIVATE handoff contains exact source/context and priority finding+fingerprint relationships for **human coordination only**, with all authority flags false.

An absent later LOCAL fingerprint, archived HUMAN stage, low severity source label or evidence reuse never proves a fix. The outputs never claim custody, chronology, authenticated owner, true vulnerability, consent, grant or security approval. Every output is new, exclusively published 0600 in an owner-only folder and original source bytes are re-read before publication to prevent stale snapshots. No background monitoring, scanners, active target requests, testsuites, CI bypass or deployment.

The longitudinal timeline is deliberately independent of the durable triage session. A new snapshot requires a fresh human review session if review actions are needed; existing local status must not be silently carried to a new packet.


## Offline HUMAN bulk worklist: export → edit → preview → apply

The unified `desk.py bulk` command makes a **complete owner-private 0600 JSON worksheet** of every existing source-byte-bound local HUMAN question in `triage.py`, so an authorized local human can edit *several* stage and note fields with a trusted local editor rather than running many individual commands.

The worksheet exports each original `ordinal`, original finding ID and SHA-256, question reasons, unchanged previous HUMAN stage/note and editable `new_stage` / `new_human_note`. Only those **two new fields** may change; all exact original context, full current/previous PRIVATE source-byte digests, entire original HUMAN session-byte digest and every baseline row must remain identical. This is a PRIVATE local manual draft, not a file for public spreadsheets, untrusted editors, web services, CI artifacts or original native LightUp Apply.

    python3 remediation-evidence-reuse/desk.py bulk export --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --worksheet "$HOME/lightup-private-review/PRIVATE-bulk-edit.json"
    # Edit ONLY new_stage / new_human_note, using a trusted OFFLINE private text editor.
    python3 remediation-evidence-reuse/desk.py bulk preview --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --worksheet "$HOME/lightup-private-review/PRIVATE-bulk-edit.json"
    python3 remediation-evidence-reuse/desk.py bulk apply --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --worksheet "$HOME/lightup-private-review/PRIVATE-bulk-edit.json"

If the original triage inbox was started with `--previous`, supply the **identical previous PRIVATE original JSON** to all commands. No prior inbox gets overwritten if the source, session, worksheet, reasons, row ordering or baseline HUMAN notes have changed. `preview` is strictly read-only and outputs only changed ordinal/stage and note-changed yes/no (never private note text). `apply` requires an interactive terminal to type the literal human acknowledgement, silently, before re-reading the exact original packet and comparing the current session and worksheet. It applies only changed proposed HUMAN statuses and notes in a single fsynced atomic local 0600 session replacement.

An operator can mark `answered_human` to track **local human communication**, not security closure, validated repair, confirmed evidence, legal retention, original LightUp Apply or authorized retest. Never treat bulk edits as cross-device distributed locking; the private lock protects one local session path on one machine only. No customer/target file bytes are read or sent.


## PRIVATE HUMAN continuity into a later local packet of the EXACT same original source

The new `desk.py carry` workflow addresses the real workflow gap where a HUMAN reviewer has local source-byte-bound notes in a `triage.py` session and receives a *new PRIVATE export of the same original findings source*, e.g. with additional local artifact references. Unlike native LightUp casework or cross-original-source recovery, this does **not** move anything between different original finding-source SHA values, clients, engagements or original finding counts.

The workflow uses two original PRIVATE packet byte sets and a strictly admitted old PRIVATE HUMAN session. It builds a new session tied to the **new exact packet and newly proposed HUMAN questions**. Existing HUMAN review statuses and notes are carried **only when original finding ID + local file SHA-256 + the entire exact question-reasons list is identical**. All old actions must still be present in the new proposed set. If a former action disappeared, changed reasons, or the original source/context differs, the *entire carry is refused*, rather than falsely implying a resolved issue. New additional questions start `open`. The old session and all original evidence files remain unchanged.

Safe operator flow (substitute independently obtained trusted 0600 PRIVATE paths and keep the literal same old-previous/new-previous arguments, if present):

    python3 remediation-evidence-reuse/desk.py carry preview --old-current "$HOME/lightup-private-review/current.json" --old-session "$HOME/lightup-private-review/reuse-inbox.json" --new-current "$HOME/lightup-private-review/new-export.json"
    python3 remediation-evidence-reuse/desk.py carry carry --old-current "$HOME/lightup-private-review/current.json" --old-session "$HOME/lightup-private-review/reuse-inbox.json" --new-current "$HOME/lightup-private-review/new-export.json" --output "$HOME/lightup-private-review/PRIVATE-next-inbox.json"

The read-only preview exposes **anonymous counts only**, including how many original HUMAN questions would be preserved, how many new local questions start fresh and aggregate carried HUMAN statuses. The carry requires a real interactive terminal and explicit hidden confirmation; then all original PRIVATE bytes and old session bytes are checked again before publishing a **new exclusive 0600 owner-private** inbox. Continue through `desk.py inbox` with **the new exact PRIVATE packet and new session**. The old inbox is still available for separate human reconciliation.

This is intentionally stricter than an automatic merge, because neither local fingerprint nor Human status proves original evidence provenance or client consent. Same-source metadata claims and owner-private local files are not signed/authenticated source-owner proof, and `answered_human` is not a validated fix, legal closeout, scan grant or native Apply. No cross-device locking, scanner, external target or HTTP call is performed.


## Reversible PRIVATE HUMAN history and pre-change checkpoints

The integrated [history.py](history.py) workflow adds a real recovery path for HUMAN-only status and private note mistakes without touching original source/evidence, scanner/grant, native LightUp HUMAN Apply or security approval. Checkpoints contain a **complete local HUMAN session** encoded inside an owner-private **0600** envelope, bound to the exact original current/previous packet byte hashes and canonical proposed question identities. They are **not encrypted or signed**: storing/sharing the files requires the same strong local privacy and source-owner policy as the HUMAN inbox itself. The claimed local save timestamp is not independently authenticated history.

1. Save a new, immutable HUMAN checkpoint before private editing:

       python3 remediation-evidence-reuse/desk.py history capture --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-before-review.json"

2. Inspect its difference from the current HUMAN inbox (counts-only, no finding IDs or notes in console):

       python3 remediation-evidence-reuse/desk.py history inspect --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-before-review.json"

3. Create a NEW **scriptless, CSP-protected 0600 PRIVATE HTML** showing per-finding stage and PRIVATE-note-changed flags, never note text:

       python3 remediation-evidence-reuse/desk.py history report --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-before-review.json" --output "$HOME/lightup-private-review/PRIVATE-restore-preview.html"

4. Restore the prior local HUMAN status/notes only after a real private terminal acknowledgment. You **must** choose an additional unused owner-private backup destination: the current local state is preserved before atomic replacement and can itself be restored if desired.

       python3 remediation-evidence-reuse/desk.py history restore --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-before-review.json" --backup-to "$HOME/lightup-private-review/PRIVATE-before-restore.json"

All commands require exactly the same original source packet(s) that created the HUMAN session. If the inbox was created with `--previous`, repeat that same `--previous` on every command. The checkpoint is strictly schema-admitted (no duplicate JSON properties, no elevated authority flags, exact original source/proposal digests), and restoration never proceeds when the original session, checkpoint or source changed during the interactive confirmation.

**Direct integration without extra release gates:** ordinary `desk.py inbox mark` and `desk.py bulk apply` now accept an optional `--backup-to "$HOME/lightup-private-review/PRIVATE-unique-before-edit.json"`. This publishes the old complete HUMAN state in a new exclusive private checkpoint before the actual HUMAN edit is applied; there is no approval claim and no mandatory new gate. Keep separate private names per operation and dispose of old files according to the real applicable privacy/retention policy. Files may contain PRIVATE notes, findings and file fingerprints; never put them in hosted CI artifacts, public Notion pages, issue attachments or browser cloud sync.


## Historical HUMAN checkpoints · multi-revision local progression desk

The new integrated `desk.py history-timeline` supports **2–12 different PRIVATE 0600 saved HUMAN checkpoints**, source-bound to the same exact original LightUp packet and canonical HUMAN question set. Unlike the original source snapshot `timeline` (which compares local evidence links), this module compares **how locally recorded HUMAN review statuses and PRIVATE note-change indicators evolve** between existing saved human checkpoints. It never alters a saved checkpoint, the live HUMAN inbox, original finding export, native LightUp workroom, or a real target.

Private usage (files must already be in your real owner-private 0700 directory):

    python3 remediation-evidence-reuse/desk.py history-timeline --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-a.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-b.json"
    python3 remediation-evidence-reuse/desk.py history-timeline --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-a.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-b.json" --format html --output "$HOME/lightup-private-review/PRIVATE-human-progress.html"
    python3 remediation-evidence-reuse/desk.py history-timeline --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-a.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-b.json" --format counts --output "$HOME/lightup-private-review/anonymous-human-progress.json"
    python3 remediation-evidence-reuse/desk.py history-timeline --current "$HOME/lightup-private-review/current.json" --session "$HOME/lightup-private-review/reuse-inbox.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-a.json" --checkpoint "$HOME/lightup-private-review/PRIVATE-checkpoint-b.json" --format handoff --output "$HOME/lightup-private-review/PRIVATE-human-progress-handoff.json"

Provide the exact original `--previous` source argument when the HUMAN inbox was based on one. Each PRIVATE checkpoint is independently reopened through the existing strict [history.py](history.py) admission and the actual current source/session bytes are checked again before any new file is published. **Duplicate identical checkpoint bytes HOLD** and checkpoint-to-source lineage mismatches HOLD. The count-only response includes *no original finding IDs, file digests, PRIVATE notes or human names*. The scriptless CSP-blocked 0600 HTML and optional PRIVATE handoff do include exact original finding/fingerprint identities and HUMAN stage transitions, but **never the PRIVATE note text**.

**The order of supplied checkpoints is an operator choice, NOT authenticated time, verified custody or signed reviewer history.** An `answered_human` stage still means only local correspondence, never remediated, retested, permissioned or approved. Keep all PRIVATE history within the owner's real retention and privacy policy; never publicly post the report.
