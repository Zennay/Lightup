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
