# LightUp: PRIVATE Evidence Reuse & Drift Desk

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
