# PRIVATE HUMAN workload portfolio

LightUp · INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.

This independent, offline add-only product brings 1–12 existing native PRIVATE HUMAN anonymous-count exports into one human-readable packet-level workload view. It never reads real evidence, original files, client names, hashes, dates, owner names, or secrets. The output is PRIVATE and makes no claim of unique cases, remediation, assessment authority, or source authenticity.

## Compatible original producers

The contract comes from [original held PR #1662](https://github.com/Zennay/Lightup/pull/1662) at inspected original HEAD 2d537024ae2c7347578e570a79abc7dd92153731 (the original owner can change independently). Run the original source-owner's inbox.py export-counts or workroom_control.py export-counts first. Those original tools verify their OWN native private workroom and export count JSON. This standalone portfolio imports ONLY those count files; it has no access to the original HMAC key and does not reproduce original source verification.

Native formats: lightup.anonymous_human_inbox_counts_only v1 and lightup.private_human_workroom_anonymous_counts v1. Strict exact schema, 12 all-false authority flags, 1–12 original source-free slots, bounded counts, stage accounting, no extra or duplicate JSON keys. Any rejected input HOLDS the entire collection.

## Offline operator workflow

Linux/Python 3.11+, no external packages or network required. Make an owner-private 0700 absolute directory. The original counts files must be 0600 owner-only inside 0700 parent directories. The destination must NOT exist:

    mkdir -m 700 /home/operator/private-lightup
    python3 remediation-portfolio/portfolio.py \
      --input /home/operator/private-lightup/counts-01.json \
      --input /home/operator/private-lightup/counts-02.json \
      --output-dir /home/operator/private-lightup/portfolio-20261019

### One-command private packet folder

Instead of repeating 12 input flags, create a dedicated 0700 owner-private folder containing **only** consecutively named native exporter files packet-01.json, packet-02.json, ... packet-12.json (no gaps, symlinks, extra hidden files, or any other directory contents). Every member must still be an authentic original-export-shaped 0600 counts-only JSON, not a client evidence file.

    mkdir -m 700 /home/operator/private-lightup/native-count-packets
    # Place the existing original native counts exports at packet-01.json, etc.
    python3 remediation-portfolio/portfolio.py \
      --packet-dir /home/operator/private-lightup/native-count-packets \
      --output-dir /home/operator/private-lightup/complete-human-portfolio

This path is purely **local**, does no file discovery outside the explicitly selected directory, reads all native counters, rejects an unexpected name before creating the output, and inherits whole-batch all-or-nothing admission. It never asks for or opens an original encrypted source key.

The CLI validates **all inputs before writing**, creates an owner-private staging folder and publishes a new directory exclusively through Linux renameat2 no-replace. Outputs: index.html, summary.json, counts.csv, human-volume-queue.csv and human-followup.txt, all 0600 within a 0700 directory. The standalone HUMAN follow-up brief prioritises pending source-owner questions, unassigned planning slots and dated reviews without revealing their identities. Open index.html locally: scriptless, static, offline CSP-pinned dashboard with packet workload and per-stage HUMAN planning. No JS, fetch, scripts, remote assets or private source paths. The browser also shows the HUMAN follow-up recommendations plus a volume-only private routing table sorted by pending HUMAN questions. human-volume-queue.csv carries only packet ordinals and counts; this is never risk/severity priority and does not perform or authorize any action.

Inboxes have no HUMAN planning stage data. Their stage cells are blank (“not provided”), not zero. Summations are **packet appearances**, never unique findings or clients: two files may describe exactly the same material, and local HUMAN “answered” never means a verified fix. A file can be syntactically admitted yet factually false or deceptive; there is NO cryptographic source truth asserted.

Even aggregate small-cell counts might identify people; outputs stay PRIVATE. A human operator must decide on any separate onward disclosure.

## Original owner and release boundaries

This PR does not modify actively owned original remediation, source, domain, auth, consent, scanner, CI or grant paths. There is no merge to main or deployment in INCUBATE DRAFT/HOLD. Original hosted and permanent named VPS exact-head CI, independent source-owner/security/privacy/browser review, #177/#182/#829, authentic current separate client and operator consent including action-time revocation, and explicit HUMAN GO remain mandatory. No new QA, testsuites or regression runs.

## New: source-free two-snapshot HUMAN comparison

Compare any two **complete** private portfolio folders created by portfolio.py. Both complete folders are independently re-admitted: the comparison reconstructs the original source-free count and HUMAN summary, byte-exact static HTML, counts CSV and HUMAN follow-up brief. A tampered or partial input folder HOLDS the whole comparison before any new output. It does not re-open original evidence or assert authentic source ownership.

    python3 remediation-portfolio/compare.py \
      --earlier /home/operator/private-lightup/portfolio-previous \
      --later /home/operator/private-lightup/portfolio-current \
      --output-dir /home/operator/private-lightup/comparison-new

A fresh exclusive 0700 directory contains 0600 index.html, comparison.csv, comparison.json and human-interpretation.txt, all identity-free numeric packet appearances. The scriptless static browser displays the left/right count difference and explicitly warns that different sets of packets, missing inputs and duplicate source-free workrooms **make any apparent decrease ambiguous**. There is deliberately no case matching, remediation-success claim, auth, target action or network request. Counts-only comparison is useful for local HUMAN workload discussion, not outcome measurement.

## NEW: no-Python offline browser HUMAN Studio (single-file)

Open [studio.html](studio.html) locally in a modern browser on the **operator's trusted machine**. This is a portable one-file deliverable; no server, internet, login, package install, model, Python process, external stylesheet or remote script. It includes one inline JavaScript module whose exact content is pinned by SHA-256 in the restrictive static Content Security Policy. The production source is [studio.js](studio.js), the responsive build shell is [studio.template.html](studio.template.html), and [build_studio.py](build_studio.py) deterministically regenerates the distributable browser file without external dependencies.

1. Obtain source-free JSON only from **original held source-owner native** `inbox.py export-counts` or `workroom_control.py export-counts` after its OWN current private original source/key admission. Avoid original evidence, attachments, secrets, plaintext casework or per-operator workroom exports in the browser.
2. Choose 1–12 count JSON files in the Studio. The browser reads selected files only, with strict fatal UTF-8 decoding, per-file 16 KiB cap, bounded JSON depth, duplicate-key detection at every object level, rejection of floating/exponent numeric encodings, exact original schema, exact literal false authority fields and consistent original stage/count cross-fields. Any one invalid selected file rejects **the entire new selection** without modifying admitted browser state.
3. Review a HUMAN question-volume ordered private workload table, planning-stage totals, and missing-versus-zero indicators. Blank planning cells mean **not provided**; they never mean zero. Remove specific packets or clear all current imports without touching original files.
4. Save an anonymous question-volume CSV, a separate human-readable PRIVATE follow-up briefing, or a **source-free browser numeric snapshot JSON** using their separate explicit local download controls. The browser JSON uses the separate `lightup.private_human_studio_numeric_snapshot` kind and never pretends to be a native original HMAC/source attestation.
5. Optionally freeze the earlier numeric aggregate in browser memory, clear current imports, load later counts and save a count-difference CSV. The earlier snapshot retains aggregate numbers only, not original content. The Studio never asserts the two selections represent the same clients, findings, scope or case coverage. **A reduction cannot be called remediation progress.**
6. Closing the tab discards all browser memory. There is no localStorage, IndexedDB, ServiceWorker, network request or server side storage. Downloads are explicit and browser-controlled.

The browser is a **privacy-minimal count-preview tool**, not a substitute for the original native source/key admission. JSON self-declarations or local browser byte checks do not authenticate sender/source identity, grant, consent, verified evidence, real-world security results or fix outcomes. No automatic remedial or scanning actions occur. Private small-cell aggregates can still reveal sensitive patterns; onward release remains a separate human decision.

### Resume and create a private browser-to-CLI HUMAN handoff

Use **Save resumable numeric session** after importing 1–12 native-shaped count exports. This downloads one distinct source-free `lightup.private_human_browser_numeric_session` v1 document with numeric packet descriptions, four-stage HUMAN counts and optional earlier numeric aggregate only. No client identity, source paths, case notes, hashes, timestamps, original evidence or secrets. Twelve authorization flags remain literal FALSE.

Use **Restore private session** to reopen that document on a trusted device. Whole-file admission requires exact schema, limited size, duplicate-key-free nested JSON, bounded count consistency and all false flags. Existing in-memory counts/baseline are replaced only after explicit human confirmation. The UI keeps an explicit restored-numeric-not-original-source warning.

For an owner-private offline briefing independent of the browser, use the NEW CLI:

    python3 remediation-portfolio/session.py --session /home/operator/private-lightup/lightup-private-human-browser-session.json --output-dir /home/operator/private-lightup/restored-human-brief

The CLI reads ONLY the private self-declared browser-session document from a 0700 owner-private folder containing a 0600 input. It regenerates numeric counts and optional previous-baseline deltas, then exclusively publishes a NEW 0700 folder with 0600 `index.html`, `summary.json`, `continuity.csv` and `human-followup.txt`. HTML is standalone scriptless CSP; no network or shared secret. It never calls a restored session an authenticated original native export, verified finding, permission or verified fix. To refresh original provenance, rerun the original owner-pinned source exporter instead.

The complete offline Python portfolio and historical compare CLI remain available above for exclusive 0600/0700 private folder publication and independent exact reconstruction. When separate original count packets have identical **numeric profiles**, the browser flags an overlap caution. It never suppresses either packet or asserts duplicate original clients: independent legitimate workrooms can report the same anonymous numbers. The caution is included in the optional numeric browser snapshot JSON and operator briefing.\n\nBrowser exports are **not** interchangeable with original source-owner native attestations, and nothing from this Studio bypasses LightUp's existing HOLD gates.

### Offline HUMAN numbered-session timeline (2–12 saved sessions)

The new add-only `session_timeline.py` creates one complete local source-free trend workbench from two to twelve private saved browser sessions, in the EXACT order the operator specifies. Each session is independently admitted through the same `session.py` reader (exact schema, flags, bounded numeric counts, owner-only files, no symlink). Every complete input must be admitted before publication. Byte-identical repeated session documents HOLD, whereas two distinct exports with coincidentally matching numbers are retained as independent *appearances*, never deduplicated into alleged customers.

    python3 remediation-portfolio/session_timeline.py --session /home/operator/private-lightup/moment-01.json --session /home/operator/private-lightup/moment-02.json --session /home/operator/private-lightup/moment-03.json --output-dir /home/operator/private-lightup/numbered-human-moments

A NEW exclusive owner-only 0700 directory contains four private 0600 outputs: `index.html` (scriptless offline accessible SVG trend visuals for HUMAN question, slot and attention *appearances*; plus all numeric moments, coverage cautions), `series.csv`, `series.json`, and `human-followup.txt`. None contains source client names, original evidence, source files, case numbers, real dates, users, remediations or permission.

Every ordinal is **operator-selected order only, not an independently verified date**. Source-free totals may represent overlapping or different case sets. Even unchanged packet counts do NOT prove matching cases; falling HUMAN question counts do NOT indicate fixed vulnerabilities, verified retests, lower risk or valid consent. Input files are self-declared anonymous browser output, not original native authenticated source receipts. For any real decision, return to the original authorized HUMAN desk. No release, active target, scan or grant action is performed.

### Numbered HUMAN session timeline — available IN the standalone browser

The browser Studio itself now has a **Numbered HUMAN moments** panel requiring no Python. Select 2–12 previously saved source-free browser session JSON files (not original client/evidence files); each document must pass the exact strict, bounded, duplicate-key-free original browser-session admission. Only aggregate numeric counters are retained in memory, not the original session content. A malformed selection is rejected completely and never replaces existing moments.

The browser's initial order is the file-picker order, NOT a verified time ordering. Use the per-moment **Earlier / Later** controls to explicitly arrange the source-free sequence. The pure inline-SVG (no remote resources) view displays HUMAN question appearances with numeric accessible labels. The table shows packet counts, question counts, slot appearances, planning attention, adjacent changes and coverage-change warnings. A decline or unchanged packet count never proves matching cases, verified remediation or reduced security risk.

Use **Save numbered HUMAN counts CSV** or **Save separate numeric timeline JSON** to export the selected order. The distinct JSON kind `lightup.private_human_browser_numbered_moments` with all original authority flags false is NOT a native authenticated source receipt. Closing/clearing the page discards the work in memory; the exports are explicit files under your browser's chosen download location. Distinct customers can generate exactly the same numbers and source packets can be counted repeatedly; HUMAN review is still required.

The Python `session_timeline.py` above remains the stricter Linux owner-private, exclusive-publish alternative. Do not feed the exported browser timeline summary back as a native source-owner count file or a resumable browser session: these are deliberately different non-authorizing data contracts.

## NEW: complete anonymous HUMAN follow-up routing desk (not a security authority)

The existing portable `studio.html` now has a real **HUMAN next-action board** under Section 3, separate from all original authenticated source casework. Import up to 12 original source-free native counts, then choose one predefined HUMAN-only routing action and one local routing state per anonymous **packet ordinal**. No free-text, name, case ID, original path, source artifact, date, credential, target, scan, grant, or consent can be entered. This prevents the local workload board from silently becoming a substitute for original evidence or client authorization.

Supported next actions: none; request a new authenticated original source count export; discuss unanswered HUMAN questions; clarify original HUMAN assignment; reconcile possible anonymous coverage overlap; request genuine original HUMAN desk review. Local states: not triaged; needs HUMAN follow-up; waiting original source owner; locally discussed **not a verified fix**.

The operator can filter rows by their local routing state, view live counts, reset choices after HUMAN confirmation, and explicitly export **one private follow-up JSON, anonymous routing CSV, or human-readable next-actions brief**. The board is kept in memory only and never updates original casework. Restoring a previous board accepts only the exact native v1 board format with 12 literally false authority fields and the **complete current numeric packet selection in the same local order**; invalid or nonmatching files leave all existing choices unchanged. Equal anonymous numbers are not unique original case fingerprints.

**Linux operator file-placement before running the private CLI:** Browser download folders are not guaranteed to satisfy LightUp's owner-only file policy. Do not relax `session.py`, `action_board.py` or the 0700/0600 checks. Instead copy your own two downloaded files into a new owner-private directory, retaining your original backups:

    mkdir -p -m 700 "$HOME/private-lightup"
    chmod 700 "$HOME/private-lightup"
    install -m 600 "$HOME/Downloads/lightup-private-human-browser-session.json" "$HOME/private-lightup/lightup-private-human-browser-session.json"
    install -m 600 "$HOME/Downloads/lightup-private-human-followup-board.json" "$HOME/private-lightup/lightup-private-human-followup-board.json"

Use the **absolute** output path inside that same private directory and a **fresh** output-directory name. Never put original client evidence, attachments, authentication keys or scanner configuration into these source-free artifacts. Do not run as root or weaken system permissions to make a shared folder pass validation.

Pair the downloaded browser follow-up board JSON with the **matching separately downloaded resumable browser numeric session JSON**, created from the same in-memory selection before reordering or removing packets. Both contain unencrypted source-free small-cell counts; keep both in an owner-private folder and do not forward without human disclosure approval.

### Linux PRIVATE offline action report, directly or inside session handoff

An independent production CLI publishes a complete scriptless private HUMAN follow-up desk:

    python3 remediation-portfolio/action_board.py --session /home/operator/private-lightup/lightup-private-human-browser-session.json --board /home/operator/private-lightup/lightup-private-human-followup-board.json --output-dir /home/operator/private-lightup/new-human-action-desk

This validates BOTH original on-disk files under the repository's owner-private 0700/0600 file access, exact v1 kinds/false flags and bounded numeric packet/plan contract, then matches the entire ordinal packet shape before **any** report is published. The all-or-nothing result is a fresh 0700 owner-private directory containing 0600 `index.html`, `summary.json`, `human-followup.csv`, `human-followup.txt`. HTML is offline scriptless CSP. Source-free local HUMAN routing states are not original source-owner task state, legal consent, verified remediation or validated evidence.

To generate **one joined numeric session + HUMAN routing private package** (instead of separate dirs), the existing CLI now accepts optional `--board`:

    python3 remediation-portfolio/session.py --session /home/operator/private-lightup/lightup-private-human-browser-session.json --board /home/operator/private-lightup/lightup-private-human-followup-board.json --output-dir /home/operator/private-lightup/new-joined-human-handoff

This produces the existing private numeric `index.html`, `summary.json`, `continuity.csv`, `human-followup.txt` PLUS `human-actions.html`, `human-actions.json`, `human-actions.csv`, and `human-actions-followup.txt` in the **same atomic exclusive private folder**. The numeric entry page links to the paired HUMAN action desk. If the board is missing or does not match exactly, no joined result is published. Omit `--board` to retain the existing standalone numeric session behavior.

Neither standalone route contacts any network, opens any real target, edits original source evidence, verifies client/operator consent or performs an action. Current independent original owner/CI/security/privacy/browser/HUMAN GO release gates remain in force; DRAFT/HOLD is never changed by a local follow-up status.
