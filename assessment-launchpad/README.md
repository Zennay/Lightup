# LightUp · Isolated-lab batch launchpad

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** New-only `assessment-launchpad/` product pinned to original held CLI source commit `74e865201c8a4270e404046ef3447eb7f190edfb`. The original source owner, CLI, `_admit_explicit_lab_url`, `LabScenario`, and `ScopePolicy` files are not modified.

## Browser composer

Open `composer.html` locally. It is one standalone file with a strict hash-pinned CSP (no unsafe-inline script/style) and no external assets, APIs, storage, DNS or network access. Compose 1–16 distinct literal HTTP(S) URLs within the native CLI\'s 16 KiB manifest limit, or import a private existing local manifest. Import is all-or-nothing (strict UTF-8, no BOM/NUL, no duplicate values); failed imports retain the current editor. Edit/remove/reorder endpoint slots before clicking **Download private text manifest**. Nothing is uploaded or saved to browser storage. Browser checks are convenience-only and do not prove an endpoint is isolated.

Browser downloads cannot set file permissions. Before using the native CLI, move the downloaded file to a private directory and set mode `0600`. Use this PR branch (not the older source-only pinned ancestor), for example `git fetch origin chatgpt/lightup-assessment-launchpad-20261021-gpt6` followed by `git switch --detach FETCH_HEAD` in a disposable trusted checkout. The CLI refuses any modified original pinned validator or CLI bytes.

## Native validator-backed handoff

Requires a checkout of this launchpad PR branch, which contains both `assessment-launchpad/` and the original source files at the frozen source pin, with the existing project Python dependencies. Checking out the pinned ancestor commit **alone will not work** because that older commit does not contain the launchpad. Create an owner-only output directory separate from the manifest directory:

```bash
chmod 600 ~/Downloads/lightup-lab-targets.txt
mkdir -m 700 ~/private-lab-launchpad-output
python3 assessment-launchpad/launchpad.py \
  --manifest ~/Downloads/lightup-lab-targets.txt \
  --output-dir ~/private-lab-launchpad-output
```

The CLI checks the Git blob hashes of the pinned original `cli.py`, `labrun.py`, `labeval.py`, `scope.py` and `models.py` before loading the original `_admit_explicit_lab_url` and `LabScenario`. `LabScenario` invokes the original isolated loopback/private-lab `ScopePolicy`. No DNS resolution or target connection is made.

The command requires an owner-owned input regular file with mode `0600`, no symlink/hard-link alias, bounded stable contents (16 KiB), and 1–16 distinct endpoints. The output directory must already exist, be owned by the current user and have mode `0700`. Outputs are exclusive no-overwrite files with mode `0600`; failed bundle publication removes newly created outputs.

The output directory receives five private artifacts:

- `lightup-lab-targets.txt` — canonical one-URL-per-line manifest, suitable for the original CLI's `--targets-file` argument.
- `lightup-lab-plan-receipt.json` — PRIVATE source-bound receipt with input/canonical manifest SHA-256, endpoint count, pinned original CLI/validator sources, and SHA-256 of the generated HTML/command; no endpoint values.
- `lightup-lab-plan-handoff.html` — scriptless, CSP-pinned handoff showing the exact preview command, counts and private paths; endpoint values are not embedded.
- `lightup-lab-preview-command.txt` — exact shell-quoted display-only command using `--preview-only`.
- `lightup-lab-minimal-summary.json` — separate privacy-minimal, counts-only `REVIEW_ONLY` stakeholder handoff with no endpoint literals, source paths, source hashes or identifying records; local validator checks are not permission.

The command is generated but **never executed**. A human may inspect it and, separately, run the existing CLI with `--preview-only`; that original mode validates the same input without running an assessment. The future preview output path is intentionally not created by the launchpad.

## Safety boundaries

All receipt flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, `release_allowed=false`. Source content/identity, client identity, scope approval, operator consent and HUMAN GO are each explicitly unauthenticated/false. The receipt does not authenticate source identity, client identity, scope approval or consent. No subprocess, assessment, model call, target interaction, DNS, network request, grant, scan, remediation, retest or release occurs. Original exact-head CI, source-owner/security/privacy review, authentic separate client/operator consent, action-time revocation and HUMAN GO remain mandatory.

## Offline reopen and handoff integrity

On the same verified PR checkout (and Python interpreter), re-open the generated packet without running its displayed command:

```bash
python3 assessment-launchpad/launchpad.py --verify-output-dir ~/private-lab-launchpad-output
```

Reopen demands the original five owner-owned single-link mode-0600 regular files in an owner-owned mode-0700 directory. It checks bounded stable bytes, the canonical manifest and ordinals, exact known receipt schema and literal-false authority flags, the pinned original CLI/scope sources, the stored HTML/command content hashes, and exact expected `--preview-only` command. It does not fetch outside the local workspace, run a subprocess, create an output file, authenticate the original source producer, verify client scope authority or prove that a target was assessed. The digest hashes are **unsigned consistency checks only**: an attacker controlling both payload and receipt could rewrite both. Mismatch fails closed with HOLD and no output.

The separate minimal summary is deterministically reconstructed during reopen; any extra source identifiers, paths, hashes, or edited authority statements make the bundle fail closed. It is a low-detail planning artifact, **not proof of confidentiality, anonymous identity, validated scope or assessment**. Its endpoint count may still be sensitive in a small engagement.


## PRIVATE HUMAN follow-up desk

A second source-bound offline workflow turns one completed five-file Launchpad preview packet into a PRIVATE, human-only review desk. It does not execute its preview command, authorize any asset, perform network requests, or assess any target.

Create a new, separate directory owned by the current user with mode 0700 (e.g., mkdir -m 700 ~/private-lab-human-round-1). Then run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --output-dir ~/private-lab-human-round-1

The desk first reopens all five original files through the pinned original URL/isolated-lab scope validator. It creates four owner-only, no-overwrite mode-0600 files:
- lightup-lab-human-private.json: a source-byte-bound per-slot HUMAN planning worksheet. Only ordinal slots, stages, roles and up to 400-character notes may be edited. All authority, consent, dispatch and release flags remain false.
- lightup-lab-human-private.html: a CSP-pinned, scriptless printable workroom. **Contains the original endpoint URLs and private notes. Never publish or host it.**
- lightup-lab-human-counts.json: counts by fixed stage and role. Excludes endpoints, identifiers, paths, hashes and notes.
- lightup-lab-human-counts.csv: the same fixed-vocabulary counts for offline planning, no source or note values.

The initial worksheet assigns NEEDS_INPUT and UNASSIGNED to every original endpoint slot. Human stages are limited to NEEDS_INPUT, HUMAN_REVIEW and FOLLOW_UP; there is intentionally no APPROVED, CLEARED or DONE state. Neutral role choices are UNASSIGNED, LAB_OPERATOR, SCOPE_OWNER, SECURITY_REVIEWER and PRIVACY_REVIEWER.

To record a subsequent HUMAN follow-up, manually edit only the stage, role and note values in a copy of the owner-private JSON worksheet. Do not change its original source fingerprint, slot ordinals or false authority flags. Make a new empty owner-only 0700 directory and run:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --output-dir ~/private-lab-human-round-2

Strict JSON duplicate-key rejection, source fingerprint binding, exact original endpoint count and ordered slots, neutral stage/role schema, and owner/mode/no-link bounded stable reads apply before publication. Existing rounds are not overwritten. To re-open a completed review round read-only, revalidate against the SAME original packet:

    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --verify-review-dir ~/private-lab-human-round-2

This checks the four output artifacts against the canonical worksheet and original-source manifest bytes; hashes here are UNSIGNED LOCAL CONSISTENCY ONLY. The aggregate handoffs are low-detail, not a promise of statistical anonymity in small engagements. HUMAN notes never become security findings, client approval, remediation proof or a scan permit. All existing source-owner, hosted/permanent named VPS CI, independent security/privacy review, distinct authenticated client/operator consent with action-time revocation, and HUMAN GO gates remain mandatory.


### Guided local HUMAN review (no JSON editing required)

Use an interactive terminal instead of manually editing the worksheet:

    mkdir -m 700 ~/private-lab-human-guided
    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --interactive --output-dir ~/private-lab-human-guided

The interactive mode shows ONLY source ordinals (never the endpoint URLs), a fixed menu for stage and reviewer role, and the length—not the content—of any previous note. Enter a free-text note through a non-echoing terminal prompt. Enter retains the current value and a single hyphen clears an old note. Nothing is stored in shell history. A refused value or interrupted session cannot publish a partial new round.

To continue an older round interactively, add the --responses argument pointing at that old round's private worksheet and choose another distinct empty output folder. All exact-source and worksheet-validation protections still apply before and after editing. The HTML and JSON artifacts remain **private unencrypted files on disk**, regardless of the non-echoing terminal input. The absence of actual authority/consent/HUMAN GO still applies.


## Original-source-bound HUMAN round comparison

Compare two manually selected, already-created PRIVATE HUMAN review rounds without revealing their original endpoint URLs or private notes in the resulting handoffs:

    mkdir -m 700 ~/private-lab-human-changes
    python3 assessment-launchpad/compare_review.py --bundle-dir ~/private-lab-launchpad-output --before-dir ~/private-lab-human-round-1 --after-dir ~/private-lab-human-round-2 --output-dir ~/private-lab-human-changes

The comparator first reopens the original five-file packet through the frozen original validators, admits both complete four-file HUMAN rounds by private no-follow reads, checks each JSON against the exact original source bytes and regenerates the rest of the original HUMAN packet to detect drift. It requires two distinct source directories and does not mutate their contents.

The new exclusive mode-0600 artifacts inside the owner-only mode-0700 output directory are:

- lightup-lab-human-delta-private.html — scriptless CSP-pinned ordinal-by-ordinal follow-up history (stage and reviewer-role transition and whether a private note changed), without original endpoint values, notes, hashes or paths.
- lightup-lab-human-delta-counts.json — totals of changed slots, stage/role/note changes, plus stage and role distributions before and after. No per-slot identifiers or original source values.
- lightup-lab-human-delta-counts.csv — the equivalent counts for HUMAN workload reporting.

Read-only reopen against the SAME original packet and two original HUMAN rounds:

    python3 assessment-launchpad/compare_review.py --bundle-dir ~/private-lab-launchpad-output --before-dir ~/private-lab-human-round-1 --after-dir ~/private-lab-human-round-2 --verify-delta-dir ~/private-lab-human-changes

The ordering of the two supplied rounds is manually selected, not authenticated chronology. These changes do not prove finding resolution, client scope, completion, consent, verified identity, a scan, release or HUMAN GO. Any locally consistent data remains UNSIGNED. Never expose the PRIVATE outputs to a web server; continue to apply the original release gates.


## Portable PRIVATE browser editor for HUMAN worksheets

A HUMAN reviewer can now edit status, fixed reviewer role and private notes directly in the browser without entering values into raw JSON or a terminal. The new standalone editor is **produced offline from a previously admitted original Launchpad packet and one owner-private HUMAN worksheet**. It does not embed endpoint URL values, call external services, store anything in browser storage, or execute a preview/assessment. It DOES embed the PRIVATE worksheet and notes, so keep this HTML owner-only and never serve/host it.

    mkdir -m 700 ~/private-lab-human-editor
    python3 assessment-launchpad/editor.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --output-dir ~/private-lab-human-editor

Open the mode-0600 file lightup-lab-human-editor.html locally in the browser. This is a single-file app with SHA-256 CSP-pinned script and styles, no unsafe-inline, no dependencies or external network. Change the HUMAN stage/role and note fields for source ordinals, then explicitly click **Download edited PRIVATE HUMAN JSON**. Original source digest and literal-false authority fields are carried unchanged, with no endpoint values.

Browser downloads do not enforce private permissions. Move the newly downloaded lightup-lab-human-private.edited.json to a separate current-user-owned mode-0700 local directory and set its file permissions to mode 0600 before native import. Native import remains authoritative:

    mkdir -m 700 ~/private-lab-human-browser-round
    python3 assessment-launchpad/review_desk.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-import/lightup-lab-human-private.edited.json --output-dir ~/private-lab-human-browser-round

To verify the original generated editor's bytes again, with the unchanged original Launchpad packet and source HUMAN worksheet:

    python3 assessment-launchpad/editor.py --bundle-dir ~/private-lab-launchpad-output --responses ~/private-lab-human-round-1/lightup-lab-human-private.json --verify-editor-dir ~/private-lab-human-editor

Native readmission rejects new fields, duplicate JSON keys, changed ordinals, changed source digests, affirmative authority claims, untrusted control/bidi marks and source drift. The local browser editor is a convenience for HUMAN self-report only; its download is NOT approval, consent, scope attestation, clearance, target access or verified original evidence. Security/privacy, separate authentic consent and revocation, required CI and HUMAN GO remain independent gates.


## One-command PRIVATE HUMAN assessment workspace

The native workspace.py composes the original Launchpad, a blank HUMAN review round, and the offline browser editor in one complete owner-private source-bound workspace.

Prepare a mode-0600 original manifest in a separate private directory and a NEW empty mode-0700 output root. Launch:

    mkdir -m 700 ~/private-lab-whole-workspace
    python3 assessment-launchpad/workspace.py --manifest ~/private-input/lab-endpoints.txt --workspace-dir ~/private-lab-whole-workspace

No subprocess, DNS, HTTP request, model, lab assessment, dispatch or permission request is executed. The orchestrator invokes the existing pinned original validator/source admission and native Launchpad, review desk and hash-pinned offline browser editor entirely in process. It creates owner-private mode-0700 subdirectories:
- launchpad: all five original 0600 manifest/receipt/preview artifacts and exact display-only --preview-only command.
- human-round-01: initial non-authorizing NEEDS_INPUT/UNASSIGNED HUMAN slots, private scriptless read-only HTML view, source-free stage/role count JSON/CSV.
- human-editor: the portable self-contained PRIVATE HTML to edit a source-bound HUMAN worksheet locally and explicitly download revised PRIVATE JSON.
- START-HERE-PRIVATE.txt: a mode-0600 guide and unsigned original source digest. This guide is PRIVATE; never publish it.

The root directory MUST be empty, current-user owned and mode 0700; each subdirectory is exclusively created at mode 0700 and each file at mode 0600. The original input directory must be separate and never nested inside the output workspace. A failure leaves any intermediate files strictly private and explicitly invalid: never accept them as an approved, complete or deployable workspace.

Reopen the entire original packet using the original five-file and source gates, complete HUMAN round, editor and guide verification, with no writes:

    python3 assessment-launchpad/workspace.py --verify-workspace-dir ~/private-lab-whole-workspace

For changed HUMAN responses, download from human-editor/lightup-lab-human-editor.html, move the download to a separate owner-only mode-0700 input directory, chmod 600 the JSON, then use review_desk.py --responses with a NEW private output directory. Compare separately admitted HUMAN rounds via compare_review.py. No claim of authorship, identity, consent, valid scope, completed review, cleared risk, remediation or HUMAN GO is possible from this workflow.


## Source-bound PRIVATE HUMAN role inbox

The separate native routing.py turns one already-produced, exactly admitted original PRIVATE HUMAN round into a role-specific human follow-up queue. Original source bundle and HUMAN round are re-opened and revalidated before publication. This is not a scan or assignment of verified consent.

    mkdir -m 700 ~/private-lab-role-inbox
    python3 assessment-launchpad/routing.py \
      --bundle-dir ~/private-lab-launchpad-output \
      --round-dir ~/private-lab-human-round-2 \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --output-dir ~/private-lab-role-inbox

Filter options: --role ALL or one admitted HUMAN role; --stage ALL or NEEDS_INPUT, HUMAN_REVIEW or FOLLOW_UP. All outputs are no-overwrite, mode 0600 files in a distinct owner-only mode-0700 directory:
- lightup-lab-human-routing-private.html: private scriptless role-specific HUMAN inbox, sorted by role/stage/original slot, including original local endpoint URLs and HUMAN notes. NEVER share/host.
- lightup-lab-human-routing-private.csv: PRIVATE fixed-vocabulary slot, stage, role and note-length rows. It does not include endpoint values or note text. It is explicitly not anonymous.
- lightup-lab-human-routing-counts.json: separate low-detail role/stage counts excluding source values, paths, digest and HUMAN note text. Counts may still reveal information in small engagements.

Read-only reopen, against the EXACT same original bundle and original HUMAN round:

    python3 assessment-launchpad/routing.py \
      --bundle-dir ~/private-lab-launchpad-output \
      --round-dir ~/private-lab-human-round-2 \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --verify-routing-dir ~/private-lab-role-inbox

The one-command workspace.py now creates a default ALL-role/ALL-stage private routing desk as its fourth workspace stage, in human-routing, and includes it on the scriptless local HTML landing page. Changed HUMAN rounds require an independent NEW routing export. Missing/changed source material, reviewer self-reports and stage changes never constitute remediation, clearance, original consent or permission. No active assessments, scans, network interactions, targets or execution are performed.


## Direct guided terminal creation — no browser download required

A private interactive TTY can now compose the original lab endpoints directly into a 0600 local file and then build the entire offline private workroom. The source is admitted through the pinned original URL and LabScenario lab-only policy **before** private publication. Neither the wizard nor later workroom generation performs DNS, target I/O, subprocesses, scans or any active operation.

Create TWO distinct empty owner-only mode-0700 directories — one for original local source input, and one for the complete product workspace:

    mkdir -m 700 ~/private-lab-guided-input
    mkdir -m 700 ~/private-lab-guided-workspace
    python3 assessment-launchpad/workspace.py \
      --interactive-manifest \
      --input-dir ~/private-lab-guided-input \
      --workspace-dir ~/private-lab-guided-workspace

The CLI prompts for 1–16 literal HTTP(S) private isolated-lab URLs, with an empty line ending input. Text typed into the terminal is visible locally (do not paste credentials). The complete batch must pass exact pinned original lab gates. It then publishes lightup-lab-input-manifest.txt in the separate private source folder, followed by the entire original five-file preview bundle, HUMAN workroom, local editor, role routing inbox, source-bound guide and start screen.

No browser Downloads file or manual chmod is needed; all native writes use exclusive mode-0600 files. Empty input/output directories are required to prevent replacing old source or review work. Any error remains HOLD, with possible partial PRIVATE artifacts explicitly invalid for release; there is no silent cleanup that could remove previously existing user data. Use --verify-workspace-dir to reopen a complete source-bound packet without execution. Interactive mode cannot be used when verifying.


## One-command HUMAN follow-up round — workroom, routing and delta

The independent next-round builder under assessment-launchpad/advance.py admits the same original private five-file Launchpad packet and a previous independently validated full PRIVATE HUMAN round. It then admits a **new** owner-private 0600 edited HUMAN worksheet, checks exact original source-bound slot/false-authorization schema, and packages the whole next step into a fresh separate mode-0700 root. No source-owner files, original HUMAN input or old output are modified.

Example: first complete offline workroom created by workspace.py at ~/private-lab-guided-workspace; after using its local browser editor, put the downloaded JSON in a NEW mode-0700 directory and chmod 600 it. Then:

    mkdir -m 700 ~/private-lab-next-round
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --responses ~/private-import/lightup-lab-human-private.edited.json \
      --output-dir ~/private-lab-next-round

The workroom creates exclusive owner-only mode-0700 folders human-round (updated original-source-bound complete 0600 four-file HUMAN desk), human-editor (re-pinned private browser editor), human-routing (PRIVATE fixed-role/stage routing and counts), human-changes (PRIVATE scriptless HUMAN stage/role/note-change comparison and source-free counts), and PRIVATE 0600 START-HERE and OPEN-NEXT-ROUND local HTML navigation. It never changes original endpoint values, grants consent, starts assessment, contacts a target, executes commands or draws remediation conclusions.

Changed HUMAN count and chronological order refer only to the two explicitly supplied HUMAN files, not authenticated time. The current HUMAN stage is a non-authorizing self-report; no CLEARED/APPROVED stage exists.

Read-only reopening independently verifies the exact original Launchpad source packet, previous HUMAN round, all current source-bound HUMAN/role/delta/editor files, and the local landing/guide:

    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --verify-workroom-dir ~/private-lab-next-round

For another follow-up round, use the same original bundle and the new workroom's human-round as --previous-round-dir. The revised responses must always live in a separate owner-private source folder; choose a brand-new empty output root. A partial on-disk result after an error is not a validated workspace. All original security/privacy, authenticated consent and revocation, source-owner and mandatory CI, and HUMAN GO release gates remain entirely separate.


## Multi-round PRIVATE HUMAN history (2–8 original-source-bound rounds)

The separate offline history.py viewer accepts **2–8 already generated** HUMAN rounds in the human-selected order. Every previous round must be a complete owner-private four-file source-bound review packet for the exact same original private five-file Launchpad packet. This avoids conflating inconsistent original endpoints or copying HUMAN state between different source manifests.

    mkdir -m 700 ~/private-lab-human-history
    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --output-dir ~/private-lab-human-history

Repeat --round-dir up to eight times in the operator-selected order. **The order is not authenticated time; it cannot prove that any reviewer acted at a particular date or that a finding was fixed.** No original source, HUMAN stage, reviewer identity, consent, scope or HUMAN GO is authenticated by this unsigned local tool.

Output in a distinct current-user-owned mode-0700 directory (all artifacts exclusive mode 0600):
- lightup-lab-human-history-private.html: single-file scriptless SHA-256-CSP-pinned PRIVATE HUMAN history. Collapsible endpoint-by-endpoint view of the original local URL, self-reported HUMAN stage, proposed role, private note and changes across 2–8 manually selected rounds. **Contains original endpoints and every selected private note. Do not host/share.**
- lightup-lab-human-history-routing-private.csv: PRIVATE latest-stage/role routing for each original ordinal, note length and number of changed HUMAN transitions. Never described as anonymous.
- lightup-lab-human-history-counts.json: counts only by fixed stage/role per round, adjacent transitions, changed HUMAN slots and note-presence counts. No URLs, hashes, paths, private note text or per-slot identifiers.
- lightup-lab-human-history-counts.csv: equivalent counts-only stage/role and transition matrix in static no-formula vocabulary.

The file integrity reopen is source-bound and read-only:

    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --verify-history-dir ~/private-lab-human-history

The existing next-round builder assessment-launchpad/advance.py **now creates this 2-round HUMAN history automatically**, along with the current HUMAN desk/editor/routing/delta. To include more old rounds when advancing, add --earlier-round-dir for each earlier round, oldest first, up to **six earlier** rounds, then --previous-round-dir for the immediate prior round. The edited response worksheet becomes the final round (up to 8 total). The same --earlier-round-dir values in the same order must be provided to --verify-workroom-dir so it can reopen the original source, earlier HUMAN rounds, current HUMAN state and every new history artifact. The local HTML landing page includes a direct history link.

All work remains offline PRIVATE, LAB-ONLY DRAFT/HOLD. A HUMAN stage transition cannot mean CLEAR, APPROVE, consent, verified repair or end-user permission, and a missing source round is never evidence of a fixed vulnerability.


## Guided, no-intermediary HUMAN next-round creation

The next-round builder now also has a **PRIVATE TTY-only interactive mode**, reusing the existing admitted source-bound HUMAN editor in memory. This completes the native workflow without editing JSON manually or moving a browser download. It starts from a copy of the immediately prior original-source-bound HUMAN worksheet; earlier rounds and original packet stay unchanged.

    mkdir -m 700 ~/private-lab-interactive-next
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --interactive \
      --output-dir ~/private-lab-interactive-next

For 3–8 rounds, provide up to six --earlier-round-dir values (oldest first) as documented above. The TTY menu displays **only original slot ordinals**, stages, neutral roles and note lengths; source endpoint values are not printed. Notes are entered without terminal echo through getpass. Blank stage/role/note inputs preserve the previous HUMAN value; entering a hyphen for a note clears it. An invalid entry or interruption aborts without publishing a new complete packet. The new workroom includes HUMAN updated notes, browser editor, private routing and 2–8 round chronological-*proposal* history, with all original source/rounds re-admitted immediately before publication. Its multi-round order is user-chosen, never authenticated chronology.

Interactive creation is mutually exclusive with --responses and with read-only --verify-workroom-dir. No browser, external service, model, scan, target operation, authorization, consent or HUMAN GO is involved. The resulting HTML/JSON includes sensitive PRIVATE notes and endpoint URLs, remains unencrypted local 0600 and must not be shared or hosted.


### Navigable 2–8-round attention and bounded source custody

The full PRIVATE history now starts with a HUMAN-only per-round workload matrix (NEEDS_INPUT, HUMAN_REVIEW, FOLLOW_UP, note-presence counts) and a current HUMAN attention queue. The queue lists only fixed HUMAN states, fixed reviewer roles, note lengths and original slot ordinals, with local anchor links to each expandable private endpoint-by-endpoint discussion. There are **no inferred security severities, remediation findings, real deadlines or approval flags**.

The native output enforces a consistent 512-KiB ceiling for each saved history item, including a full eight-round, sixteen-slot discussion whose private HUMAN notes may contain HTML-escaped characters. The standalone history reopener and integrated next-round reopener use the same bound, reject missing/extra artifacts, require owner-only mode 0600 regular files and re-admit original source and all selected previous HUMAN rounds. If a legitimate input exceeds that fixed product bound, generation refuses publication rather than issuing a saved packet it cannot later reopen.

No QA suites, scans, real target or model actions are required or performed. The user-selected sequence is NOT authenticated time and changed HUMAN notes are not evidence that work was performed or a vulnerability fixed.


## Compare any manually selected HUMAN interval, including return-to-prior status

The 2–8-round private history supports an explicit operator-selected interval. This is useful when HUMAN planning passed through intermediate revisions and the latest state alone hides temporary stage/role changes. For example, with four rounds in an already established PRIVATE history input order:

    python3 assessment-launchpad/history.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-round-02/human-round \
      --round-dir ~/private-lab-round-03/human-round \
      --round-dir ~/private-lab-round-04/human-round \
      --compare-from-round 1 \
      --compare-to-round 4 \
      --output-dir ~/private-history-interval-01-to-04

Any two different original round ordinals within 1..N are allowed as long as from < to. By default the first and last rounds are compared. The PRIVATE scriptless HTML shows an ordinal-level net stage/role change, note-change indicator and separate markers for a HUMAN stage or reviewer role that returned to its original value after differing in one of the manually inserted rounds. The source-free counts JSON/CSV include the total net changed slots, HUMAN stage/role/note changes and stage/role returns, but no original endpoint, source path/hash or note text. The ordinary next-round workroom uses the default first-to-latest HUMAN interval and includes the comparison automatically.

This is **not** a status change on an actual system, not verified remediation or regression, not authenticated real-world chronology, not identity attestation, not consent and not release. A HUMAN status returning to its previous value has no security meaning by itself. To reopen the custom interval artifact, use --verify-history-dir instead of --output-dir with the SAME repeated --round-dir list and the SAME --compare-from-round/--compare-to-round values.


## Updated PRIVATE HUMAN management briefing and canonical packet integrity

A HUMAN history now generates a **fifth** self-contained artifact: lightup-lab-human-history-brief.html. It is a scriptless, CSP-hash-pinned offline management briefing that displays stage counts for every manually selected 2–8 HUMAN rounds, adjacent HUMAN change totals, currently proposed reviewer-role allocation, and net plus return-to-earlier-value counts for the requested interval. It contains no original endpoint URLs, per-slot ordinals, source paths/digests or private note text. It is **PRIVATE by default** because even aggregate counts from a small lab engagement can reveal context; it is not an anonymity or client-consent guarantee.

The existing one-command next-round workroom automatically includes the source-free briefing and links to it from OPEN-NEXT-ROUND-PRIVATE.html. The original detailed PRIVATE history is still available separately, under a distinct link, and must never be served or shared. The standalone history's exact read-only reopen now expects five canonical files; both standalone and integrated publication share their previous source/round re-admission, 512-KiB history-item capacity and exclusive owner-only mode 0600 output.

### Strengthened original-source reopen and private source isolation

- launchpad.py now refuses any missing or unexpected file in its original five-file private bundle. It reconstructs the original scriptless CSP-pinned HTML from the pinned renderer and validated canonical manifest, receipt fields and exact display-only --preview-only command. A matching hash in a **rewritten unsigned receipt** is no longer sufficient to re-open arbitrary replacement HTML. This remains unsigned byte consistency, not cryptographic source authentication.
- workspace.py demands the complete canonical file inventory in each private HUMAN review/editor/routing subfolder in addition to its original Launchpad and parent-inventory checks.
- review_desk.py refuses nonempty destination directories, requires existing response worksheets to be in distinct private source directories, and demands exact four-file inventory on read-only reopen.
- compare_review.py and its shared original-source human-round reader require exact private file inventories. Standalone routing.py and editor.py now likewise demand empty new output roots and exact inventories on reopen.
- advance.py checks the full bounded output sizes, including all history artifacts, **before creating** its new private subdirectories. Its integrated stored packet cannot be published in a state which would later exceed the read-only re-open limits.

No changes grant scope, consent, risk approval, authorization, release, scanning or real security assessment. The original release gates, independent source ownership and separate action-time revocation checks remain mandatory. No QA or regression suites were written or run.


## Voluntary PRIVATE HUMAN reviewer handoff — selected role, stage and original slots

The new independent native assessment-launchpad/role_handoff.py creates a small original-source-bound PRIVATE offline reviewer dossier from 2–8 existing complete HUMAN rounds. It is a privacy-minimized alternative to sharing the complete multi-round PRIVATE history, which contains every endpoint and every HUMAN note.

Choose one latest self-reported HUMAN reviewer role, optionally one latest self-reported HUMAN stage and optionally exact original slot ordinals:

    mkdir -m 700 ~/private-lab-role-subset
    python3 assessment-launchpad/role_handoff.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --round-dir ~/private-lab-guided-workspace/human-round-01 \
      --round-dir ~/private-lab-next-round/human-round \
      --role SECURITY_REVIEWER \
      --stage FOLLOW_UP \
      --slot 2 --slot 5 \
      --output-dir ~/private-lab-role-subset

A supplied --slot must match the selected role and stage in the latest round. Duplicate, missing, incompatible and out-of-range ordinals are rejected rather than silently broadening disclosure. Without --slot, all matching latest HUMAN slots are included. Zero matching HUMAN slots is a non-authorizing HOLD, not grounds to invent or infer approval.

The four resulting exclusive 0600 private files (in a NEW empty 0700 owner-only folder):
- lightup-lab-role-handoff-private.html: standalone scriptless CSP-hash-pinned PRIVATE printable dossier. Contains only selected original endpoint URL values and HUMAN stages/roles/private notes belonging to the chosen suggested role across the rounds. Historical notes belonging to other suggested roles are withheld even when the endpoint is selected. Do not host or share publicly.
- lightup-lab-role-handoff-private.csv: PRIVATE selected original slot ordinals and latest fixed vocabulary and lengths, omitting endpoint values and note texts. Per-slot ordinals can still be sensitive.
- lightup-lab-role-handoff-counts.json: separate low-detail aggregate counts. No original URLs, per-slot ordinals, source paths/digests, or HUMAN note text. Tiny cohorts can still be identifiable; keep private.
- START-HERE-ROLE-PRIVATE.txt: safe-use operator guide with explicit non-authorizing HUMAN-only limitations.

To read-only reopen the full source-bound packet, supply the SAME ordered --round-dir values, role/stage/slot selection and original --bundle-dir, replacing --output-dir with --verify-handoff-dir. The original five-file source and all complete previous HUMAN rounds are re-admitted before publishing. The output is capacity-bounded to 512 KiB per artifact, owner-only, no overwrite, and requires exactly the original four output files.

The existing native advance.py next-round builder can include a selected role handoff as part of its full new private workroom in one command:

    mkdir -m 700 ~/private-next-with-role
    python3 assessment-launchpad/advance.py \
      --bundle-dir ~/private-lab-guided-workspace/launchpad \
      --previous-round-dir ~/private-lab-guided-workspace/human-round-01 \
      --responses ~/private-import/lightup-lab-human-private.edited.json \
      --handoff-role SECURITY_REVIEWER \
      --handoff-stage FOLLOW_UP \
      --handoff-slot 2 --handoff-slot 5 \
      --output-dir ~/private-next-with-role

The resulting human-selected-role folder contains the four private files and the scriptless local OPEN-NEXT-ROUND-PRIVATE.html navigation now links the dossier. Without --handoff-role no dossier is created. A subsequent --verify-workroom-dir must be run with identical --handoff-role, --handoff-stage and any --handoff-slot values; otherwise the complete-workroom admission fails.

IMPORTANT: Human roles are unsigned self-reports, not verified identities or server-side access control. A privacy-reduced file is not automatically safe to distribute: an operator must authenticate and authorize recipients separately. This product does not issue consent, grants, assessment scope, clearance, completed findings, remediation, real chronology, security permissions or HUMAN GO. No active target, model or scan actions occur. Existing source-owner, CI/permanent VPS, independent security/privacy, actual client/operator consent and action-time revocation/HUMAN GO release gates remain mandatory.


## Returning role-filtered HUMAN replies

See [ROLE_RETURN_GUIDE.md](ROLE_RETURN_GUIDE.md) for the complete offline role-specific CSV or non-echoing terminal reply -> source-bound owner-only HUMAN worksheet -> native advance workflow. Voluntary roles are not authenticated, and no scope/consent/target action occurs.


Owner-only multi-recipient workflow: advance.py accepts up to five repeatable --role-return-dir inputs from disjoint selected HUMAN roles. See ROLE_RETURN_GUIDE.md for original round ordering, overlap refusal, private receipts, the browser editor and source-bound import. This is never consent or authorization.


## PRIVATE HUMAN return reconciliation desk

Native offline per-role/ordinal change desk and source-free aggregate workload across 1–5 disjoint original role replies: [ROLE_RECONCILIATION_GUIDE.md](ROLE_RECONCILIATION_GUIDE.md). Separate exact source-bound CLI role_return_reconcile.py, scriptless CSP-pinned HTML, private CSV, aggregate JSON, deterministic owner-only read-only reopen. This is NOT recipient authentication or a grant.


## Manual resolution of overlapping HUMAN role returns

If two original private selected-role returns claim the same local slot, advance.py deliberately HOLDS. Use [ROLE_CONFLICT_GUIDE.md](ROLE_CONFLICT_GUIDE.md) and role_return_conflicts.py to prepare a PRIVATE role/slot choice CSV + scriptless CSP offline HTML, explicitly choose a source packet per conflict, and produce a complete owner-private canonical HUMAN worksheet for advance.py --responses. This is never automatic precedence, identity proof, remediation validation, consent or an assessment permission.


## Direct owner PRIVATE manual conflict handoff to next HUMAN round

The original resolved four-file overlap packet plus original chosen CSV and original source-bound role returns can now be imported with advance.py --conflict-resolved-dir, --conflict-decision-file and repeated --conflict-return-dir. Preserves a scriptless local provenance desk inside human-manual-conflict-review without duplicating the complete PRIVATE notes worksheet. See [ROLE_NATIVE_MANUAL_INTAKE.md](ROLE_NATIVE_MANUAL_INTAKE.md). No assessment authorization, real identity or scan.


## Offline HUMAN action desk

Source-bound multi-role reconciliation now includes an operator-only, locally filterable and printable HTML next-action desk plus fixed-vocabulary CSV for every original slot, prioritizing missing replies without treating HUMAN_REVIEW as approval. The PRIVATE next-round home links directly to this view. See [ROLE_RECONCILIATION_GUIDE.md](ROLE_RECONCILIATION_GUIDE.md). No network, grants or scans.


### PRIVATE HUMAN action desk: safe selected-row handoff

For a role-return reconciliation packet (or the next-round workroom that
embeds it), open `lightup-lab-human-next-actions-private.html` locally.
Select a voluntary role, original reply status, suggested next action,
self-reported HUMAN stage and/or PRIVATE note-change flag. Clear all HUMAN
filters restores the complete local view without altering source data.
The live counts update for the chosen view. Tick individual original slots,
then use **Select displayed slots** to add all rows currently visible without
clearing earlier selections; selections survive filter changes in memory only.
**Deselect displayed slots** removes only the visible rows from the queue; **Clear all selections** resets the queue. **Print only displayed PRIVATE rows**
prints the current filtered view; **Download selected rows as PRIVATE CSV**
exports only explicitly selected fixed-enum/ordinal rows in original source
order, including selections hidden by the current filter. The browser does not
persist selections. The original worklist and source/returns remain unchanged.
Neither print nor CSV contains endpoint URLs or human notes, but role/slot
combinations may identify people; keep printouts and CSV private.
No reviewer is authenticated, no recipient sharing is performed, and no
consent, scan, grant or HUMAN GO is inferred.

### Original-source re-admission for selected HUMAN action CSV

Do **not** mistake the browser-selected CSV for an authenticated reviewer
reply. `action_handoff.py` optionally converts this private browser selection
into a fresh, four-file original-source-bound PRIVATE native handoff after
checking all selected rows and order against the exact original five-file
Launchpad bundle, original operator-ordered HUMAN rounds and original selected
role-return packets. No new grants, targets, scans or reviewer identities.
See `ROLE_RECONCILIATION_GUIDE.md` for the complete create/reopen commands.
The downloaded browser CSV must first be moved into a private `0700` folder
and set to mode `0600`. Its six-column header must remain exactly
`original_slot,latest_suggested_role,private_human_reply_status,latest_self_reported_human_stage,suggested_operator_next_step,private_note_changed`;
rows must be an ordered, unique subset of the freshly reconstructed original
worklist. The native summary reports counts by all five HUMAN dimensions
(role, reply status, self-reported stage, next action and note-change flag),
not note content. All outputs remain private mode `0600`; missing or modified
original source bytes keep the workflow in HOLD.
