# LightUp · PRIVATE curated lab evidence dossier

**INCUBATE · M3/M7 PLAN/LAB ONLY · DRAFT/HOLD.** [Issue #1678](https://github.com/Zennay/Lightup/issues/1678). This independent companion turns **already-produced** private lab findings into an original-source-bound, human-curated, selected-only evidence handoff. It never executes an assessment, grants authority or claims a verified finding.

## Required existing original materials

Keep these files locally in a separately approved PRIVATE environment:

1. Original existing PRIVATE lab-assess JSON (from original held PR #1610, no new scan).
2. The same source's original PRIVATE briefing/paged-report manifest.json from held PR #1672.
3. The matching exact seven-column original human-followup.csv (may have HUMAN follow-up edits).

The companion imports the unchanged original open_source, source_manifest and read_human_csv admission from PR #1672. Producer/tenant trust is NOT established by those fields or unsigned hashes. Branch is intentionally stacked on the original owner HEAD.

## Step 1 — Prepare HUMAN selection (no target execution)

From the repository root:

    python3 assessment-evidence-curation/curate.py prepare \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --output-dir ./NEW-PRIVATE-PREPARATION

Produces exclusive NEW 0700 directory, each file 0600, with no overwrite:

- selection-template.csv — original ordinal, source severity and evidence-reference count for every original source record, plus blank HUMAN selection, priority, and question columns.
- selection-receipt.json — exact unsigned SHA-256 bindings to the original source, human worksheet and original blank template; all permission flags literal false.
- PRIVATE-source-free-selection-studio.html — complete local self-contained browser UI with original ordinal/severity/evidence-reference count only. Search and severity filter, up to 64 selected entries, pagination, HUMAN priority and questions, filtered bulk selection and confirmation, PRIVATE CSV export. No original targets/identifiers/evidence/human worksheet in this browser file. CSP-pinned JS/CSS; no network, storage or APIs.
- PRIVATE-selection-instructions.html — scriptless local instructions.

In the browser studio select at most 64 original ordinals, set each selected row HUMAN priority to routine/soon/urgent, supply a human review question, and download PRIVATE-human-selection.csv. Browser choices live only in local memory until exported. **Resume PRIVATE Studio CSV:** use the built-in local CSV file picker to reopen a previously exported canonical Studio CSV; before asking for explicit HUMAN replacement confirmation, it checks all original ordinals, severity, reference counts, every status, priority, question and the 64-item limit as a single batch. Invalid/private wrong-source membership preserves all current unsaved selections. The browser does not authenticate an original lab producer or a source hash; the Python publish command still requires the independent original source plus SHA-bound original receipt. **Local PRIVATE disposal:** select **Discard unsaved local choices** in the generated source-minimized browser to explicitly clear the selection state, decrypted current HUMAN notes and input fields in this tab after confirmation. Already downloaded files, the separately generated source-ordinal metadata and browser-GC/physical-memory guarantees are outside that action: it never claims secure erasure. **Optional encrypted private continuity:** enter a fresh 12–120-character passphrase twice to export the current validated selection as a canonical .luec AES-256-GCM workroom encrypted in-browser with a random 16-byte salt, 12-byte nonce, purpose-bound AAD and PBKDF2-SHA256 310k iterations. Restore with the same passphrase using the separate encrypted file picker; the decrypted bytes undergo full original-ordinal/severity/count selection re-admission and a separate HUMAN replace confirmation, or existing unsaved state is kept. The passphrase input is cleared after use; no browser-garbage-collection guarantee. WebCrypto secure context is required; there is never a silent plaintext fallback. The .luec does NOT contain original evidence/target, nor does its authentication establish original source producer or current client consent. Alternatively edit selection-template.csv offline: set select_for_private_dossier to yes for selected rows, priority and human question; preserve ALL ordinal, severity, evidence count and ordering. Leave priority/question empty for unselected rows. Export UTF-8 CSV privately; beware of spreadsheet cloud sync.

## Step 2 — Create PRIVATE selected-only evidence dossier

    python3 assessment-evidence-curation/curate.py publish \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --output-dir ./NEW-PRIVATE-EVIDENCE-DOSSIER

Full source re-admitted through original unchanged validator. Whole original worksheet must match preparation receipt's exact byte SHA, and ALL selection rows must match original ordinal/severity/evidence count before output. Source change, wrong worksheet, missing, duplicated or re-ordered rows, unknown HUMAN priority, invalid human question, more than 64 selected ordinals and receipt drift cause single HOLD without partial publishing.

Result, NEW 0700 directory / private 0600 artifacts:

- PRIVATE-curated-dossier.html — only selected original finding records and original evidence details + unchanged human ownership/action/blocker, with human question and priority, printable and scriptless. Explicit REVIEW ONLY / NOT VERIFIED warnings.
- PRIVATE-source-minimized-HUMAN-handoff.html — a separate printable scriptless PRIVATE recipient question handoff, containing only selected original ordinals, source-reported severity and evidence-reference count, human priorities and questions. Deliberately no original target, finding ID, run/scenario ID, evidence content, source hash or human-owner notes. **Human-entered questions may still identify a client: NOT public-safe or certified anonymous.**
- PRIVATE-curation-receipt.json — exact original source/worksheet/selection and both PRIVATE report unsigned digests plus selected source ordinals; PRIVATE, never a producer signature.
- PRIVATE-HUMAN-routine-priority.html / PRIVATE-HUMAN-soon-priority.html / PRIVATE-HUMAN-urgent-priority.html (only for nonempty priority groups) — three separately private, printable scriptless, source-minimized human question packets. Each contains ONLY the selected ordinal/severity/evidence-count and the HUMAN priority/question for that group, never other groups' HUMAN questions or full original findings. Preparation does not deliver a real message to anyone; HUMAN recipient routing/disclosure approval remains separate. The unsigned PRIVATE-curation-receipt binds every generated group packet byte hash.
- anonymous-counts-PRIVATE.json — source-count, selected-count and source-reported severity/HUMAN priority numeric counts only. No original run, target, finding, evidence, human names/questions, source hash or paths. **Even small-cohort counts can be identifying: still PRIVATE.**

Exit code 2 = REVIEW_ONLY product generated, 3 = HOLD; neither is a valid security verdict. All source and existing source-owner files remain unchanged.

## Step 3 — Compare PRIVATE HUMAN selection revisions (without target work)

Use two complete separately saved original-ordinal HUMAN selection CSVs, **both against the same exact original PRIVATE lab source, original manifest, seven-column HUMAN worksheet and selection-preparation receipt**:

    python3 assessment-evidence-curation/revision.py \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --before-selection ./PRIVATE-human-selection-v1.csv \
      --after-selection ./PRIVATE-human-selection-v2.csv \
      --output-dir ./NEW-PRIVATE-HUMAN-REVISION

Each version is independently fully source-admitted, including all unchanged original ordinal/severity/evidence-count source rows, status and HUMAN question constraints. Creates only a NEW private output directory with:

- PRIVATE-human-curation-revision.html — fully scriptless, printable human before/after for selected original ordinal, priority, question; clearly flags five kinds of change including added/removed selection and simultaneous question/priority changes; unchanged original evidence is NOT copied into the report.
- PRIVATE-human-curation-revision-receipt.json — PRIVATE unsigned original source, exact HUMAN worksheet, two selection byte SHA-256 values, generated report hash and changed original ordinal list. Not a trusted producer signature.
- human-revision-counts-PRIVATE.json — source-ID-free, hash-free numeric HUMAN selection move totals plus changed source-reported severity distribution; remains PRIVATE for small cohorts.

**A selection removed means only that a HUMAN deselected it.** Never infer that original evidence, scope, risk, target validity, fix or consent changed.

## Step 4 — View 2–12 separately saved PRIVATE HUMAN selection versions

    python3 assessment-evidence-curation/history.py \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection-v1.csv \
      --selection ./PRIVATE-human-selection-v2.csv \
      --selection ./PRIVATE-human-selection-v3.csv \
      --output-dir ./NEW-PRIVATE-HUMAN-HISTORY

Provide between **2 and 12 --selection flags in explicit oldest-to-newest HUMAN order**. No clock chronology is fabricated: numbers v1–v12 are the user's declared sequence, not actual validated timestamps. Original source, manifest and exact HUMAN worksheet are re-admitted once, and every selection file is independently fully admitted before any output.

Produces **PRIVATE-human-curation-history.html**: readable scriptless human timeline with 2–12 version HUMAN selections, ordinal/priority matrix, per-revision changed priority/questions with human-proposed wording and original reported severity. No original target/finding ID, evidence body, source hash or original HUMAN worksheet owner/action is included. **Human-entered questions may identify clients, so still PRIVATE.** A separate **human-curation-history-counts-PRIVATE.json** contains only grouped source-reported/priority HUMAN counts and step changes, no original IDs/hashes/notes, while **PRIVATE-human-curation-history-receipt.json** binds the original source, worksheet and ordered private version bytes with unsigned SHA-256 and exact selected ordinals. A missing HUMAN selection never indicates original finding fixed or revoked.

## One foreground PRIVATE operator console

Use the menu instead of assembling long paths or shell commands:

    python3 assessment-evidence-curation/console.py

It offers **all eight complete offline workflows**: prepare local browser workroom, publish selected finding report, compare two HUMAN selections, inspect 2–12 HUMAN versions, prepare PRIVATE recipient replies or reconcile recipient response CSV. Enter only explicit existing local ORIGINAL input files, a NEW private output directory, and exactly `REVIEW ONLY` after the accurate PRIVATE disclosure warning. No subprocess or target network is invoked, no special operating-system privileges or assessment grant are requested. Cancelled, invalid or missing inputs HOLD without claiming completed work. Existing source and prior local packages remain untouched.

## Step 5 — PRIVATE recipient HUMAN question/reply exchange (without assessment execution)

The original selected-only HANDOFF can now be returned with human replies. This **does not** mean a respondent is authenticated or the finding is verified. The original full lab source, original unsigned briefing manifest, original exact seven-column HUMAN worksheet, original selection receipt and complete selected HUMAN CSV are **all re-admitted** before preparing the recipient template or accepting a reply.

Prepare a PRIVATE original-ordinal / HUMAN question template:

    python3 assessment-evidence-curation/response.py prepare \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --output-dir ./NEW-PRIVATE-RECIPIENT-TEMPLATE

Creates an exclusive 0700 PRIVATE output folder with 0600 files: PRIVATE-recipient-response-template.csv (exact selected source ordinals, reported severity/evidence-reference counts, HUMAN priority/question, **blank recipient HUMAN stage/reply/followup question**), PRIVATE-recipient-response-binding.json (source/worksheet/selection/template unsigned byte hashes, mandatory literal false authority), and PRIVATE-recipient-response-instructions.html (scriptless explicit privacy warnings). No original target, finding ID, evidence body, producer, run or original HUMAN owner/action is included in this limited recipient handoff; HUMAN question text can still identify the source, so use a separately approved PRIVATE exchange channel.

A human can privately fill ONLY the three recipient columns in that CSV. Allowed self-reported stage: empty, responded_claimed, needs_more_information or blocked_human. Freeform recipient reply/followup question is limited to 500 safe characters each, without dangerous formula/control prefixes; an empty stage must have both reply fields empty. No stage carries any fix, authenticity, consent or authorization semantics.

Conservatively reopen this human reply against the unchanged original PRIVATE source and the exact original selected HUMAN questions:

    python3 assessment-evidence-curation/response.py return \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --response-binding ./NEW-PRIVATE-RECIPIENT-TEMPLATE/PRIVATE-recipient-response-binding.json \
      --response ./PRIVATE-filled-recipient-reply.csv \
      --output-dir ./NEW-PRIVATE-RECIPIENT-RETURN

The whole original selection and recipient reply must be exactly aligned to original ordinal, severity, original evidence-reference count, selected HUMAN priority and exact original question, in the same row order. Any changed source, recipient substitution, invalid stage or modified original question causes one atomic HOLD, preserving all existing files. Generates PRIVATE-recipient-HUMAN-replies.html (scriptless HUMAN reply vs original HUMAN question, without original source evidence), PRIVATE-recipient-HUMAN-reply-receipt.json (unsigned binding and exact selected source ordinal list), and recipient-HUMAN-reply-counts-PRIVATE.json (source-ID-free human stage totals). No email, calendar API, real messaging, authentication or target action.

## One unified foreground PRIVATE console

Run:

    python3 assessment-evidence-curation/console.py

It now offers **eight** HUMAN-only offline workflows: prepare source-minimized browser studio, produce the selected-only original PRIVATE dossier, compare two HUMAN selections, view 2–12 HUMAN versions, prepare a recipient reply template, and privately re-admit that response. Every operation requires a separate **REVIEW ONLY** confirmation including its disclosure profile, explicit local existing source/receipt/CSV paths and one NEW private output directory. It runs no subprocess/assessment, never contacts a target, never mutates original source or existing outputs and cannot authenticate a recipient.

## Step 6 — PRIVATE source-bound browser editing and encrypted recipient continuity

The existing `response.py prepare` operation now also creates `PRIVATE-recipient-browser-studio.html`. It is a complete local-browser HUMAN reply editor with question/ordinal search, original HUMAN priority + recipient-stage filters, accessible form fields, a counted queue, strict editable stage semantics, an exact original-selected-ordinal CSV resume/export, and explicit discard of unsaved browser state. All source context is in an inert template block under CSP source-hash-pinned JavaScript/CSS; **no network, original target or evidence export**. It contains the sender's HUMAN question text, which may identify clients and must be treated as PRIVATE.

To keep longer HUMAN answers out of an unencrypted spreadsheet while still working offline, a recipient can enter a separate 12–120-character passphrase and confirmation to export a local `.luer` AES-256-GCM **encrypted** workroom. It uses PBKDF2-SHA256 310,000 iterations, new independent 16-byte random salt / 12-byte nonce, purpose-bound AAD bound to an unsigned SHA-256 of the exact original question rows, and literal-false authority flags. Opening a `.luer` checks canonical authenticated ciphertext, exact original HUMAN row digest, decrypts locally and sends the full HUMAN reply through the **same atomic ordinal/priority/question and recipient stage/answer admission** as canonical CSV resume, with a separate HUMAN confirmation. Existing in-memory replies survive incorrect source/password/format. No silent plaintext fallback: a browser secure context with WebCrypto is mandatory. Actual respondent identity, source producer, consent, remote calendars, browser GC and physical-memory secure erasure are not established.

The original CLI `response.py return` still requires the **separate original lab JSON, its original manifest, original seven-column HUMAN worksheet, original selected CSV + prepared receipt and private recipient binding** before accepting any exported reply. Its binding can read older canonical preparation receipts; newer packages also include a digest of the generated standalone browser studio. Browser encryption proves neither real tenant nor approved assessment.

## Step 7 — PRIVATE sender HUMAN response triage and next-question workflow

New `response_triage.py` takes the completed reply from Step 5/6 and performs **full original source + original manifest + HUMAN worksheet + original selection receipt + exact selected CSV + original response binding + exact recipient response** admission. It creates a PRIVATE triage package:

    python3 assessment-evidence-curation/response_triage.py prepare \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --response-binding ./PRIVATE-RECIPIENT/PRIVATE-recipient-response-binding.json \
      --response ./PRIVATE-recipient-human-response.csv \
      --output-dir ./NEW-PRIVATE-SENDER-TRIAGE

The new PRIVATE package contains a source-bound eight-column `PRIVATE-sender-triage-template.csv`, an unsigned `PRIVATE-sender-triage-binding.json`, scriptless instructions, and a complete `PRIVATE-sender-triage-browser.html` offline editor. The browser displays the original HUMAN selected question, existing recipient HUMAN reply and follow-up (all unverified), with local search, routing filter, owner-group/next-question fields, source-ordinal paging, human-confirmed CSV export and strict full source-row-bound CSV resume. Only original ordinal, HUMAN priority, recipient self-reported stage, SHA-256 of exact reply/recipient-next-question text plus sender HUMAN route/owner/next-question enter the sender CSV. Incoming replies and human questions may still identify a client; browser content is PRIVATE.

Four non-authorizing sender HUMAN routes are available: `needs_human_review`, `request_clarification`, `route_to_owner`, and `documented_for_followup`. Empty means unreviewed; HUMAN route-to-owner requires a group plus next question, request clarification requires a next question. No choice creates an approved finding, verified fix, grant, revocation, real assigned owner or original risk result.

The sender returns the completed HUMAN triage CSV by explicit local CLI:

    python3 assessment-evidence-curation/response_triage.py return \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --response-binding ./PRIVATE-RECIPIENT/PRIVATE-recipient-response-binding.json \
      --response ./PRIVATE-recipient-human-response.csv \
      --triage-binding ./NEW-PRIVATE-SENDER-TRIAGE/PRIVATE-sender-triage-binding.json \
      --triage ./PRIVATE-sender-HUMAN-triage.csv \
      --output-dir ./NEW-PRIVATE-SENDER-RETURN

The CLI fully reopens original producer-declared data, all original matching HUMAN selected rows and recipient answers, and exact per-response SHA before admitting any sender change. It writes a NEW 0700 private directory, 0600 files: scriptless `PRIVATE-sender-HUMAN-triage.html`, matching original/selection/response/triage unsigned byte receipt, and source-ID-free private numeric sender-route counts. It **also builds independent least-disclosure PRIVATE route packets**: `PRIVATE-HUMAN-request-clarification.html` and `PRIVATE-HUMAN-route-to-owner.html`, each showing only HUMAN actions for that route, plus `PRIVATE-HUMAN-next-actions.csv` with source ordinal, human route, human owner/group and human next question. No original target, finding ID, run, source hash, raw evidence or other recipients' private source/notes is inserted into these separate packets. Original answer/question content may still identify clients, and no recipient, message delivery or consent is authenticated or initiated. The original PRIVATE triage receipt now includes the byte SHA-256 of each outgoing packet. Wrong original, missing source/response row or mismatched human text HASH or unsupported stages/roles HOLD atomically, leaving all previous files intact. **No actual respondent identity, tenant provenance, security finding validation, consent or remediation authority is created.**

The same `console.py` now offers **ten** offline human-only workflows, including preparing and returning PRIVATE sender HUMAN triage. The source-bound sender browser also permits optional **encrypted PRIVATE HUMAN triage continuity**: 12–120 character password, PBKDF2-SHA256 310,000 iterations, random per-save 16-byte salt/12-byte nonce, AES-256-GCM with purpose AAD bound to SHA-256 of exact original received HUMAN reply rows, canonical `.luts` envelope and literal-false authority flags. Encrypted load rejects a mismatched original recipient reply, wrong password or noncanonical envelope before complete original source-ordinal/recipient reply hash/route/question CSV re-admission, then explicitly asks the HUMAN sender before replacing local edits. There is no network/key service, browser persistent state or silent plaintext fallback. Password inputs are cleared after use but browser/physical memory secure erase is not claimed. A password never authenticates original findings, recipient identity, consent or approval. It does not run scanners, workers, subprocesses or network calls.

## Step 8 — Explicit next HUMAN question proposal: close the private correspondence loop

The operator can now **prepare an optional next recipient round without manually copying HUMAN replies and questions**, while never treating unanswered/removed questions as fixed or verified. The new `next_round.py` workflow independently re-admits **the same original lab source, original manifest, exact original HUMAN worksheet, original selection receipt + full original selected CSV, source-bound recipient reply and its binding, and the complete exact sender HUMAN triage CSV + original triage binding**.

    python3 assessment-evidence-curation/next_round.py \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --response-binding ./PRIVATE-RECIPIENT/PRIVATE-recipient-response-binding.json \
      --response ./PRIVATE-recipient-human-response.csv \
      --triage-binding ./NEW-PRIVATE-SENDER-TRIAGE/PRIVATE-sender-triage-binding.json \
      --triage ./PRIVATE-sender-HUMAN-triage.csv \
      --output-dir ./NEW-PRIVATE-NEXT-HUMAN-ROUND

It creates an **entirely NEW privately protected output directory** containing `PRIVATE-proposed-next-HUMAN-selection.csv`, `PRIVATE-next-HUMAN-question-proposal.html`, original-source-/reply-/triage-byte-linked PRIVATE unsigned receipt, and source-ID-free PRIVATE numeric counts. The CSV uses **exact original six-column selection format** and preserves all source ordinal, original severity, evidence-reference count, unchanged selection membership, original HUMAN priority and unselected rows in original sequence. It changes **only** HUMAN questions where a sender explicitly chose `request_clarification` or `route_to_owner` and supplied a genuinely changed HUMAN next question. It never deselects a finding due to its recipient response, never infers remediation or creates a target, grant or permission.

The scriptless private proposal HTML shows original HUMAN vs new proposed questions for explicit operator inspection. If no HUMAN question actually changed or any original / recipient / triage source binding differs, the entire operation HOLDs and publishes nothing. The proposed selection may be deliberately reviewed and later passed into the existing original `response.py prepare` as a **new original source-bound HUMAN proposal**. There is **no automatic sending, calendar scheduling, finding verification, source approval, client/operator authentication or consent**. The single foreground `console.py` now exposes **ten** locally run, separately confirmed HUMAN workflows.

## Step 9 — Source-bound consolidated HUMAN assessment workroom (optional stage-by-stage)

The existing offline source-bound result, HUMAN selection, recipient replies and sender triage previously lived in separate private exports. Use the new `review_hub.py` to build a **single source-minimized HUMAN stage overview**, without marking any security finding verified or launching any assessment.

It operates in three deliberate modes: **selection-only**, **original recipient reply available**, and **original sender triage available**. It independently re-admits the unchanged original lab JSON, manifest, exact seven-column HUMAN worksheet, prepared selection receipt and full original selection every time. If recipient data are supplied, the complete original source-bound recipient receipt/CSV are also admitted. If sender triage is supplied, the original recipient reply must exist and the complete original sender triage binding and CSV must also be re-admitted. Partial/inconsistent pairing is a single HOLD; no files are overwritten or partially published.

Selection-only:

    python3 assessment-evidence-curation/review_hub.py \
      --source ./PRIVATE-original-lab.json \
      --manifest ./PRIVATE-original-briefing/manifest.json \
      --worksheet ./PRIVATE-human-followup.csv \
      --selection-receipt ./NEW-PRIVATE-PREPARATION/selection-receipt.json \
      --selection ./PRIVATE-human-selection.csv \
      --output-dir ./NEW-PRIVATE-HUMAN-OVERVIEW

To include recipient replies, additionally supply both `--response-binding` (original private recipient binding JSON) and `--response` (original HUMAN reply CSV). To also include sender follow-ups, **in addition** provide both `--triage-binding` (original private sender triage binding JSON) and `--triage` (original HUMAN sender triage CSV). The operator console option **10** provides the same functionality through an explicit `selection / recipient / triage` stage choice.

The new package also includes **PRIVATE-HUMAN-interactive-workroom.html**, a separate self-contained CSP-SHA-pinned offline browser dashboard with 16-record pagination, original ordinal and source-reported severity filters, HUMAN priority/response/route/phase filters, live counts, and collapsed PRIVATE human question/reply fields. The UI exposes only original ordinal, canonical metadata and relevant HUMAN freeform notes — NOT original targets, finding IDs, source manifests or evidence bodies. Notes are **hidden on screen by default but embedded in the HTML**, not encrypted. An explicit HUMAN confirmation is required to reveal all notes; printing the current page honors the currently revealed-note state and warns about confidentiality. For the full multi-page printable PRIVATE dossier use the separate scriptless HTML report. Exact byte SHA-256 of the interactive HTML is included in the original-bound private receipt.

The resulting **NEW PRIVATE** 0700 package contains `PRIVATE-HUMAN-assessment-overview.html` (scriptless, per-ordinal source-reported severity and evidence-reference counts; HUMAN priority, recipient self-reported stage and HUMAN sender route, with collapsed personal questions/replies and suggested HUMAN-only action), `PRIVATE-HUMAN-assessment-overview-receipt.json` (literal false authority flags plus unsigned byte SHA-256 of original source, selection, optional original recipient/triage CSV and generated HTML), `PRIVATE-HUMAN-assessment-overview-counts.json` (source-identifier-free numeric priority, self-reported recipient status and sender routing counts), and separate priority-only PRIVATE HTML workroom reports for each nonempty HUMAN routine/soon/urgent group. A source-minimized `PRIVATE-HUMAN-review-candidates-NOT-DISPATCHED.csv` also lists original ordinals, source-reported severity, HUMAN priority/stage/route and **only a fixed, proposed HUMAN next action**, ordered urgent/soon/routine. It deliberately omits original targets, finding IDs, raw evidence, HUMAN owner labels and freeform questions or replies; it is a private proposed review list, NOT an actual task queue, assignment or authorized dispatch. The source-bound private receipt includes the exact SHA-256 of this file.

This is a **document-state dashboard, NOT a live assessment/runtime dashboard**. `responded_claimed`, `route_to_owner` or a removed selection is never a verified security finding, fixed issue, actual owner assignment, authorized target, consent, appointment or dispatch. Only previously available HUMAN fields are shown. Original targets, finding IDs and evidence body are omitted from the workroom; freeform questions, owner names and answers can **still identify a client**, so every HTML/JSON/count artifact remains PRIVATE. There is no server, email, worker, network, model or external connector action.

## Safety / release fence

No scanner, DNS, network target, model, subprocess, live assessment, authorization, grant, trusted producer, automated triage verdict, remediation/retest execution, or changing consent. Byte hashes do NOT authenticate any source, operator, tenant, findings or permission. HUMAN stages/priorities are proposals, not actual fixes.

Only NEW companion files under assessment-evidence-curation/. Frozen original owner #1672 at exact HEAD 7b537a1f67d01ce7a3104a3710d48100109c6604. Other worker, original runtime/DomainStore/auth/scope, CI and test/QA paths untouched.

**DO NOT MERGE MAIN OR DEPLOY.** Original exact-approved-head hosted GitHub CI + permanently registered named VPS CI, original source-owner review, independent security/privacy/browser review, #177/#182/#829, authentic separately authenticated current client/operator consent and action-time revocation, and explicit HUMAN GO remain mandatory. Nothing in this companion claims to have met these gates.

No QA or regression tests authored or executed. Source/syntax inspection is not independent security certification.
