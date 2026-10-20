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

It offers **all six complete offline workflows**: prepare local browser workroom, publish selected finding report, compare two HUMAN selections, inspect 2–12 HUMAN versions, prepare PRIVATE recipient replies or reconcile recipient response CSV. Enter only explicit existing local ORIGINAL input files, a NEW private output directory, and exactly `REVIEW ONLY` after the accurate PRIVATE disclosure warning. No subprocess or target network is invoked, no special operating-system privileges or assessment grant are requested. Cancelled, invalid or missing inputs HOLD without claiming completed work. Existing source and prior local packages remain untouched.

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

It now offers **six** HUMAN-only offline workflows: prepare source-minimized browser studio, produce the selected-only original PRIVATE dossier, compare two HUMAN selections, view 2–12 HUMAN versions, prepare a recipient reply template, and privately re-admit that response. Every operation requires a separate **REVIEW ONLY** confirmation including its disclosure profile, explicit local existing source/receipt/CSV paths and one NEW private output directory. It runs no subprocess/assessment, never contacts a target, never mutates original source or existing outputs and cannot authenticate a recipient.

## Safety / release fence

No scanner, DNS, network target, model, subprocess, live assessment, authorization, grant, trusted producer, automated triage verdict, remediation/retest execution, or changing consent. Byte hashes do NOT authenticate any source, operator, tenant, findings or permission. HUMAN stages/priorities are proposals, not actual fixes.

Only NEW companion files under assessment-evidence-curation/. Frozen original owner #1672 at exact HEAD 7b537a1f67d01ce7a3104a3710d48100109c6604. Other worker, original runtime/DomainStore/auth/scope, CI and test/QA paths untouched.

**DO NOT MERGE MAIN OR DEPLOY.** Original exact-approved-head hosted GitHub CI + permanently registered named VPS CI, original source-owner review, independent security/privacy/browser review, #177/#182/#829, authentic separately authenticated current client/operator consent and action-time revocation, and explicit HUMAN GO remain mandatory. Nothing in this companion claims to have met these gates.

No QA or regression tests authored or executed. Source/syntax inspection is not independent security certification.
