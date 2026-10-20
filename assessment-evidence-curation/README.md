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

In the browser studio select at most 64 original ordinals, set each selected row HUMAN priority to routine/soon/urgent, supply a human review question, and download PRIVATE-human-selection.csv. Browser choices live only in local memory until exported. **Resume PRIVATE Studio CSV:** use the built-in local CSV file picker to reopen a previously exported canonical Studio CSV; before asking for explicit HUMAN replacement confirmation, it checks all original ordinals, severity, reference counts, every status, priority, question and the 64-item limit as a single batch. Invalid/private wrong-source membership preserves all current unsaved selections. The browser does not authenticate an original lab producer or a source hash; the Python publish command still requires the independent original source plus SHA-bound original receipt. **Optional encrypted private continuity:** enter a fresh 12–120-character passphrase twice to export the current validated selection as a canonical .luec AES-256-GCM workroom encrypted in-browser with a random 16-byte salt, 12-byte nonce, purpose-bound AAD and PBKDF2-SHA256 310k iterations. Restore with the same passphrase using the separate encrypted file picker; the decrypted bytes undergo full original-ordinal/severity/count selection re-admission and a separate HUMAN replace confirmation, or existing unsaved state is kept. The passphrase input is cleared after use; no browser-garbage-collection guarantee. WebCrypto secure context is required; there is never a silent plaintext fallback. The .luec does NOT contain original evidence/target, nor does its authentication establish original source producer or current client consent. Alternatively edit selection-template.csv offline: set select_for_private_dossier to yes for selected rows, priority and human question; preserve ALL ordinal, severity, evidence count and ordering. Leave priority/question empty for unselected rows. Export UTF-8 CSV privately; beware of spreadsheet cloud sync.

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
- anonymous-counts-PRIVATE.json — source-count, selected-count and source-reported severity/HUMAN priority numeric counts only. No original run, target, finding, evidence, human names/questions, source hash or paths. **Even small-cohort counts can be identifying: still PRIVATE.**

Exit code 2 = REVIEW_ONLY product generated, 3 = HOLD; neither is a valid security verdict. All source and existing source-owner files remain unchanged.

## Safety / release fence

No scanner, DNS, network target, model, subprocess, live assessment, authorization, grant, trusted producer, automated triage verdict, remediation/retest execution, or changing consent. Byte hashes do NOT authenticate any source, operator, tenant, findings or permission. HUMAN stages/priorities are proposals, not actual fixes.

Only NEW companion files under assessment-evidence-curation/. Frozen original owner #1672 at exact HEAD 7b537a1f67d01ce7a3104a3710d48100109c6604. Other worker, original runtime/DomainStore/auth/scope, CI and test/QA paths untouched.

**DO NOT MERGE MAIN OR DEPLOY.** Original exact-approved-head hosted GitHub CI + permanently registered named VPS CI, original source-owner review, independent security/privacy/browser review, #177/#182/#829, authentic separately authenticated current client/operator consent and action-time revocation, and explicit HUMAN GO remain mandatory. Nothing in this companion claims to have met these gates.

No QA or regression tests authored or executed. Source/syntax inspection is not independent security certification.
