# PRIVATE HUMAN sensitivity triage for completed LightUp note packets

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is a working **offline, owner-private, non-authorizing product**. It is NOT a privacy assessment, a clearance, a source authentication, a real client/operator consent check, a security finding, a grant or permission to share. No scan, active target, connection, model, upload, external distribution or automatic action.

## Purpose
Pattern-masked notes can still contain passwords, personal information, customer identifiers, proprietary data and context-sensitive secrets. This tool adds an independent **complete HUMAN sensitivity concern register** for an already-finalized original LightUp masked-note packet without copying any original or masked note text into the triage workroom. Every source stays identified by its original 1–12 ordinal and unsigned original SHA-256; no filenames or original note content are embedded.

## Offline operator journey

First complete the original `notes.py prepare` and `notes.py finalize` flow. Its already-completed HUMAN packet must retain its original 0700 owner-private folder, 0600 notes, original-source byte manifest, and original final decisions CSV.

```sh
python3 private-assessment-notes/notes.py sensitivity-prepare \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --private-parent /private/owner
```

This creates a **new** `PRIVATE-lightup-sensitivity-draft-*` owner-only directory, with:

- `OPEN-PRIVATE.html`: readable human-only original-slot concern preview, not a source-text viewer.
- `PRIVATE-HUMAN-sensitivity-editor.html`: fully offline, accessible browser editor with CSP hash-pinned script and `connect-src 'none'`; no local/session storage or remote libraries. The operator can choose HUMAN concern statuses per ordinal, identify potential sensitive categories, and enter a short private follow-up question. Download always contains **the complete original source roster**, not only selected/visible items.
- `PRIVATE-HUMAN-sensitivity-template.csv`: immutable source-bound manual editor alternative. **Copy** this file before editing it; never overwrite the original.
- `PRIVATE-triage-bindings.json`: unsigned exact original completed manifest/decision-byte digests, slot roster and literal false authority fields. Keep this PRIVATE.

In the browser, choose per source one of `PENDING`, `REVIEW_REQUIRED`, `WITHHOLD`. Select `UNKNOWN` **alone**, or one or more categories in canonical order `CREDENTIALS|PERSONAL_DATA|CLIENT_DATA|OTHER`. No status is a clearance. Free text is at most 300 characters and cannot begin with spreadsheet formula characters even after whitespace. Avoid copying actual secrets or PII into follow-up notes.

After saving the browser-generated `PRIVATE-HUMAN-sensitivity-completed.csv`, move it to an owner-private location and `chmod 600` it: ordinary browser downloads may default to world-readable permissions.

```sh
chmod 600 /private/owner/PRIVATE-HUMAN-sensitivity-completed.csv
python3 private-assessment-notes/notes.py sensitivity-finalize \
  --completed-packet /private/owner/PRIVATE-lightup-human-handoff-ORIGINAL \
  --triage-kit /private/owner/PRIVATE-lightup-sensitivity-draft-ORIGINAL \
  --completed-csv /private/owner/PRIVATE-HUMAN-sensitivity-completed.csv \
  --private-parent /private/owner
```

The native finalizer reopens the complete **original completed packet** through the original `load_workroom` and `load_decisions` validators, recomputes exact original byte digests and human stage totals, then reopens the unchanged original triage template and source roster. It refuses any source drift, revised original decisions, malformed/extra/reordered/missing rows, unsafe human note, unknown category/status, forged authority flag, or non-private input. Successful local HUMAN review **still exits HOLD (3)**, not PASS. It writes a separate 0700/0600 `PRIVATE-lightup-sensitivity-review-*` containing private scriptless HTML, complete operator concerns CSV and an unsigned source-bound receipt with only counts and literal false authority flags. No note content, filenames, grants or client evidence are copied. A failed finalizer does not overwrite either input.

### Operator limitations and release gates
A status, SHA digest, masked note or category reflects HUMAN-local proposals; it is not verified absence/presence of a secret, safe anonymization, true source provenance or independently authenticated HUMAN identity. Do not circulate these PRIVATE files. No automatic deletion or cryptographic identity/signature is claimed.

All original exact-head hosted and permanently registered named VPS CI, source-owner acceptance, independent security/privacy/browser review, existing #177/#182/#829, separately authenticated current client and operator consent with action-time revocation and explicit HUMAN GO remain mandatory before any eventual main merge, deploy, disclosure or active assessment. This draft adds no QA/test suite and does not change the underlying scanner, authenticator, authorization policy, grant, or original producer.
