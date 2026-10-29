# Offline assessment lab review desk

Status: INCUBATE M3/M7 · PLAN/LAB ONLY · HUMAN REVIEW ONLY · HOLD.

This directory reviews an already-produced private LightUp isolated-lab result.
It does not run assessments, call models, open sockets, contact targets, grant
authorization, approve risk, schedule workers, perform retests, or deploy.

## Use

1. Open index.html directly in a current desktop browser. It has no external
   scripts, styles, fonts, images, APIs, or network dependencies.
2. Choose one existing private result JSON produced by the isolated lab.
   Admission is all-or-nothing: strict UTF-8, duplicate-key rejection, finite
   numbers, known-key schema, bounded bytes, nesting and list sizes.
3. Filter findings by endpoint and severity. Add a human follow-up question
   and disposition for an individual finding.
4. Optionally choose a previous review-return JSON. Resume is accepted only if
   its SHA-256, byte length, source schema, finding count, indexes and check
   identifiers match the exact original input bytes. A mismatch rejects the
   whole return and applies no notes.
5. Explicitly download either a human-only review return or a privacy-minimal
   summary. The source is never uploaded or written by the desk.

The Python standard-library companion emits only aggregate counts:

    python3 assessment-lab-review/review_contract.py /path/to/private-result.json

Exit status 0 means admitted for review; exit status 2 means HOLD. The CLI
never prints findings, endpoint values, evidence IDs, notes, paths or raw errors.

The reader opens each supplied path component relative to an already-open directory descriptor and refuses symlinks in both parent directories and the final file. Parent traversal (`..`), non-regular files, multi-link files and files that change during the bounded read fail closed.

## Data handling

- Source and follow-up notes stay in page memory. There is no localStorage,
  sessionStorage, IndexedDB, service worker, telemetry, fetch, XMLHttpRequest,
  or remote asset.
- Clearing the desk drops its source and notes. Browser history/cache behavior
  is controlled by the browser and operating system; avoid shared profiles.
- The summary export contains counts and false authority flags only. It omits
  source bytes, file names, paths, endpoints, finding text, evidence references
  and the source digest.
- The private human-only return contains exact-source SHA-256 and byte length,
  finding ordinals, check identifiers and follow-up notes. It omits target
  values, evidence IDs, finding text and the original artifact.
- SHA-256 binds a return to bytes; it does not authenticate the source, prove
  ground truth, establish consent, validate authorization or prove completeness.
- Imported claims remain untrusted. Zero findings and partial coverage never
  imply a clean bill of health.

contract.json records schema identifiers, limits and fail-closed flags. The
only files created by the browser are downloads explicitly selected by the
human. A review return is a work note, not a grant, scan request, execution
plan, remediation instruction or deployment artifact.

## Release gates

This is an incubated lab-only capability. Do not merge as a release or deploy
until original hosted CI and permanently registered named VPS CI pass on the
exact head, independent source-owner/security/privacy review is recorded, and
separate authenticated client/operator consent, action-time revocation and
HUMAN GO are established. No external target interaction is part of this feature.
