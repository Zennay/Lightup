# LightUp · Cross-agenda human coordination portfolio

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** Issue #1629, implemented as new-only `assessment-portfolio/` files on a child of the exact original workbench commit `880d59e0a996005dce174516358ca04a48d4633d`. It does not replace or edit the original `assessment-archive/agenda.py`.

## Product behavior

Combine **2–12 already-created original private agenda JSON exports** from the unchanged `assessment-archive/agenda.py` against one explicit human planning reference day. The portfolio groups follow-up rows by neutral role and proposed-date bucket, preserves separate agenda/source slot ordinals, and never merges original source identifiers or bytes.

The output bundle contains three separate, no-overwrite artifacts in an existing directory owned by the current user with mode `0700`:

- `assessment-portfolio-private.html` — static, scriptless, CSP-pinned, printable private workroom. Shows only agenda and source slot ordinals, fixed source kind, human stage, neutral role, proposed review date, date bucket, and canonical generic question.
- `assessment-portfolio-anonymous.json` — aggregate counts only.
- `assessment-portfolio-anonymous.csv` — aggregate counts only.

All three files are created with mode `0600`. The private HTML does not embed source bytes, source paths, filenames, hashes, targets, client identities or HUMAN commentary. The JSON/CSV contain no row-level or per-agenda data.

## Use

Use a local Python 3.11+ environment with the standard library only. Agenda input files must be owner-owned regular files with mode `0600`, no symlink/hard-link alias, and at most 128 KiB each. Duplicate agenda bytes, duplicate JSON keys, unknown fields, inconsistent count maps, mismatched date buckets, unknown stage/role/source-kind values, changed inputs and any true authorization/consent/dispatch/release flag fail the entire batch before outputs are published.

Create a new, separate owner-only output directory; do not place it inside any original source room:

```bash
mkdir -m 700 /private/new-assessment-portfolio
python3 assessment-portfolio/portfolio.py \
  --as-of 2026-10-21 \
  --output-dir /private/new-assessment-portfolio \
  /private/agenda-room-a/agenda.json \
  /private/agenda-room-b/agenda.json
```

The directory must already exist, be owned by the current user and have mode `0700`. Existing output filenames cause HOLD rather than overwrite. If bundle publication fails part-way, newly created files are removed. Input paths are opened component-by-component without following symlinks; inputs must remain stable during the read.

## Interpretation and safety

- Input agenda exports are untrusted claims. Strict schema admission is not source authentication, reviewer authentication, customer identity, consent or security validation.
- `--as-of` is one operator-selected reference day for display. A past proposed date is a human discussion prompt, not a legal deadline, finding age, authorization expiry or proof of missed work.
- Source slot and agenda slot numbers are local ordinals only; they do not prove chronology.
- A missing source, absent flag or changed status is never interpreted as a verified fix.
- Planning flags remain `authorized=false`, `consent_verified=false`, `dispatch_allowed=false`, and `release_allowed=false`.
- No network, model, target, scanner, grant, active assessment, remediation, retest or release operation is performed.

This feature remains **DRAFT/HOLD** until the existing parent workbench and this exact child head receive all required CI, source-owner, independent security/privacy review and authorization gates. No QA/regression suites are added by this change.
