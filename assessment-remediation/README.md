# LightUp · Assessment → Remediation human link workbench

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This independent private offline workbench aligns already-completed original lab benchmark results with separately authenticated and previously exported LightUp client findings. It does not authenticate the sources, verify that they belong to the same client, establish ground truth, verify remediation, obtain consent, authorize scanning, run a tool, perform a retest, grant access, or approve a release.

## Human workflow

1. Obtain an original completed **#1515 cohort comparator JSON** using the unchanged original comparator with cohort and desk-json format (1–64 complete cases, HOLD or REVIEW_ONLY). A no-work preview is not a finished benchmark result.
2. Obtain the original five-column LightUp render_client_findings_csv output via the separately authenticated existing export pathway for the relevant client and engagement. The CSV is redacted but remains sensitive. Export authorization is not current scan permission.
3. Confirm **identity, client and engagement out of band** with a real operator before linking the separate sources. A matching digest never certifies source ownership.
4. Open [the private offline mapping Studio](standalone.html) on your own computer. Choose both source files. Select individual scenarios and finding IDs, supply local human stage/reviewer/next action/notes, export a source-bound private JSON. One scenario may link to multiple findings and vice versa; repeated pairs are rejected. Restore the draft only with the exact same original source bytes.
5. Use the Python CLI for **strict source admission** and generation of a private no-network human operator briefing and follow-up agenda. Browser import is not the final validation authority.

### Concrete CLI

Run from a checkout containing the original unchanged assessment composition and this new directory. Choose a private 0700 directory that you own and an unused output prefix.

    install -d -m 700 /private/lightup-followup
    python3 assessment-remediation/bridge.py \
      --comparison /private/completed-cohort-comparison.json \
      --findings-csv /private/authenticated-client-findings.csv \
      --output-dir /private/lightup-followup \
      --prefix initial

After human mapping in the standalone Studio:

    python3 assessment-remediation/bridge.py \
      --comparison /private/completed-cohort-comparison.json \
      --findings-csv /private/authenticated-client-findings.csv \
      --links /private/lightup-private-manual-links.json \
      --output-dir /private/lightup-followup \
      --prefix reviewed

The CLI creates **four private 0600 artifacts** without replacing any existing file:

- PREFIX-private.html — scriptless, no-network private dossier of original source-reported lab case status/metric flags, source findings, and specifically **unverified manual** finding mappings. An original source label of fixed remains source-reported, not independently verified remediation.
- PREFIX-links.json — edit/reimport the manually linked, exact-original-byte-bound PRIVATE human review draft. Contains identifiers, optional notes and could be client confidential; never publicly share.
- PREFIX-private-agenda.csv — separate private per-link human follow-up list, preserving original security-source status separately from human stage. Spreadsheet-leading formula characters are escaped.
- PREFIX-aggregate.json — anonymous source-ID-free counts: original cases, source adverse scenarios, findings by severity, human stage counts; all four authority flags are literal false. No client labels, original IDs, source names/hashes, reviewers, notes or raw findings.

An initial CLI run without manual links produces an empty editable mapping template, **not a clean security verdict**. Source HOLD stays HOLD. Returns exit 2 for REVIEW_ONLY and 3 for HOLD including invalid source; never exit 0 as an assessment grant.

## Native source, privacy and integrity

- Strict source reader and private publisher are imported unchanged from the original assessment-archive/archive.py already composed by original parent PR #1625. Uses bounded single-FD no-follow regular-file reads, duplicate JSON-key and non-finite rejection, and exclusive no-overwrite, fsynced 0600 publication.
- Accepted original lab data: canonical complete #1515 report with all 15 metric names/case, finite and consistent numeric delta, matching adverse metric classifications and scenario/cohort HOLD status, 1–64 original distinct scenario IDs, complete four false authority fields.
- Accepted findings: original five-column CSV schema, 1–350 distinct IDs, 1 MiB limit, canonical original severity/retest values. No target, raw evidence, scanner or credential data is required or imported.
- Optional human link JSON: explicit original scenario and finding IDs, no duplicate pairs, supported HUMAN stage, bounded original-source SHA-256 for both inputs, reviewer/action/note length limits, no Unicode text-direction controls, four false authority fields and 512 links maximum.
- Before publication, both original source files and optional human links are re-read and must still match exact source bytes. The private output folder must be owner-owned and inaccessible to group/other users. Outputs are computed first and published as distinct non-overwriting 0600 final files. Multiple output files are **not one filesystem transaction**; on known failures only identical just-created files are candidates for rollback. Sudden power loss may require operator cleanup of private leftovers.
- The standalone browser Studio is source-only, no external assets/network, local memory only, restrictive SHA-256 CSP. Imported text is rendered via DOM textContent, not HTML injection. The Python CLI performs the final deep validation, including rejection of duplicate JSON object keys that ordinary browser JSON.parse does not identify.
- Nothing changes real DomainStore, scope, grants, consent, pipeline, client security reports, original lab measurements or original retest values. The link between an original scenario and finding is a **human statement**, not proof that the origins match.

## Build and release

The portable standalone is built reproducibly with:

    python3 assessment-remediation/package.py

It embeds original mapping-studio.js and CSS into standalone.html with per-source SHA-256 script/style CSP; no CDN or backend. This is a packaging step, not a QA/test suite.

This independent draft child follows [original held assessment source composition #1625](https://github.com/Zennay/Lightup/pull/1625) and exclusively creates assessment-remediation/ paths. Original active #1515 comparator, #1610 lab CLI, #1595 original Lab Scenario Studio, original evidence-remediation owner, scope/authorization, CI and tests are unchanged.

**Release remains HOLD.** No main merge, production deployment, live target work, consent or grant may occur until original exact-head hosted plus permanently registered named VPS CI, original source owner acceptance, independent privacy/security review, genuine separately authenticated current client and operator consent (with action-time revocation for any actual use), and explicit HUMAN GO. Known original scope #301 acceptance dependencies are not waived or overwritten.
