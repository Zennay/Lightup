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

## Revision-aware follow-up without stale links

New source revisions must not silently inherit old human stages. The separate
[private source renewal CLI](refresh.py) accepts an older exact original pair,
its bound manual links, and a new original comparator/findings pair:

    python3 assessment-remediation/refresh.py \
      --old-comparison /private/old-comparison.json \
      --old-findings-csv /private/old-findings.csv \
      --old-links /private/old-manual-links.json \
      --new-comparison /private/new-comparison.json \
      --new-findings-csv /private/new-findings.csv \
      --output-dir /private/lightup-followup \
      --prefix reviewed-revision

It creates three 0600 **new-only private** artifacts: source-revision HTML,
source-bound refreshed link JSON, and anonymous refresh-count JSON. It explicitly
classifies original case and finding IDs as added, changed, absent or unchanged.
Absent never means fixed. The default withholds ALL old human links until reviewed.

For a human operator who has independently verified that the source files
continue to concern the same actual client and engagement, add
--carry-unchanged: only exact semantically identical original scenario rows
**and** original five-column finding rows may retain their manual stage/notes.
Every changed/missing source row loses its old human link. Added findings/cases
are never linked automatically. A changed source, withheld link or original new
HOLD keeps review output HOLD; a complete unchanged REVIEW_ONLY source is
still not security clearance, permission or successful retest. No original
file is modified or action is dispatched.

## Portable confidential review room (single private ZIP)

To hand off the four original bridge.py outputs as one private source-bound
room, keep all four files in the same owner-only output folder and run:

    python3 assessment-remediation/packet.py bundle \
      --output-dir /private/lightup-followup --prefix reviewed

This creates **reviewed-private-room.zip**, one new exclusive fsynced 0600
artifact with the unchanged original private scriptless HTML, private manual
link JSON, anonymous aggregate JSON, private formula-escaped agenda CSV,
README and a SHA-256/size manifest for every included output. No original
benchmark case JSON, original client findings CSV, target, credential, consent
record, API call or execution code is bundled. The ZIP still contains sensitive
scenario and finding IDs, confidential notes and human assignments: only hand
it to a separately verified authorized recipient via an approved private route.

Read-only offline integrity inspection without unpacking is available:

    python3 assessment-remediation/packet.py inspect \
      /private/lightup-followup/reviewed-private-room.zip

Inspection requires the exact expected six static ZIP members, safe regular-file
metadata, no duplicates, no compression or extra payloads, valid SHA-256
manifest and matching original aggregate/link schema. It exits 2 REVIEW_ONLY
or 3 HOLD, never confirms sender authenticity, client ownership, current
consent, safety, remediated vulnerabilities or permission to retest.

### One-command operator delivery

The native bridge CLI also supports --bundle to generate its four original
private artifacts **and** the portable 0600 private room ZIP in one invocation.
It rejects all five output names up front and delegates to the same exact
source-bound packet builder; no original source is modified. A sudden process
crash between per-file publications can still leave completed private
intermediate files; do not treat the five artifacts as a transactional DB commit.

    python3 assessment-remediation/bridge.py \
      --comparison /private/completed-cohort-comparison.json \
      --findings-csv /private/authenticated-client-findings.csv \
      --links /private/lightup-private-manual-links.json \
      --output-dir /private/lightup-followup \
      --prefix final-handoff --bundle

## Direct path from two already-completed original cohorts

Instead of creating an intermediate original cohort comparator JSON by hand,
use the new **source-integrated offline CLI**:

    python3 assessment-remediation/from_cohorts.py \
      --baseline /private/original-baseline-cohort.json \
      --candidate /private/original-candidate-cohort.json \
      --findings-csv /private/authenticated-client-findings.csv \
      --output-dir /private/lightup-followup \
      --prefix first-run --bundle

The tool takes bounded immutable private snapshots of TWO explicit
already-completed original cohort files, invokes the unchanged original #1515
comparison through its existing lightup_review compare --cohort --format
desk-json entry point, verifies original canonical 15-metric source status and
non-authority, rechecks the original source files, and then publishes the exact
first-run-canonical-comparison.json alongside the four private bridge
artifacts and optional confidential 0600 ZIP. No original cohort file or client
export is modified or included in the handoff ZIP.

For later human mapping, open the separately packaged standalone Mapping Studio,
select first-run-canonical-comparison.json and the same original five-column
findings CSV, then export source-bound private human links. Reinvoke bridge.py
with a NEW prefix and --links to produce the linked dossier; do not expect
human links to magically appear in the first direct cohort comparison. Review
original source identity and same-client/engagement linkage with an independent
operator before recording any human associations.

All component outputs are private non-overwriting files; this is **not** a single
transaction across files. The workflow stays REVIEW_ONLY/HOLD and returns 2/3;
a newly constructed comparison is not verified security evidence, grants or GO.

## Original metric transparency and real follow-up backlog

The generated scriptless confidential dossier now exposes on demand the
exact original complete **15 metrics per lab scenario** (baseline, candidate,
delta and source-reported adverse flag) alongside original finding details.
The operator does not invent a severity score or assume successful remediation
from a laboratory metric.

The private CSV action agenda no longer hides missing human associations:
- Every mapped source finding appears with original scenario and status,
  source retest status and separate local human next action.
- Every original finding without any manual scenario link receives an explicit
  UNLINKED_SOURCE human mapping row, highest original severity first.
- Every original lab scenario with no linked finding receives a separate
  human follow-up, with source adverse HOLD first.

These are proposed HUMAN attention items, never real scanner tasks, retests or
vulnerability discoveries. Unknown linkage is not a negative finding.
Aggregate-only output remains free of original source identifiers.

The offline Mapping Studio now also shows selected original 15-metric values
and source remediation text independently from human-only editable notes, with
visible gaps for unlinked original findings and scenarios. Its first-pass
metric/delta/adverse check reduces misleading source displays; the native
Python backend remains the final original reader, including rejection of
duplicate JSON keys.

## Strict local original JSON intake in portable Studio

The portable Studio now rejects duplicate decoded JSON object keys, including
Unicode-escape alias collisions, at every nesting level. It refuses excessive
nesting/object size, nonfinite numbers and trailing JSON, before permitting
local original metrics to be displayed or a private human link draft to be
restored. This prevents the browser's usual JSON.parse key-overwrite behavior
from misleading reviewers about original authority flags, source metrics or
previously saved human annotations. The source CLI remains the final strict
original validator. The private single-file browser package has no extra
dependencies and its CSP hashes are updated with the source.
