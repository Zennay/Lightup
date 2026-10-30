# Combined loopback lab score suite

`lightup-lab-score-suite` runs the three first-party lab scorers in one operator command and checks their returned metrics and evidence lineage again before reporting success.

## Run

Choose a **new** output directory whose parent already exists:

    PYTHONPATH=src python -m lightup.lab_score_suite --output-dir ./lab-score-run-001

After installing the package:

    lightup-lab-score-suite --output-dir ./lab-score-run-001

The output directory must not already exist. The command creates it with owner-only permissions and retains three separate SQLite stores plus `report.json`. The JSON report is published atomically with mode `0600`. Existing directories, symlinked path components, parent traversal and group/other-writable ancestors are rejected rather than reused or repaired. The only writable-ancestor exceptions are root-owned sticky `/tmp`, `/var/tmp` and `/dev/shm`. Each parent is opened relative to a pinned `O_NOFOLLOW` directory descriptor before creating the new directory, so a substituted intermediate path cannot redirect creation. The report is fsynced before being published by an atomic no-overwrite hard link, rather than an `exists()`/`replace()` race. This prevents accidental mixing with earlier evidence and protects an existing report even if its final filename appears concurrently.

## Acceptance contract

The command invokes the existing service-inventory, TLS-baseline and HTTP-baseline scorers against their built-in `127.0.0.1` fixtures. Each scorer writes to its own database:

- `service_inventory.sqlite3`
- `tls_baseline.sqlite3`
- `http_baseline.sqlite3`

The aggregate independently requires:

- the scorer's own `passed` value, the **complete exact first-party check set** for its capability (no missing or unknown checks), and every check value exactly true, including `evidence_lineage_verified` and `persisted_record_readback`;
- expected valid-finding counts of 1 service finding, 1 TLS finding and 5 HTTP findings;
- zero invalid findings, missed findings, unknown coverage, scope violations and policy violations;
- integer counters must be actual integers (not booleans that compare equal to 0/1); reproducibility and evidence quality must be numeric non-booleans equal to `1.0`, with positive integer assessed coverage;
- source-defined fixed-scenario identity, exact 2 service / 2 TLS / 4 HTTP distinct bounded evidence IDs, exact first-party engine version, no model bindings, zero human interventions/provider costs, matching worker-call counts and distinct scenario, run and evaluation-record IDs across all three scorers; these checks run **before publishing a suite PASS**, not only during later inspection.
- source-schema-valid optional metrics (non-negative integer counters, non-negative runtime/cost, and fractions within 0–1), plus a bit-exact derived float false-positive rate consistent with the verified valid/invalid counts; negative-zero float scores are rejected instead of being silently normalized. A first-party fixed-loopback calibration must report zero human interventions and zero model/compute cost.

A scorer exception is recorded by exception type only; raw exception text and filesystem paths are not copied into the aggregate. The aggregate exposes fixed `failure_reasons` when identities are aliased across capabilities, rather than silently passing three labels bound to one underlying run. Remaining scorers still run so the operator receives one complete report. Failed or malformed results make the suite exit nonzero. The published report includes only recognized first-party check labels and numeric fields from the canonical EvaluationMetrics schema. Unknown check labels, unrecognized metric names and nonnumeric metric payloads fail the suite with fixed failure codes; no arbitrary source-provided label or value is echoed. The aggregate retains only printable, bounded ASCII scenario/run/record identifiers (maximum 128 characters); path-like, multiline and oversized identifiers are rejected and represented as `null`. The report uses `artifact_directory: "."` instead of repeating the user-supplied output folder name. Original evidence IDs remain in the owner-private SQLite stores; report output contains only an evidence count, never raw evidence payloads.

## Read-only verification of a saved run

A saved `report.json` is a historical claim, not a durable PASS if its SQLite
evidence changes later. Without starting fixtures or invoking workers, verify all
three persisted records again:

```bash
PYTHONPATH=src python -m lightup.lab_score_inspect --output-dir ./lab-score-run-001
# Or after package installation:
lightup-lab-score-inspect --output-dir ./lab-score-run-001
```

The inspector requires an existing owner-private directory and exactly the
original four artifacts (one report and three SQLite files). It refuses
symlinked directory components, unsafe writable ancestors, nonregular or
multiply linked artifacts, oversized files and unexpected SQLite sidecars.
SQLite is reopened through pinned file descriptors with `mode=ro&immutable=1`
and `query_only=ON`; the source runtime schema is **not** initialized and no
replay, network call, retest, provider or authorization gate runs. Existing
WAL/SHM/journal sidecars are rejected rather than silently ignored.

It verifies strict canonical, duplicate-free report/record JSON, database
integrity, each persisted record's SHA-256 and indexed identity, expected
scenario, exact first-party check set, all metric contracts, unique independent
scenario/run/record IDs, the expected 2/2/4 evidence-record counts, and each
evidence record's source-defined worker capability, tool, observation kind,
run identity and fixed loopback lab provenance. It also binds each
persisted evaluation to the exact first-party M1 engine version, an empty
model-binding set, zero human involvement/compute cost and precisely 2/2/4
worker calls across the service/TLS/HTTP scorers. Files must be owner-private:
the directory is mode 0700 and all four artifacts are mode 0600 or stricter.
The SQLite connections explicitly disable trusted schema and reopen through
read-only immutable descriptors; the report stays open and is rechecked for
byte content and inode/stat changes after the SQLite inspections. Both each
SQLite file and the containing directory are checked for concurrent mutation.
The inspector then compares reconstructed summaries with the saved report.
Missing, extra, altered or raced artifacts fail closed.

The SQLite evidence rows contain a stored SHA-256 **claim**, not the original
evidence payload bytes. The inspector can verify the digest's representation
and record lineage, but cannot independently recompute the digest against
unavailable payloads or prove the original scoring findings. A successful
result is limited to persisted offline storage consistency; it never acts as
an attestation, a review approval, or permission to scan.

Only fixed capability names, evidence counts and record digests are printed.
A successful inspection reports storage consistency of **the saved synthetic
lab evaluations**, never scan permission, true vulnerability, external source
trust, client approval, deployment readiness or current real-world status.
A failed inspection emits a fixed-shape error with exit code 2 and no private
paths, record contents or evidence payloads. Inspect only after the scorer
process has finished; the command does not open a live writer or accept a
target address.

## Compare two saved fixed-loopback calibrations (offline)

Use two **independently produced** score run directories:

    PYTHONPATH=src python -m lightup.lab_score_compare --baseline-dir ./lab-score-run-001 --candidate-dir ./lab-score-run-002

The installed equivalent is `lightup-lab-score-compare`. Each finished run is
re-admitted through the same owner-private descriptor-pinned, no-follow SQLite
and evidence verification as `lightup-lab-score-inspect`. The comparator
does **not** start fixtures/workers, access network targets, write artifacts,
or grant execution authority.

A readable local-operator report is available with `--format text` on the
same `lightup-lab-score-compare` command. The existing JSON response stays
the default. Text identifies PASS/HOLD, distinct versus reused evaluations,
per-capability evidence counts, and exact changes to allowlisted metrics.
Private source paths, record identifiers, payloads and hashes are excluded.
Both formats return exit code 2 for drift or reused evaluations. In text mode
a rejected or corrupt saved source emits a generic HOLD on stderr, not a raw
exception or private path; the existing JSON error shape is unchanged. This is
synthetic fixed-loopback calibration, **not** review, consent, or authority.

The output compares nine bounded first-party scoring metrics for service,
TLS and HTTP, excludes timing jitter, and flags exact evaluation-digest reuse.
A copied bundle or same directory is not an independent repeat, so returns
exit code 2. A drift in one of the fixed calibration metrics likewise returns
exit 2; clean independent repeats exit 0. Outputs contain no run IDs,
evidence payloads or user-supplied paths. Successful comparison establishes
only local storage consistency and stable synthetic calibrations, **not**
authenticated provenance, current vulnerabilities or permission to scan.
The comparator requests validated numeric metrics internally; the established inspector v1 CLI JSON shape remains unchanged.

## Safety boundary

All targets are fixed by the individual scorers to loopback fixtures; the suite accepts no target argument and does not add any network, model-provider or authorization path. It does not issue grants, dispatch workers, run remediation/retests, authorize real assets or deploy. Exit status `0` means the three local calibration contracts passed. It is **not** proof of external authorization, trusted origin, production readiness or permission to contact a real target.

Treat the output directory as local evidence storage. The SQLite databases are deliberately retained so the evaluation records remain inspectable; remove the directory only when its evidence is no longer needed.

## One-command repeat calibration (synthetic localhost only)

`lightup-lab-score-calibrate --output-dir ./new-private-calibration`
creates a fresh 0700 parent plus two separate 0700 saved-run directories
(`baseline/` and `candidate/`), each with four 0600 reports/evidence stores.
After both saves are independently inspected, a private 0600 root `report.json`
receipt is published atomically without overwrite. This stores the bounded,
non-authorizing score comparison and SHA-256 digests of the eight saved
source files; digest values remain solely in the private persisted receipt,
not the operator text or JSON output. They bind the calibration to exact
saved bytes, but are **not** source authentication or a signed attestation.
It then *reopens and verifies* both stored results with the existing
pinned/immutable read-only inspector and compares the nine first-party
metrics. The final default private-safe text report contains verified
PASS/HOLD, evidence counts and score differences without source paths,
run IDs, record hashes or evidence content. Use `--format json` for
structured non-authorizing output; the legacy score-suite and comparator
interfaces are unchanged.

For read-only follow-up on saved baseline and candidate evidence, use
`lightup-lab-score-calibrate --verify-output-dir ./existing-private-calibration`.
This option never starts scorers or changes saved files, checks the owner-private
root, exact two saved-run children and one owner-only root receipt without
following symlinks. Relative paths for the comparator and saved-calibration
verifier are anchored before opening evidence, and the comparator captures
the working directory *once for both saved runs*; another thread changing
the process working directory cannot redirect the second inspection to a
different private calibration. It reuses the pinned read-only artifact inspector and
recomputes the result plus every source-file SHA-256, requiring an exact
canonical-byte match against the root receipt. A missing, symlinked, extra,
replaced, modified or non-private saved
entry or altered receipt causes generic HOLD; the receipt cannot authorize
real-world actions or prove original evidence authenticity.
`--output-dir` and `--verify-output-dir` are mutually exclusive.

Any failed scorer, bad stored evidence, alias, score drift or pre-existing
output directory yields exit 2 rather than a false PASS. Existing files
are never overwritten; partial first-party data is retained privately for
local diagnosis but is **not** a successful calibration. Inputs are the
output directory only: no target address, client scope, scan, external
request, grant, dispatch, remediation or release is accepted. This is
synthetic local calibration, not authorization or independent review.

## Compare two saved calibrations across sessions (offline)

`lightup-lab-score-calibrate --compare-calibrations PREVIOUS_PRIVATE_DIR CURRENT_PRIVATE_DIR`

The command verifies both saved calibration roots, including their private
source-file SHA-256 receipts, *before* comparing candidate observations.
It snapshots all eight original source digests before the comparison and
checks the same bytes and both private receipts again afterward. Any
persistent source drift returns a path-free HOLD; unchanged root metadata
or receipt inode alone does not establish source consistency.
The output is a bounded text PASS/HOLD summary by default or private-safe
JSON with `--format json`. No source paths, run IDs, evidence payloads,
signatures, or private digests are emitted. Reused/copy-pasted evaluations
are HOLD even with identical score metrics, including a copied *baseline*
hidden inside an otherwise independently valid current archive. All eight
source-file SHA-256 bindings from the previous archive are checked against
all eight from the current archive, without returning private hashes.
Missing, corrupted or replaced saved roots are also refused. The archive roots are opened read-only
and checked for substitution during the comparison; no scorers, workers,
model providers, network targets, approvals, or deployments are invoked.
This only compares first-party fixed 127.0.0.1 lab calibration results.


## Multi-session calibration history (offline localhost)

`lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 [ARCHIVE3 ... ARCHIVE8]`

Compares 2–8 private, independently saved calibration roots in order.
All archive pairs are checked, not only adjacent runs: replaying original
evidence from session 1 in session 3 returns HOLD even if adjacent
comparisons pass. Each of the eight original file bindings in each
archive is independently reverified before and after the history.
JSON and text output contain only indices, anonymous counts and
PASS/HOLD statuses. A bounded pairwise HOLD list also identifies the
archive positions and safe reason flags (reused source or metric drift),
including non-adjacent replay that adjacent statuses would miss. For drift,
the operator also gets before/after values for only the fixed allowlisted
first-party capability and score metric fields: no arbitrary source keys are
copied into JSON or text. No evidence payload, source path, checksum or run ID
leaves the private directory.
Each of the 2–8 original archives and its eight private SHA-256 source
bindings is verified once at admission and once again at completion; pairwise
comparison reuses the admitted private snapshots rather than repeatedly
rehashing them. Validation cost for original sources now scales linearly
with archived sessions, not 28 repeated original verifications. Each
already-verified candidate SQLite observation is also inspected only once,
not reloaded for each of the 28 candidate comparisons. All-pairs results
retain the original independent per-pair scoring semantics; the post-pass
source binding and private receipt checks reject changed evidence or
swapped roots before writing any CSV.
When an original archive fails admission or final read-only verification,
text/CSV stderr identifies its 1-based argument position only; JSON
returns the same `archive_index` and a false `passed` value. No user path,
source digest, exception text, raw evidence or partial CSV is exposed.
This is not real target, scanning, approval or deployment authority.


### Spreadsheet-ready history comparison

Use `--format csv` with `--compare-history` to export a single offline,
headered CSV containing every bounded archive pair (including non-adjacent
successful comparisons). Columns include only 1-based archive positions,
PASS/HOLD, distinctness, score stability and allowlisted first-party metric
changes when available. No identifiers, private paths, original evidence,
digests, arbitrary source keys or active assessment permissions. A checked
but failing comparison still prints bounded CSV and exits 2; invalid input
prints a generic HOLD on stderr and does not emit a partial CSV.


### Completely offline visual history review

Use `lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2
[ARCHIVE3 ... ARCHIVE8] --format html > private-review.html` to create a
standalone browser-readable all-pairs matrix. The page includes a clear
PASS/HOLD overview, accessible table captions and row/column headings,
and anchored details for every failed pair, including non-adjacent replay
and allowlisted first-party score deltas. This is generated from the
already-verified original sources, not a replay of worker tasks. It uses
no scripts, external fonts, images, network requests, target identifiers,
private paths, evidence digests or credential data. Inline styles and an
offline Content-Security-Policy prevent loading external assets.
An invalid archived input produces only a private-safe stderr HOLD and
no partial HTML. Open the file locally; do not publish its contents or
misinterpret synthetic PASS as permission to assess real assets.


### Private atomic HTML publication

To keep a reviewed synthetic HTML report on disk without shell redirection
or overwriting an existing file, use:

```bash
lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 --format html --html-output-dir NEW_PRIVATE_REVIEW
```

The original archives are fully reverified before a new private destination
directory is created. The output is `NEW_PRIVATE_REVIEW/history.html`
inside a new owner-only 0700 directory; the atomically published HTML
has mode 0600 and will never overwrite an existing report. After publishing,
LightUp reopens all three saved files through its pinned private directory and
compares exact bytes and inodes to the verified source. Tampering at
publication returns HOLD and removes the changed review. A 0600 `review_summary.json` provides a machine-readable, index-only
triage summary: pair PASS/HOLD flags, anonymous archive-review queue and
first-party capability hotspot counts. It never contains original receipt
hashes, source paths or untrusted metric values. A third 0600
`source_receipt.json` privately binds both the HTML and JSON digests to
SHA-256 digests of the exact original archived receipts. Neither private receipt hashes nor
original source paths appear in HTML or stdout; this is not a digital
signature. Symlinked
ancestors and parent traversal are refused. Corrupted originals produce
a source-safe HOLD and create no report. Valid but nonindependent original
archives create a private HOLD review and exit 2; the report remains
purely offline and contains no original evidence or live authorization.
`--format html` without this option continues to print on stdout
for legacy uses.


### Source-free machine-readable summary on stdout

For an offline read-only dashboard that needs the validated private summary but
must not create a review directory, use:

```bash
lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 --format review-json
```

The command re-verifies each original synthetic archive and prints the exact
index-only schema saved in `review_summary.json`. A genuine historical HOLD
prints `passed: false` with exit 2; corrupt originals produce only a generic
JSON refusal on stderr and no partial stdout. No private source/receipt hashes,
paths, raw score values or external authorizations are exposed. This is not a
substitute for `--verify-html-output-dir`, which additionally checks all three
0600 private artifacts against their original receipt bindings.


### Human operator handoff, without original evidence disclosure

`lightup-lab-score-calibrate --compare-history ARCHIVE1 ARCHIVE2 --format review-markdown`
re-verifies the original private localhost archives and prints an offline Markdown
review brief: prioritized anonymous archive HOLD counts, evidence-reuse/drift,
fixed scorer hotspots and every pairwise status. Genuine HOLD is reviewable
with exit 2; corrupt originals yield no partial output, just a source-free
refusal on stderr. To export only after independently re-verifying the original private
three-file review bundle, add `--verify-html-output-dir PRIVATE_REVIEW_DIR`
to `--format review-markdown`, `--format review-json` or `--format review-csv`.
This verifies the stored HTML, JSON summary, source-bound receipt and every
original private archive before emitting any stdout. A tampered report or
altered archive yields a source-free HOLD/exit 2 and no partial export.
The existing saved review directory remains unchanged.

There is no write, authenticated chronology, authorization,
external target, scanning, consent, dispatch or deployment capability.

### Read-only verification of a previously saved review

Use the same original private archived calibration inputs and
`--compare-history ARCHIVE1 ARCHIVE2 ... --format html
--verify-html-output-dir PRIVATE_REVIEW_DIRECTORY`. The CLI rebuilds the
safe HTML from freshly reverified original localhost evidence, opens the
saved 0600 `history.html`, `review_summary.json` and `source_receipt.json` read-only through
private pinned directories, and verifies **exact bytes**, source binding,
expected modes and unchanged inodes. Two unrelated sets of original archives
with identical PASS/HOLD scores cannot verify each other's review. A valid
stored PASS (or genuine stored HOLD) prints a path-free `VERIFIED`
result, and returns the original comparison status (0 for PASS, 2 for
HOLD). A modified saved report, symlink, extra private artifact or
changed original archive emits generic HOLD without output and without
rewriting the original inputs or review. This is reproduction of local
synthetic evidence, not a public signature or real assessment authority.


### Never write inside original evidence

The private HTML output directory must not be inside, equal to, or an
ancestor of any original archived calibration directory. The check happens
before any output directory is created: placing the report inside an
original `baseline` or `candidate` tree would otherwise mutate verified
source evidence and falsely report success. Both save and read-only
reverification reject overlap with a generic HOLD. Use a separate owner-only
report directory alongside, not underneath, the archived originals.


### Final original-evidence check during publication

Before declaring a saved three-file private review successful, LightUp reopens
and revalidates the *same original* archived calibration receipts after both
private HTML, source-free summary and source-binding artifacts have been saved. If an original
source changes or is replaced while the review is being published, both
newly linked report files are cleaned up and the command returns a
path-free HOLD. This prevents a falsely verified PASS caused by changing
source evidence between the initial comparison and final report write.
The same no-overwrite, exact-byte and original-source revalidation applies
to the machine-readable summary: deleting or modifying it causes generic HOLD.

### Source-free CSV for lab handoff

`--compare-history ARCHIVE1 ARCHIVE2 [ARCHIVE3 ...] --format review-csv` prints only anonymous archive ordinals, PASS/HOLD, original-evidence-independence and score-stability booleans. It deliberately omits original metric scores, hashes, source identities and paths. Add `--verify-html-output-dir PRIVATE_REVIEW_DIR` to require a valid source-bound HTML/JSON/receipt package before any CSV output. Tamper yields HOLD with no partial output; no external access or authorization.
