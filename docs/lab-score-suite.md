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
Both formats return exit code 2 for drift or reused evaluations. This is
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
