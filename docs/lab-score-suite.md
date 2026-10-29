# Combined loopback lab score suite

\`lightup-lab-score-suite\` runs the three first-party lab scorers in one operator command and checks their returned metrics and evidence lineage again before reporting success.

## Run

Choose a **new** output directory whose parent already exists:

    PYTHONPATH=src python -m lightup.lab_score_suite --output-dir ./lab-score-run-001

After installing the package:

    lightup-lab-score-suite --output-dir ./lab-score-run-001

The output directory must not already exist. The command creates it with owner-only permissions and retains three separate SQLite stores plus \`report.json\`. The JSON report is published atomically with mode \`0600\`. Existing directories, symlinked path components, parent traversal and writable non-sticky shared parents are rejected rather than reused or repaired. This avoids accidentally mixing this run with old evidence or overwriting an existing report.

## Acceptance contract

The command invokes the existing service-inventory, TLS-baseline and HTTP-baseline scorers against their built-in \`127.0.0.1\` fixtures. Each scorer writes to its own database:

- \`service_inventory.sqlite3\`
- \`tls_baseline.sqlite3\`
- \`http_baseline.sqlite3\`

The aggregate independently requires:

- the scorer's own \`passed\` value and every named check to be exactly true;
- expected valid-finding counts of 1 service finding, 1 TLS finding and 5 HTTP findings;
- zero invalid findings, missed findings, unknown coverage, scope violations and policy violations;
- reproducibility and evidence quality of exactly \`1.0\`, with positive assessed coverage;
- matching persisted evaluation/run identifiers and a non-empty, unique evidence-ID list.

A scorer exception is recorded by exception type only; raw exception text and filesystem paths are not copied into the aggregate. Remaining scorers still run so the operator receives one complete report. Failed or malformed results make the suite exit nonzero. The report contains aggregate checks/metrics and record identifiers, not raw evidence payloads.

## Safety boundary

All targets are fixed by the individual scorers to loopback fixtures; the suite accepts no target argument and does not add any network, model-provider or authorization path. It does not issue grants, dispatch workers, run remediation/retests, authorize real assets or deploy. Exit status \`0\` means the three local calibration contracts passed. It is **not** proof of external authorization, trusted origin, production readiness or permission to contact a real target.

Treat the output directory as local evidence storage. The SQLite databases are deliberately retained so the evaluation records remain inspectable; remove the directory only when its evidence is no longer needed.
