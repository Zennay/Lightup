# HTTP baseline labeval

This command scores the existing HTTP security-header baseline worker against
explicit ground truth from two temporary loopback fixtures: one deliberately
weak response and one hardened negative control.

## Run

    PYTHONPATH=src python -m lightup.lab_web_score --db /tmp/lightup-web-score.db

After installing the package, the same fixed-loopback scorer is available as:

    lightup-lab-web-score --db /tmp/lightup-web-score.db

## What is scored

- Valid findings: all five hand-maintained missing-header/server-banner findings
  are detected on the weak fixture.
- Invalid findings: the worker emits no findings against the hardened control.
- Missed findings: none of the five expected weak-fixture findings are absent.
- Reproducibility: two observations of each fixture return the same finding set.
- Evidence quality: all four evidence rows have the expected worker, capability,
  kind, lab marker and run ID.
- Persistence: the canonical StateStore evaluation record is read back and its
  record/run/evidence IDs are matched to the producing run.

A successful run exits 0. Any ground-truth, control, repeatability, lineage or
persistence mismatch exits 2 and prints a structured result. The score record
contains aggregate metrics and evidence identifiers, not raw evidence payloads.

## Safety boundary

The command accepts no target or host override. Both HTTP servers bind only to
127.0.0.1 on operating-system-assigned ports, and both are shut down before the
command returns. The worker is registered in a fresh ToolRegistry and invoked
through ToolExecutor in a LabScenario/lab RunContext, preserving the normal
policy gate and worker-side lab-target validation. The weak fixture's expected
findings are maintained separately from the worker's check table.

No external network, model provider, grant, dispatch, real target, remediation
or deployment is involved. The score is a local calibration result, not proof
of external authorization or release readiness.
