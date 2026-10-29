# Lab service-inventory scoring

The `lightup-lab-service-score` command makes the existing TCP service-inventory capability measurable through the same lab evaluation and evidence-history path used by the HTTP baseline.

## Run

```bash
PYTHONPATH=src python -m lightup.lab_service_score --db /tmp/lightup-service-score.db
# After installing the package:
lightup-lab-service-score --db /tmp/lightup-service-score.db
```

The command creates its own fixture and has no target/host override. It binds one temporary TCP listener to `127.0.0.1`, allocates a currently closed loopback TCP port as a negative control, and asks the registered `lab-service-inventory` worker to inspect only those two ports. It performs the observation twice in the same lab run context.

## What is scored

- **Valid finding:** the known listener is reported open.
- **Invalid finding:** the supposedly closed control is reported open.
- **Missed finding:** the known listener is not reported open.
- **Reproducibility:** both observations report the same open-port set.
- **Evidence quality:** both evidence rows have the expected worker/capability/kind, are explicitly marked lab-only, and belong to the same run as the evaluation record.
- **Persistence:** the evaluation is read back through the canonical SHA-256 and evidence-lineage verifier after insertion.

The record is written to the SQLite database through `StateStore.add_lab_evaluation`; its two evidence IDs are retained on the score. A successful run exits 0. Any score/control/lineage mismatch exits 2 and prints a structured result.

## Safety boundary

The fixture binds only to IPv4 loopback. The target is hard-coded and not accepted from CLI arguments. The worker is registered in a fresh `ToolRegistry` and invoked through `ToolExecutor` in a `LabScenario`/lab `RunContext`, so the ordinary policy gate and worker-side lab-target validation both remain in force. No model provider, external network, real target, authorization grant, scan, or deployment is involved.

The closed-port control is checked immediately before the scan, but another local process could still claim that port in the small interval before observation; if so, the command reports an invalid finding rather than silently accepting the result.
