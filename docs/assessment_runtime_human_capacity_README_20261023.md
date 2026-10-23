# LightUp PRIVATE HUMAN capacity board — assessment-runtime

This **offline, non-authorizing** companion extends [existing PR #1617](https://github.com/Zennay/Lightup/pull/1617). It accepts 2–8 separate, already-completed and source-bound **ten-member annotated PRIVATE review ZIPs** produced by `assessment_runtime_attach_triage_cli_20261018.py`. It does not accept source-rich raw assessment outputs, standalone briefing ZIPs, a browser-only saved JSON file, or the four-member minimized recipient packet.

## Product workflow

From a checkout containing the unchanged original review-handoff modules:

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_cli_20261023.py \\
  /private/review-01.zip /private/review-02.zip \\
  --capacity-per-group 4 --reference-date 2026-10-23 \\
  --output /private/NEW-human-capacity.zip

PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_inspect_cli_20261023.py \\
  /private/NEW-human-capacity.zip
```

The result is one new owner-only PRIVATE ZIP with:

- `capacity.html`: local script-free printable planning page, no network access; includes source-priority, HUMAN-stage and route distributions, date/route load and an explicit overdue summary (or states that overdue was not computed);
- `capacity.csv`: all anonymous original packet/case ordinals, HUMAN stage, routing group, follow-up date, priority and source-reported regression count;
- `capacity.json`: the same rows and aggregate stage/priority/routing totals plus dated open work loads;
- `manifest.json`: unsigned SHA-256 byte checks for the three outputs and permanently false authorization flags;
- `READ-ME.txt`: explicit privacy and no-authority instructions.

The source comparison status stays **HOLD** if any input is HOLD. A manually marked `reviewed` row is not open planning load, **but never becomes a finding fix or approval**. A repeated source comparison (including a separately edited HUMAN revision of the same original review) is rejected rather than double-counted. Packet ordinals express command-line input order, not authenticated chronology, and capacities are hypothetical user-provided rows per date/route rather than real staffing, assignments, deadlines or security decisions.

To inspect counts **without creating an output directory or files**, omit `--output` and use `--preview-only` with the same input options. Preview prints only aggregate packet/open/reviewed/undated counts and status. To get overdue counts, an operator must supply a literal ISO reference day; no clock is consulted.

## Fail-closed and privacy boundary

Sources must be existing single-link, owner-only regular files with no symlink path components and stable bytes across bounded reads. The original existing PR #1617 source inspector rechecks the **same accepted ZIP bytes**, complete member inventory, original result and saved HUMAN plan bound to the original comparison. Each distinct original comparison is counted once. Invalid archives, replays, source mutations, unknown stages, oversized contents or attempted overwrite produce generic HOLD and no output. The companion does not read directories opportunistically or discover inputs via globs.

All output remains PRIVATE: aggregated counts and dates can be sensitive even without source hashes, target names, original scenario identities, credentials, evidence, or HUMAN notes. The read-only reopen checker validates the bundle's fixed layout, exact output fingerprints, source-free canonical rows and aggregate accounting. These are **unsigned local integrity checks, not source authentication**.

Valid REVIEW_ONLY returns exit code **2**; valid upstream HOLD remains exit code **3** with an explicit HOLD marker. Invalid packets also return 3, without disclosing source content. Neither a successful preview, an intact re-opened artifact nor a human stage permits a scan, a grant, consent, dispatch, remediation verification, release or deployment.

## Integration and release

This is new-only assessment-runtime companion code. It does **not** change original comparison logic, source-owner scanner/runtime, domain authorization, portal/tenancy, existing CI, quality suites or other active work. The existing #1515 parent and independent security/privacy reviews remain prerequisites. Keep **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD** until exact-head hosted/permanent named VPS CI, source-owner acceptance, independent security/privacy review, real separately authenticated client and operator authorization with action-time revocation, and explicit HUMAN GO all pass. No QA suite is added or executed by these scripts.