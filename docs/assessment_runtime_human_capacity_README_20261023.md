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
- `capacity-summary.csv`: spreadsheet-ready counts by source priority, HUMAN stage and routing group, open load per date/route, and open counts by source priority/date/route; it also includes the declared hypothetical capacity and explicit overdue totals when a reference date is supplied;
- `capacity.json`: the same rows and aggregate stage/priority/routing totals plus dated open work loads;
- `manifest.json`: schema-v2 unsigned SHA-256 byte checks for all four data/report outputs and permanently false authorization flags;
- `READ-ME.txt`: explicit privacy and no-authority instructions.

The source comparison status stays **HOLD** if any input is HOLD. A manually marked `reviewed` row is not open planning load, **but never becomes a finding fix or approval**. A repeated source comparison (including a separately edited HUMAN revision of the same original review) is rejected rather than double-counted. Packet ordinals express command-line input order, not authenticated chronology, and capacities are hypothetical user-provided rows per date/route rather than real staffing, assignments, deadlines or security decisions.

To inspect counts **without creating an output directory or files**, omit `--output` and use `--preview-only` with the same input options. Preview prints only aggregate packet/open/reviewed/undated counts, source-priority open counts, route/date group and over-capacity counts, overdue count (or `not-computed`) and status; it never prints source identifiers or writes files. To get overdue counts, an operator must supply a literal ISO reference day; no clock is consulted.

## Fail-closed and privacy boundary

Sources must be existing single-link, owner-only regular files with no symlink path components and stable bytes across bounded reads. The original existing PR #1617 source inspector rechecks the **same accepted ZIP bytes**, complete member inventory, original result and saved HUMAN plan bound to the original comparison. Each distinct original comparison is counted once. Invalid archives, replays, source mutations, unknown stages, oversized contents or attempted overwrite produce generic HOLD and no output. The companion does not read directories opportunistically or discover inputs via globs.

All output remains PRIVATE: aggregated counts and dates can be sensitive even without source hashes, target names, original scenario identities, credentials, evidence, or HUMAN notes. The read-only reopen checker validates the six-member bundle's fixed layout, exact output fingerprints, source-free canonical rows and aggregate accounting, including the canonical aggregate CSV. These are **unsigned local integrity checks, not source authentication**.

Valid REVIEW_ONLY returns exit code **2**; valid upstream HOLD remains exit code **3** with an explicit HOLD marker. Invalid packets also return 3, without disclosing source content. Neither a successful preview, an intact re-opened artifact nor a human stage permits a scan, a grant, consent, dispatch, remediation verification, release or deployment.

## Integration and release

This is new-only assessment-runtime companion code. It does **not** change original comparison logic, source-owner scanner/runtime, domain authorization, portal/tenancy, existing CI, quality suites or other active work. The existing #1515 parent and independent security/privacy reviews remain prerequisites. Keep **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD** until exact-head hosted/permanent named VPS CI, source-owner acceptance, independent security/privacy review, real separately authenticated client and operator authorization with action-time revocation, and explicit HUMAN GO all pass. No QA suite is added or executed by these scripts.

## PRIVATE capacity aggregate delta — two original existing bundles

The new [offline comparison CLI](../scripts/assessment_runtime_human_capacity_delta_cli_20261023.py) consumes two **existing, fully admitted** six-member HUMAN capacity ZIPs (not source-rich review or assessment files). It independently reuses the exact original admission and source-free accounting from the existing capacity inspector, then produces only aggregate differences by fixed HUMAN stage/priority/route and declared date/route load. Input order is **manually nominated, not authenticated chronology**. Different source case membership is not knowable from anonymized capacity packets; a numerical change can never establish completion, remediation, client permission, security improvement or staff availability.

```bash
PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_delta_cli_20261023.py \
  --earlier /private/CAPACITY-A.zip --later /private/CAPACITY-B.zip \
  --preview-only

PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_delta_cli_20261023.py \
  --earlier /private/CAPACITY-A.zip --later /private/CAPACITY-B.zip \
  --output /private/NEW-PRIVATE-capacity-delta.zip

PYTHONPATH=src:scripts python scripts/assessment_runtime_human_capacity_delta_cli_20261023.py \
  --inspect /private/NEW-PRIVATE-capacity-delta.zip
```

The output is a five-member private no-overwrite ZIP containing an unsigned canonical `delta.json`, source-free aggregate `delta.csv`, scriptless `delta.html`, SHA-256 member manifest and operator guidance. No case/packet IDs, source digests, original targets, original finding details, dates of the source files, private HUMAN free-text notes or identities are emitted. A literal date/route count and small cohort remain PRIVATE and may still be sensitive. If reference dates or hypothetical capacity differ, the report explicitly refuses to infer comparable overdue or overload changes. Explicit source comparison HOLD propagates. The read-only inspector rejects altered members or authority flags; source SHA-256 verification is not source-person authentication. No QA suites, scanner, network, grant, authenticated consent, release or deployment are added.


### Aggregate integrity limits

The companion inspector verifies fixed dimension order, canonical ISO dates, literal-false authority, every count-change arithmetic identity, and independently reconciles all HUMAN stage, route, priority and date/route totals with original snapshot-wide row totals. The source-free report still cannot prove that the earlier and later source populations are identical, who supplied them, whether chronology is true, or whether a changed count means a verified remediation.
