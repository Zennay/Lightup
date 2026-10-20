# LightUp integrated PRIVATE assessment handoff

**Incubate M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is an integrated **source-only release candidate**, not an authorization, active scanner, security finding certification or production deploy.

## What is really integrated

This branch carries the original held lab inspector/CLI from #1610, original PRIVATE briefing from #1672, select-only evidence dossiers from #1679, HUMAN retention desk from #1683 and source-minimal disclosure reviewer from #1685. Each original contributor branch remains unchanged. The new suite under this directory **uses** the original native lab inspector and briefing/disclosure producers; it does not duplicate their validators or collect evidence.

The operator can take **already-produced** original PRIVATE lab JSON, generate both original-source-admitted PRIVATE disclosure review and optional detailed finding-level PRIVATE briefing with **one command**, and receive an offline entry page linking the original generated artifacts plus **three actual existing offline HUMAN browser workrooms**. This joins previously isolated product capabilities without scanning.

## Run completely locally in a trusted checkout

Prepare a separate, empty or existing **owner-owned mode 0700** parent folder *outside the repository*. Never use a repository or a public web root for customer data.

~~~sh
install -d -m 700 /path/to/PRIVATE-only-parent
python3 assessment-integrated-suite/suite.py catalog

# PRIVATE disclosure for one or more already-produced original lab artifacts
python3 assessment-integrated-suite/suite.py prepare \
  --source /private/original-lab-a.json \
  --source /private/original-lab-b.json \
  --private-parent /path/to/PRIVATE-only-parent

# Also include the original detailed PRIVATE findings briefing and its worksheet
python3 assessment-integrated-suite/suite.py prepare \
  --source /private/original-lab-a.json \
  --private-parent /path/to/PRIVATE-only-parent \
  --brief
~~~

**Return code 2 means REVIEW_ONLY product was prepared**, not an error requiring retry and not a PASS signal. **Return code 3 means HOLD** and normal failed preparations remove their own newly created private output tree. Sources must each be non-symlink local files of 1–8 MiB; at most 12 unique source files. Optional `--brief` applies only to the first source and requires original briefing's strict source contract. Do not send live targets or arbitrary URLs to the launcher.

On success, the CLI prints a unique local `PRIVATE-lightup-kit-*/OPEN-PRIVATE.html` path. Open that file locally in a trusted offline browser; do not serve through HTTP. The CSP-protected scriptless entry page links:
- Original **PRIVATE** detailed findings briefing, original HUMAN worksheet and unsigned manifest (when `--brief` selected).
- Original **PRIVATE** disclosure review, source-minimized unsigned receipt and small-cohort-suppressed PRIVATE counts.
- The previously committed, completely offline **HUMAN disclosure, retention and worksheet** studios (worksheet with `--brief`). They remain independent source-bound HUMAN-only UIs.

For select-only dossiers, use the physically integrated original `assessment-evidence-curation/console.py` after the original detailed briefing and worksheet are available. This new suite intentionally does not duplicate or reinterpret original source-declaration matching, HUMAN admission, AES-GCM decryption, or original result classification.

## Privacy / integrity behavior

- Runs only the two **fixed, original local file-only producers** with argument-vector subprocesses; no shell, host resolution or arbitrary script target.
- Uses the original `lightup.lab_inspect.inspect_artifact()` as required by disclosure. Missing/invalid original inspector is HOLD; there is no fallback decoder.
- Insists on an existing owner-controlled no-group/no-other directory **outside the repository**; creates unique mode 0700 private output and mode 0600 copied workrooms/entry page.
- Source bytes are **not copied** into the package; the detailed briefing deliberately includes original PRIVATE finding details, and resulting HTML/receipts/counted cohorts should all be treated as PRIVATE.
- An incomplete normal preparation removes only its newly created package. Unexpected process termination can leave a PRIVATE incomplete 0700 directory, which must be reviewed and securely handled by its custodian. The package does **not** delete or modify original source.
- No browser is opened automatically, no external handoff/publish is performed, no model or tool execution, scanning, grant creation, assessment request, retest or deletions.

## Release and authority gates

No merge to `main`, runtime deployment or real target activity. Original exact-head GitHub-hosted and **permanently registered named VPS CI**, source-owner approval, independent security/privacy/browser review, #177/#182/#829 remediation, separate **current authenticated client and operator consent**, action-time revocation, and explicit **HUMAN GO** remain prerequisites. This integration branch is DRAFT/HOLD even if it has no source conflicts. Original PR branches may continue advancing; this candidate refers to the frozen source heads recorded in its merge commits, not their future work. No QA/regression suites were written or executed for this integration.
