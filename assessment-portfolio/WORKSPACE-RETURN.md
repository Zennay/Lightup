# Original workspace → complete human-only return

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD · NO GO.**

The existing `one_command.py` builds a **private offline portfolio ZIP** from the original archive manifests and human choices. After using `original-human-review-studio.html` inside the ZIP, the human operator can now return source-bound proposals **without extracting original agendas or retyping their hashes**.

Run with exactly the same original manifest/choices order that created the workspace:

```sh
python3 assessment-portfolio/workspace_return.py \
  --workspace /private/ORIGINAL-human-workspace.zip \
  --original-manifest /private/ORIGINAL-A.json \
  --original-manifest /private/ORIGINAL-B.json \
  --original-choices /private/CHOICES-A.json \
  --original-choices /private/CHOICES-B.json \
  --proposal /private/HUMAN-proposal-A.json \
  --proposal /private/HUMAN-proposal-B.json \
  --output /private/NEW-human-return.zip
```

For 1–12 sources, the CLI reads the **unaltered original** manifest and previous choices; it does not accept the ZIP as a source of current authority or authenticity. For every source it binds the original manifest SHA, original choices SHA, original original-sourced human agenda SHA, complete human source slots and source state against the ZIP source map. It independently invokes the original `agenda.render_bytes` to regenerate the original agenda from those unchanged input files and requires **byte-identical** embedded agenda bytes. It then reuses the `proposal_return.reconcile` function in memory to validate the original human stage, neutral role, proposed review date, and full original membership against the private proposal. Original HOLD remains HOLD; any changed source, duplicate, malformed/oversize member, unknown archive layout or stale human proposal rejects the entire return.

The output is one new, non-overwritten owner-private **0600 ZIP** with `original-human-choices-01.json`, `original-human-choices-02.json`, etc., each in the exact original `lightup.archive_human_followup.v1` human-only choices schema. It also contains a scriptless local index, private source fingerprints and changed-human-slot counts. **No original files are edited**, no partial ZIP is published on failure, and no original evidence, finding records, client names, real targets, credentials or tools are imported or invoked. Importing the original returned choices into a later independent human session requires the trusted original owner to re-render the agenda and verify context; there is no automatic approval.

Security boundaries: canonical ZIP member whitelist, 16 MiB total/raw bound, stored entries only, duplicate member rejection, strict original JSON decoding and false-only permission flags. Original SHA-256 values are *unsigned byte correlations*, not signatures, evidence validation, user authentication, action permission, release consent or findings verification. Keep the workspace, original source files, proposals and return ZIP **confidential**. This is not a remediation/retest/scan, source update, client consent, grant, task dispatch or GO.

Exit 2 denotes a `REVIEW_ONLY` original human return; exit 3 denotes a `HOLD` source or rejected input, even if a correctly preserved original HOLD still produces a private return. Mandatory original hosted/named VPS CI, source-owner and independent privacy/security reviews, separate actual client/operator consent with action-time revocation, #177/#182/#829 integration and explicit HUMAN GO remain release prerequisites.
