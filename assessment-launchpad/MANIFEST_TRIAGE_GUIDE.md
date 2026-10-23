# Source-bound PRIVATE HUMAN manifest-change triage

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an offline follow-up view on the **original** LightUp Launchpad's saved manifest-change desk, not a scanner, authorization, consent tool, or source approval.

## Complete native operator workflow

First, use the original \`combine_manifest.py\` to create two separate saved, policy-admitted owner-private (0700) manifest bundles. Preserve each original intact. Use \`manifest_change_desk.py --before-dir BEFORE --after-dir AFTER --output-dir DELTA\` to generate the **original** canonical source-bound PRIVATE delta. Then create an independent empty owner-private 0700 folder for HUMAN triage:

\`\`\`bash
mkdir -m 700 PRIVATE-TRIAGE
python3 assessment-launchpad/manifest_ordinal_triage.py \
  --before-dir PRIVATE-BEFORE --after-dir PRIVATE-AFTER \
  --delta-dir PRIVATE-DELTA --output-dir PRIVATE-TRIAGE
\`\`\`

Open the generated \`PRIVATE-TRIAGE/lightup-private-manifest-human-triage.html\` locally. It contains HUMAN attention rows prioritizing removed original ordinals, newly added, moved, then unchanged. The original row number and source-position pair are retained, never endpoint values. The adjacent CSV is ordinal-only for separate manual HUMAN coordination; it never contains client, URL, endpoint, path, source notes, or authenticated approvals.

Reopen the packet against **all unchanged original source bytes and original delta** without writes:

\`\`\`bash
python3 assessment-launchpad/manifest_ordinal_triage.py \
  --before-dir PRIVATE-BEFORE --after-dir PRIVATE-AFTER \
  --delta-dir PRIVATE-DELTA --verify-output-dir PRIVATE-TRIAGE
\`\`\`

The CLI re-admits all ORIGINAL source bundles and canonical delta before publish or reopen; any source change, unknown/duplicate receipt field, malformed original JSON, missing/additional output, mismatched row or digest, non-private output, symlink, hardlink or source/output overlap becomes HOLD. All output files are 0600, no replacement, within a separate user-owned 0700 directory. The HTML has a strict scriptless, network-denied CSP. No executable preview command, model request, DNS, target contact or consent path is exposed.

This unsigned source byte comparison is **not** source authenticity, approved assessment, remediation, credential exposure approval, scanner readiness, proof of consent or permission. Original source owners, independent security/privacy/browser reviews, original hosted and named permanent VPS CI, #177/#182/#829, separately authenticated current client/operator consent with revocation at use and explicit HUMAN GO remain required. The PR stays DRAFT/HOLD until its actual gates pass.
