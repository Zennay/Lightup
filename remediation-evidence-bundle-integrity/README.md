# LightUp — PRIVATE Evidence Bundle Integrity & Handoff Desk

**INCUBATE · M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD**. This is a new, independently owned, read-only companion for the existing [Evidence Relationship Desk draft #1660](https://github.com/Zennay/Lightup/pull/1660), stacked on that exact existing draft without changing its source-owner files or any other parallel PR.

## What is usable now

The original one-command `remediation-evidence-reuse/desk.py workspace` produces one owner-private snapshot directory with original `current.json`, optional `previous.json`, the complete HUMAN `session.json`, the private static browser pages, `questions.json`, `counts.json`, and a SHA-256 `manifest.json`. A copied or edited folder may no longer correspond to the original snapshot. **This tool admits the complete folder atomically for a LOCAL read-only human check** before it is handed to the original operator. No single-file cherry-picking or partial success.

The verifier requires a real owner-private `0700` directory and `0600` regular single-link files; it refuses symlinks, extra/missing objects, unlisted contents, duplicate JSON property keys, unexpected manifest claims, ambiguous original schema, forged authority booleans, oversized artifacts, incomplete/renumbered HUMAN action rows, changed original source digests, and altered JSON/counts. It verifies every manifest-declared filename, exact bytes and SHA-256, checks the original ledger v1/unified HUMAN v2 packet with existing source-owner-pinned parsers, reruns the exact HUMAN proposal/session admission and independently recalculates the private `questions.json` and anonymous `counts.json`. Finally it rereads files before publishing to reduce stale local reports. No network/active target/subprocess or database path exists.

The readable output is a **new standalone CSP-locked, no-script, owner-private HTML brief** containing only aggregate local counts and local HUMAN stage totals — not file names, paths, source/client IDs, SHA digests, plaintext evidence, free-text HUMAN notes or per-finding identities. The verifier also prints a minimal counts-only local console summary. Original files are never rewritten.

## Operator workflow

On a trusted local Linux machine with the original branch code installed, produce the original PRIVATE directory using its existing instructions:

```sh
install -d -m 700 "$HOME/lightup-private"
python3 remediation-evidence-reuse/desk.py workspace \
  --current "$HOME/lightup-private/ledger-current.json" \
  --output-dir "$HOME/lightup-private/desk-001"
```

Make a **separate, existing owner-only 0700 directory** for the newly published report. Then inspect the original directory *without modifying it*:

```sh
install -d -m 700 "$HOME/lightup-private/receipts"
python3 remediation-evidence-bundle-integrity/verify.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --report "$HOME/lightup-private/receipts/desk-001-integrity.html"
```

**Exit 2** is intentional `REVIEW_ONLY`: local byte/source/HUMAN consistency admitted, never an approval or security verdict. **Exit 3** means `HOLD`, and no report is produced. `--report` is optional for a console-only inspection. A report name must be unused. The verifier cannot write inside the original bundle; the original directory may remain immutable. Open the HTML locally only, not on a web server.

Private exports must never enter public GitHub PRs, Notion pages, third-party tools or CI artifacts. If any byte fails, re-export from the original trusted source; do not patch `manifest.json` to force a local match. A manifest is **not signed**, a locally modified manifest and contents can agree, and private SHA hashes cannot authenticate who produced the original packet or prove the evidence file bytes exist. Source reference, original owner, client or engagement labels and HUMAN notes are self-declared; this is solely a local *internal-consistency* assistant.

## Scope and release

No modifications to `src/`, original Evidence Artifact Ledger, Request Desk, native Apply, auth, scanner, scope, evidence files, CI or QA suites. Never feeds data to targets, issues grants, stages client action, changes HUMAN journals, concludes remediation or bypasses action-time revocation. As with the parent draft, **no main merge, production deploy or live use** until existing original exact-head hosted + permanently registered named VPS CI, original source-owner and independent security/privacy/browser/crypto reviews, #177/#182/#829, true independent revocable current client/operator consent and explicit HUMAN GO have all been satisfied. No new release gate is created by this utility.
