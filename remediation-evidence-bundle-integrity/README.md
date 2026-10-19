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

For a separate source-free local aggregate JSON instead of HTML:

```sh
python3 remediation-evidence-bundle-integrity/verify.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --counts "$HOME/lightup-private/receipts/desk-001-anonymous.json"
```

This second output includes only anonymous stage and open question-reason counts; no source IDs, file digests, paths, notes, or finding identities. The HTML now includes a plain-language HUMAN follow-up table by original proposed-question reason. One question may count under more than one reason. Both output options are intentionally mutually exclusive to avoid partial multi-output publication.

**Exit 2** is intentional `REVIEW_ONLY`: local byte/source/HUMAN consistency admitted, never an approval or security verdict. **Exit 3** means `HOLD`, and no report is produced. `--report` is optional for a console-only inspection. A report name must be unused. The verifier cannot write inside the original bundle; the original directory may remain immutable. Open the HTML locally only, not on a web server.

Private exports must never enter public GitHub PRs, Notion pages, third-party tools or CI artifacts. If any byte fails, re-export from the original trusted source; do not patch `manifest.json` to force a local match. A manifest is **not signed**, a locally modified manifest and contents can agree, and private SHA hashes cannot authenticate who produced the original packet or prove the evidence file bytes exist. Source reference, original owner, client or engagement labels and HUMAN notes are self-declared; this is solely a local *internal-consistency* assistant.

## Original-source PRIVATE HUMAN progression across complete workspaces

`progression.py` compares **2–12 already completed, independently admitted owner-private workspace directories**, with strict same-actual-original-PACKET-BYTES (both current and previous when present), exact original HUMAN proposal membership, no duplicated session bytes, and no claimed authenticated chronology. It never modifies the earlier workspace or interprets a disappearing evidence link as fixed.

```sh
python3 remediation-evidence-bundle-integrity/progression.py \
  --bundle "$HOME/lightup-private/desk-001" \
  --bundle "$HOME/lightup-private/desk-002" \
  --html "$HOME/lightup-private/receipts/private-historical-review.html"
```

Instead of `--html`, choose **only** `--counts /ABSOLUTE/NEW/ANONYMOUS.json` for an aggregate-only JSON. Both outputs contain ordered **slot numbers**, local stages, reopened HUMAN questions, locally answered questions, changed stages, and a count of notes that changed (never free text, original IDs, source hashes, individual fingerprint labels, or paths). The operation deliberately refuses duplicate identical HUMAN sessions; slot order is user-supplied **not authenticated time order**. Verify all source and HUMAN bytes again before publication. Unmatched original source/client, changed HUMAN proposed-question identity, or any invalid bundle results in complete HOLD and no output.

This is useful to hand over an offline readable status progression while keeping original report files and PRIVATE HUMAN notes on their own owner-controlled machine. Even an increase in locally answered questions says nothing about verified remediation, retesting, consent or actual authorization.

## Separate-source PRIVATE HUMAN portfolio board

`portfolio.py` now accepts 2–12 separately admitted, complete PRIVATE Evidence Relationship workspaces from **different original sources or contexts**. Each original workspace independently passes the exact same file/manifest/HUMAN session review as `verify.py`. It never merges source records, invents shared client identities, extracts evidence-byte contents or touches native LightUp requests. The operator gets a source-ID-free, scriptless private workload board with per-slot local HUMAN question counts, pending stages, outstanding follow-up reason groupings, and aggregate **slot workload** totals. It detects identical repeated source+HUMAN snapshots (HOLD) and highlights repeated original source packet identities across different human sessions to warn against double-counting. This is not an organization-wide set of authenticated distinct cases.

```sh
python3 remediation-evidence-bundle-integrity/portfolio.py \
  --bundle "$HOME/lightup-private/desk-client-A" \
  --bundle "$HOME/lightup-private/desk-client-B" \
  --html "$HOME/lightup-private/receipts/private-workload.html"
```

Or choose **only** `--counts /ABSOLUTE/NEW/SOURCE-FREE.json` for an aggregate local JSON intended for **private** staffing discussions, not public telemetry. Both options require an unused name in an existing owner-only directory. Source filenames, digests, client references, original finding identifiers and private free-text notes are **never exported** into this portfolio. Private per-slot workload counts may still reveal business-sensitive staffing information, so no online publication or public issue attachment is appropriate. Totals sum *local slots*, not unique customers, proven evidence or complete findings. Repeated packet groups are flagged by slot numbers only; no original identity leaves memory.

## Scope and release

No modifications to `src/`, original Evidence Artifact Ledger, Request Desk, native Apply, auth, scanner, scope, evidence files, CI or QA suites. Never feeds data to targets, issues grants, stages client action, changes HUMAN journals, concludes remediation or bypasses action-time revocation. As with the parent draft, **no main merge, production deploy or live use** until existing original exact-head hosted + permanently registered named VPS CI, original source-owner and independent security/privacy/browser/crypto reviews, #177/#182/#829, true independent revocable current client/operator consent and explicit HUMAN GO have all been satisfied. No new release gate is created by this utility.
