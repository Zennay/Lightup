# LightUp PRIVATE HUMAN finding review · 20 October 2026

**INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT-HOLD**. Neither this candidate nor its parent [PR #1611](https://github.com/Zennay/Lightup/pull/1611) is released on `main`. It does not perform active scanning, grant management, vulnerability confirmation, retesting, or automatic disclosure.

## Concrete offline product

The existing **authenticated** tenant selection path `render_client_findings_csv(...)` remains the single mandatory selector. It now feeds an optional private review product: [`src/lightup/finding_export_review.py`](../src/lightup/finding_export_review.py).

`render_client_findings_review(store, ctx, client_id, engagement_id=...)` returns an immutable `PrivateFindingReview` with five fields:
- `csv_text`: the original full-batch guarded, redacted CSV rendered by the existing tenant service.
- `html_text`: a fully scriptless, CSP-restricted offline HUMAN review showing original five CSV columns, reported severity and retest-stage counts. All cells are HTML-escaped; raw evidence, target, arbitrary metadata and tenant ID are **not added** to HTML.
- `summary_json`: PRIVATE machine-readable aggregate severity/retest counts, exact CSV byte SHA and explicit false-only authority flags; no original finding IDs, target or free-text fields. Small groups may still disclose sensitive activity and are NOT anonymous.
- `csv_sha256`: SHA-256 over the exact returned UTF-8 CSV bytes, displayed in HTML to detect representation drift, **not authenticate original source**.
- `finding_count`: admitted exported row count, maximum 128.

The output HTML never loads JavaScript, CSS, external images, fonts or remote resources. It presents native collapsible, initially open HUMAN worklists in reported severity order (critical first) without changing the exact original CSV row order or inventing time chronology. The machine-readable PRIVATE summary contains a reported-severity × retest-stage cross-tab for human workload coordination. It carries a visible HUMAN/HOLD warning; `fixed` remains only an **unverified reported retest label**. Valid international text is retained through the original Unicode guard. Invalid tenant, cross-tenant engagement/record, late-record Unicode, ambiguous formula or over-budget source -> **no CSV/HTML packet returned**. No additional user-controlled field bypasses the original guard.

### Native private output — atomic pair

[`src/lightup/finding_export_review_publish.py`](../src/lightup/finding_export_review_publish.py) provides optional `publish_client_findings_review` for an **already authenticated and authorized** in-process service only. Before touching an output file it performs complete original tenant selection and source CSV admission. It requires an **existing absolute, actual-owner 0700 parent** and a simple new output name. Linux `renameat2(RENAME_NOREPLACE)` atomically publishes one wholly NEW 0700 folder with four 0600 files, or refuses; it never falls back to an overwrite-capable rename:

- `findings.csv`: fully original guarded CSV representation.
- `review.html`: scriptless HTML view bound to the exact CSV SHA.
- `summary.json`: source-bound PRIVATE counts and false-only source/consent/verified-fix/release authority flags.
- `REVIEW_ONLY.txt`: local mandatory HOLD/PRIVATE warning.

Example from an existing **genuine authenticated LightUp service context** (do not construct or simulate `ctx` or bypass original auth):

```python
from lightup.finding_export_review_publish import publish_client_findings_review

output = publish_client_findings_review(
    store, authenticated_ctx, selected_client_id,
    output_parent="/home/operator/lightup-private",
    output_name="review-001",
    engagement_id=selected_engagement_id,
)
# Remains PRIVATE / HUMAN REVIEW ONLY, not approved for external distribution.
```

No network calls or automatic upload occur. File handling is intended only for a trusted local Linux installation; storage permissions and hashes do not prove user identity or disclosure approval. Existing review-holder explicitly authorizes any eventual transfer. The code contains no new tests or QA suite, and actual operator data, browser validation, privacy/security review and exact-head hosted/permanent named VPS CI have not been supplied.

## Original blockers, not bypassed

Parent [#1195](https://github.com/Zennay/Lightup/pull/1195), tenant wiring [#1611](https://github.com/Zennay/Lightup/pull/1611), and other original source owners remain DRAFT/HOLD. Original independent source-owner and privacy/browser/security review, exact-head hosted and permanently named VPS CI, original authorization issues #177/#182/#829, separate genuine current authenticated client/operator consent with use-time revocation as needed, and explicit HUMAN GO remain mandatory before main merge, deployment, scan, or real target interaction. No local SHA, redaction, HTML, CSV, or HUMAN status supplies any of these approvals.

## Actually reopen and compare 2–12 original private HUMAN review snapshots

[`src/lightup/finding_export_review_history.py`](../src/lightup/finding_export_review_history.py) adds an offline HUMAN operator route that **re-admits each native original** four-file `publish_client_findings_review` output. It rejects missing/extra files, symlinks, non-private ownership/modes, altered native scriptless HTML, changed original HOLD notice, noncanonical/native CSV bytes, duplicated displayed IDs, unbound native summary JSON and repeated byte-identical selected snapshots. All original input files remain untouched.

The user selects 2–12 *actually available* private reviews, and explicitly attests that these locally selected files concern the same work scope. Source identity and selection order cannot be independently verified from the deliberately minimized CSV packet. Output is therefore an **operator-selected comparison, not an authenticated chronology or tenant match**.

For each neighboring original selection, the fully native comparison shows:
- `added`: ID only appears in the later *selected* packet, NOT a new actual vulnerability.
- `absent`: ID not present in that later selection; **NEVER interpret as fixed, closed or revoked**.
- `changed`: reported title/severity/retest-stage/remediation field differs; no independent remediation or risk verification.
- `unchanged`: exact five source-selected CSV display columns match. Same ID still does not authenticate the same underlying client finding.

The scriptless `history.html` summarizes differences and previous/later **reported** severity/retest labels without raw target, raw evidence, title or remediation text. `history.json` preserves full private ID-level change classification and SHA-256 of every original CSV. `REVIEW_ONLY.txt` remains mandatory. These are all **PRIVATE** 0600 files in one NEW 0700 folder, created by original Linux atomic NOREPLACE publication after all inputs have been admitted. No network requests, scanner calls, edits to originals or shared workspace promotion.

Example for a locally authorized operator, with an existing owner-private `/home/operator/lightup-private` mode 0700:

```bash
PYTHONPATH=src python3 -m lightup.finding_export_review_history \
  --review-dir /home/operator/lightup-private/review-001 \
  --review-dir /home/operator/lightup-private/review-002 \
  --output-parent /home/operator/lightup-private \
  --output-name comparison-001 \
  --human-confirm-same-scope
```

Original review directory inputs are full native four-file packages, not arbitrary CSVs. The operator must explicitly verify matching tenant/context outside this helper; `--human-confirm-same-scope` records a human claim only and never substitutes for a permission check. When a review source or destination is unsafe, the tool exits **HOLD = 3**. A locally published PRIVATE result exits **REVIEW_ONLY = 2**. There is no release/authorized-execution success code.

These standalone native products are still on a dependent unmerged branch. No QA/regression/tests are authored or run, nor is a real client or browser end-to-end use asserted. Genuine original source owners, exact-head hosted plus permanently named VPS CI, independent privacy/browser/security review, #177/#182/#829, separately authenticated current client/operator consent and use-time revocation, and explicit HUMAN GO remain release gates.
