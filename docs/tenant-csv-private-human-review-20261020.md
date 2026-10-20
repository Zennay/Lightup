# LightUp PRIVATE HUMAN finding review · 20 October 2026

**INCUBATE / M3-M7 PLAN-LAB ONLY / DRAFT-HOLD**. Neither this candidate nor its parent [PR #1611](https://github.com/Zennay/Lightup/pull/1611) is released on `main`. It does not perform active scanning, grant management, vulnerability confirmation, retesting, or automatic disclosure.

## Concrete offline product

The existing **authenticated** tenant selection path `render_client_findings_csv(...)` remains the single mandatory selector. It now feeds an optional private review product: [`src/lightup/finding_export_review.py`](../src/lightup/finding_export_review.py).

`render_client_findings_review(store, ctx, client_id, engagement_id=...)` returns an immutable `PrivateFindingReview` with four fields:
- `csv_text`: the original full-batch guarded, redacted CSV rendered by the existing tenant service.
- `html_text`: a fully scriptless, CSP-restricted offline HUMAN review showing original five CSV columns, reported severity and retest-stage counts. All cells are HTML-escaped; raw evidence, target, arbitrary metadata and tenant ID are **not added** to HTML.
- `csv_sha256`: SHA-256 over the exact returned UTF-8 CSV bytes, displayed in HTML to detect representation drift, **not authenticate original source**.
- `finding_count`: admitted exported row count, maximum 128.

The output HTML never loads JavaScript, CSS, external images, fonts or remote resources. It carries a visible HUMAN/HOLD warning; `fixed` remains only an **unverified reported retest label**. Valid international text is retained through the original Unicode guard. Invalid tenant, cross-tenant engagement/record, late-record Unicode, ambiguous formula or over-budget source -> **no CSV/HTML packet returned**. No additional user-controlled field bypasses the original guard.

### Native private output — atomic pair

[`src/lightup/finding_export_review_publish.py`](../src/lightup/finding_export_review_publish.py) provides optional `publish_client_findings_review` for an **already authenticated and authorized** in-process service only. Before touching an output file it performs complete original tenant selection and source CSV admission. It requires an **existing absolute, actual-owner 0700 parent** and a simple new output name. Linux `renameat2(RENAME_NOREPLACE)` atomically publishes one wholly NEW 0700 folder with three 0600 files, or refuses; it never falls back to an overwrite-capable rename:

- `findings.csv`: fully original guarded CSV representation.
- `review.html`: scriptless HTML view bound to the exact CSV SHA.
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
