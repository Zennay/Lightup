# W43 — opt-in Markdown Finding lineage cardinality

**M3/M7 PLAN/LAB — DRAFT/HOLD / NO MERGE / NO DEPLOY.** Stack above W42 [DRAFT #1215](https://github.com/Zennay/Lightup/pull/1215) exact parent `51dbc4197a0db704c161320484fd2240c984dfc5`, itself a correction above optional W31 renderer. The only changed source is that optional, uninstalled W31 rendering helper. Neither `models.py`, `reporting.py`, `domain.py`, installed web/CLI, authorization, nor `main` is changed.

## Gap and narrow mitigation

An evidence report can currently display the same `finding_id` twice as separate headings, or list the same exact evidence reference twice for one finding. That can mislead downstream reviewers about the number of independent observations. This is **presentation lineage ambiguity**, not proof of duplicate real evidence, a bypass, nor a security incident.

The optional `render_escaped_evidence_markdown_optin_w31` now checks before report emission:

- **Unique exact string finding IDs throughout a batch**; late duplicate findings fail as one generic evidence-integrity `ValueError`.
- **Unique exact string evidence references within each finding**; references may legitimately be shared **across distinct findings**.
- Existing exact types, grapheme/control checks, order-preserving caller snapshots and provisional UTF-8/batch bounds remain in effect.
- No attempt to normalize ID spelling, silently deduplicate, repair caller data, infer evidence provenance, set a verified status or issue authorization.
- Empty evidence retains the existing explicit fallback. All invalid batches fail **before any Markdown escaping/emission**; no partial report or mutation is permitted.

**Nine synthetic in-memory unittest methods** in `tests/test_finding_markdown_lineage_cardinality_w43.py` cover positive ordered batches, repeated IDs with changed titles, within-record duplicate evidence late in batch, deliberately shared cross-finding evidence, caller metadata nonmutation, empty fallback, exact vs canonically composed Unicode spelling, multiple invalid cases and no status authorization.

Run exact PR head:
```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_markdown_lineage_cardinality_w43.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

Exact-head hosted diagnostics **cannot substitute** permanent registered self-hosted VPS CI. This opt-in reference is not an installed fix to the default renderer; original [issue #894](https://github.com/Zennay/Lightup/issues/894), report ownership #732, model #100, downstream Markdown/privacy/security review, historical ID compatibility, latest-main composition and release approval all remain independent gates. Zero real target/client interaction, scans, grants, persisted remediation, verified retest, merge or deployment.