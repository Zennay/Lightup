# Readable offline LightUp registry history reports

The existing scope-authorization [historical registry review](scope-capability-registry-history-review-20261014.md) outputs machine-readable JSON receipts. For a concise **human-readable, privacy-preserving, non-authorizing** explanation of which declared transitions changed, use:

```bash
python3 scripts/render_scope_registry_history_offline.py baseline.json intermediate.json candidate.json
```

Arguments are **two to sixteen** distinct physical local regular JSON manifest files, in caller-declared chronological order. Identical bytes in different files are permitted; aliases, hardlinks, symlinks, directories, FIFOs, malformed manifests and oversized inputs fail closed. The output is Markdown for an operator; it never queries network, Git, grants, secrets, target permissions or production.

When an intermediate change was later reverted, the Markdown `HOLD` report still lists both transitions as a compact table of canonical capability IDs and fixed field labels. It **never** reproduces capability names/descriptions from untrusted metadata, and source IDs are restricted to safe ASCII identifier characters. Invalid inputs instead emit a generic HOLD report without exposing partial data. A `REVIEW_ONLY` result only means the supplied metadata snapshots compare equal; it does not validate their trust, chronology or completeness.

### Mandatory authority boundary

Every report visibly states **Authority: NONE**. It is **not** a scan/target/tenant authorization, consent proof, grant, permit, merge or deployment approval. Like the underlying CLI, successful identical metadata review returns exit code **3**, while HOLD returns **2**; it never returns 0. The human must independently authenticate manifests, scope/revocation and the actual deployment history.

Use `python3 -m unittest discover -s tests -p test_scope_registry_history_report.py` for targeted regression tests; exact-HEAD hosted CI and the permanent registered VPS remain separate checks. LightUp stays INCUBATE M3/M7, PLAN/LAB ONLY.
