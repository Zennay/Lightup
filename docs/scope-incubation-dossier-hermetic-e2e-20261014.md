# LightUp real dossier CLI: hermetic mutation + no-effect canaries (#1368)

This test-only follow-on targets the **actual installed offline
incubation dossier command**, not merely an in-process mocked review
function. It does not alter LightUp's runtime API or grant authority.

## Distinct real-world boundary

The 14 executable regressions run
`scripts/review_scope_incubation_dossier_offline.py` with `runpy` in
isolated child Python interpreters. Each child hooks network/DNS,
filesystem/OS mutations, SQLite connections and child-process launch
**before** importing the real CLI, and makes any attempted operation
emit an uncaught-by-test explicit attempt marker even if the CLI
swallows the exception. Bytecode cache writes are disabled.

The child injects a **disposable in-memory** `get_capabilities()`
fixture, simulating one current-source registry drift at a time:
name, description, both fields together, ordinary state, sensitive
lab state, disabled activation, added/removed capabilities, malformed
registry type, noncanonical source text and script-like descriptions.
The real exporter and all three real reviewers then run against
that mutated registry. Nothing persists between children.

## Expected outcomes

- Unchanged local source: `REVIEW_ONLY` exit **3**, all three
  review components agree, five authority flags false.
- Any reviewed field or capability state/membership/activation drift:
  `HOLD` exit **2**, fixed/ordered canonical ID+field/code receipts
  and zero authority; secret fixture text is never echoed.
- Invalid input: **atomic HOLD** with a generic fixed reason and
  no untrusted source text.
- Target-like or execution-like CLI arguments: **HOLD** with
  zero target/port/socket/HTTP/DB/process/file side effects.
- All outputs are non-success exit codes: neither metadata
  inspection nor its receipt can be chained as a runtime grant.

Run from checkout root:

```bash
python3 -m unittest discover -s tests -p 'test_scope_incubation_dossier_hermetic_e2e_20261014.py' -v
```

This instrumentation is a regression safety canary, **not** an OS-level
sandbox, signed release attestation, verified origin, tenant consent,
trusted authorizing grant, actual scope executor guard or user approval
for live target assessment. A malicious native extension bypassing
Python hooks is out of scope. No real targets, customers, scanning,
production deployment, VPS or network actions are performed.

Only new test/docs paths. All active source, grant, StateStore,
ToolExecutor, networking, CI and runner owners remain untouched.
