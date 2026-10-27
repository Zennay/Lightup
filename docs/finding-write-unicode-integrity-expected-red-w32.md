# W32 — Persisted Finding evidence Unicode input acceptance (expected RED)

**M3/M7 PLAN/LAB ONLY — DRAFT/HOLD/NO MERGE/NO DEPLOY.** Immutable parent is original [write-side draft #857](https://github.com/Zennay/Lightup/pull/857) current head \`3187c3c715eac7dd0d7772cf572cc175b8324b02\`, itself stacked on #828. This slice adds tests and this note **only**. No edits to \`src/lightup/domain.py\`, canonical persistence, web, runner, main, or other worker files.

## Scope of negative evidence

#851/#857 validates only exact tuples and exact nonblank strings on write. It can still persist visually non-perceptible or unserialisable historical evidence IDs because \`str.strip()\` does not establish identity readability. Later read/export and opt-in #856/#886/#1205 and Unicode identity guards may reject them; a write-accepted record must not unexpectedly become a corrupt legacy row.

The six explicit \`@unittest.expectedFailure\` regressions currently call real disposable \`DomainStore.record_finding()\` and assert fail-closed **before durable insertion** for:

- Isolated combining-mark reference U+0301.
- Isolated variation selector U+FE0F.
- Isolated bidi override U+202E.
- Lone unpaired surrogate reference U+D800.
- Evidence identifier longer than the provisional 4,096-byte read-side allowance.
- Two distinct byte strings with NFKC-equivalent evidence identities.

These expectations intentionally extend #851's original narrow exact-type contract. The historical compatibility and normalization rules must be agreed with the canonical #828/#857/#856 owner and Unicode reference identity #1207 before any production write-side change. Unicode equivalence is not proof of real evidence spoofing.

Two positive methods preserve international evidence text/order and intentional empty manual evidence. Every rejected-case assertion checks raw SQLite finding rows do not change, rather than relying on exceptions alone. The current expected REDs are test contracts, **not green fixed behavior**; a true repair should remove the \`expectedFailure\` decorators only after actual write-path denial is verified. Never merge the expected-red-only branch directly to main.

## Isolated verification

\`\`\`sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_write_unicode_integrity_red_w32.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
\`\`\`

Hosted diagnostics remain distinct from registered permanent self-hosted VPS CI. Implementation ownership, historical compatibility, auth/privacy, all tenant read consumers, exact-head full CI and current-main composition/release approval remain HOLD. No target, customer data, credential, remediation/retest, authorization grant, scanning or deployment.
