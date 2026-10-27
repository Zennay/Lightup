# LightUp operator Markdown incubation review (#1372)

## Why this exists

The three-checker source-local capability dossier currently produces
machine-readable JSON only. This new read-only report turns the
**same bounded local metadata decision** into a concise human-facing
Markdown receipt: check status, fixed SHA-256 fingerprint when valid,
and a list of canonical capability IDs + fixed violation labels.

No human-readable capability name, description, tenant, grant, network
target, customer content, URL or free-text untrusted metadata is emitted.

## Operator usage

```bash
python3 scripts/render_scope_incubation_dossier_offline.py
python3 -m unittest discover -s tests -p 'test_scope_incubation_markdown_operator_20261014.py' -v
```

Example operator semantics:

- `REVIEW_ONLY`, process exit **3**: all three independent incubation
  metadata checkers match reviewed source assumptions. **It is not
  permission** for a tool, scan, merge, grant, release or deployment.
- `HOLD`, process exit **2**: catalog/activation/lab/semantic metadata
  changed, or invalid/inconsistent input. Operator review needed. The
  report includes only safe fixed labels for valid-but-changed content.
  Completely invalid/corrupt manifests have no fingerprint and no
  partial details; known fixed status text only.
- All rendered documents begin with **Authority: NONE.** and an
  explicit no-execution statement; there is never a success/zero exit.
- No source-local CLI accepts paths, targets, URLs or flags.

The renderer consumes only `review_atomic_incubation_dossier(raw)`,
whose three independent checks and consistency requirements already
exist on main. It *again* checks component status, canonical
identifiers and code vocabularies before formatting Markdown, so a
forged/invalid reviewer return cannot inject Markdown/HTML/customer
text or fake a REVIEW_ONLY report. Reports are bounded to 32 KiB.

## Security verification and limits

22 tests cover actual 31-entry source, all three clean gate states,
name/description-only drift, public/lab reclassification, disabled
activation, unknown/missing capability, malformed bytes/legacy shape,
HTML and private-text redaction, forged green/identifier/fingerprint
output, stable report ordering, and real CLI nonzero/argument rejection.

This is a **developer metadata review aid**, not a runtime
authorizing guard, independently signed provenance, operational
release readiness, live revocation validation, proof of customer
ownership, or OS sandbox. No active tests, grant state changes, target
I/O, write operations or deployment. Only four new source/CLI/test/docs
paths are added, leaving all active authority/runtime/tenant/
StateStore/worker/workflow owners' files unchanged.
