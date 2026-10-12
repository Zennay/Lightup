# W30 — optional bounded UTF-8 input for legacy Finding Markdown

**M3/M7 PLAN-LAB ONLY / DRAFT-HOLD / NO MERGE / NO DEPLOY.**

Parent: original W28 [DRAFT #1206](https://github.com/Zennay/Lightup/pull/1206), immutable `d746c8d2ed2cbc20319d26bda55a90dc8248801e`. New opt-in files only. No edits to source-owned `models.py` (#100), `reporting.py` (#732), W28 original files, default app/routes, DomainStore, main, real client data or target executor.

## Gap and narrow reference

The W28 opt-in `render_checked_findings_markdown` validates exact evidence types and item/count ceilings (128 findings/128 refs), but individual strings can be arbitrarily long, consuming memory in presentation or emitting unexpectedly large Markdown. This is a **synthetic bounded-input resilience concern**, not a proven production denial-of-service or a fixed installed endpoint.

`src/lightup/finding_evidence_markdown_bounded_optin_w30.py` exports `render_bounded_findings_markdown(findings)`. It preflights each complete batch **before rendering**, requires built-in nonempty string types for displayed fields and evidence refs, rejects invalid UTF-8/lone surrogates, enforces provisional `16,384` byte cap per displayed field, `4,096` bytes per ref and `1,048,576` aggregate input bytes. It inherits W28's maximum 128 findings/128 evidence refs and exact enum requirements. Complete snapshots omit metadata and detach caller-owned evidence, then pass to W28 checked renderer. A rejected late item never invokes the renderer; no durable write is attempted.

These counts cover **UTF-8 input** rather than every serialization or Markdown-rendering cost. No streaming allocation guarantee, security/content classification, HTML/Markdown sanitization, URL escaping, secret redaction or authentication is claimed. Compatibility ceilings are provisional pending original owner's historic data analysis.

## Regression and compatibility

`tests/test_finding_evidence_markdown_bounded_optin_w30.py` contains 10 synthetic in-memory `unittest` scenarios: multilingual happy path, empty lists, real UTF-8 byte-vs-character boundaries, oversized IDs/titles/targets/remediations, late-batch total budget, invalid container/item types and Unicode surrogate, enums, snapshot mutation/metadata non-leak, and the intentionally unchanged W28 unbounded-string control.

Reproduce on exact W30 HEAD, including W28 parent tests:

```sh
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_finding_evidence_markdown_bounded_optin_w30.py' -v
PYTHONPATH=src:tests python -m unittest discover -s tests -p 'test_*.py'
```

### Integration and release gates

Tests committed are **not equivalent to tested/passing** until exact-head runtime evidence exists. Original #894/#100/#732 owners must review baseline behavior, real historical compatibility, confidentiality and Markdown escaping; run registered permanent self-hosted `[self-hosted,zcloud,vps]` CI and independent privacy/security review against exact composed current main. No main merge, deployment, production report generator integration, client/target contacts, real remediation, evidence provenance or verified retest without explicit later approval.
