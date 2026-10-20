# LightUp M3/M7 · CSV presentation-integrity preflight (2026-10-11 W1)

**DRAFT / HOLD — opt-in and offline only.** Work for issue [#1182](https://github.com/Zennay/Lightup/issues/1182). Base is immutable `main=dd4072cdd1a2bc44a752ccbb7b1d0b6d56559da1`, with four unique **add-only** paths; no modification to live finding sources, tenant export, authorization, web, CI, scanner or concurrent producer owners.

## Confirmed source-level limitation

`finding_export._cell` guards ordinary ASCII formula prefixes and leading whitespace or low ASCII controls. It has no Unicode display-integrity preflight: an invisible `U+200B` or bidirectional override can be retained in serialized CSV source, and a visually disguised fullwidth formula token such as `U+FF1D` is not detected before display. Source acceptance is observable offline; **no spreadsheet exploitability or installed-system exposure has been shown**.

## Opt-in response

`render_findings_csv_checked` validates an exact built-in list of <=128 exact `Finding` objects, each with exact `Severity`/`RetestStatus` enums. It bounds UTF-8 input bytes (256 KiB across all projected fields, individual field caps of 256/8192/2048/8192), rejects ill-formed/empty/polymorphic cells, duplicate or NFKC-equivalent display identities, control/format/private/unassigned Unicode, and Unicode line separators. It catches NFKC-equivalent formula prefixes that the existing renderer's ordinary ASCII escape decision would miss.

A full preflight precedes *any* serializer call. Only display inputs are copied into fresh `Finding` objects before invoking the **existing redacting and ASCII-formula-escaping renderer**; the original mutable findings, raw evidence and metadata are not passed to the renderer. Good international text remains verbatim, including accents and combining marks. Intentional multiline text is conservatively **rejected** by this strict opt-in path, while default legacy export behavior is unchanged.

## Tests

```bash
PYTHONPATH=src python -m unittest -v tests.test_finding_export_unicode_integrity_20261011_w1
PYTHONPATH=src python -m unittest discover -s tests -v
```

Tests use synthetic findings only: late-item atomic rejection with mock call count, literal ASCII formula escaping, Unicode confusables, all four projected identities/fields, excluded metadata/evidence/target, exact-type negatives, UTF-8 byte budgets, and copy-before-render mutation isolation. The NFKC-equivalent identity cases enforce *unambiguous display*, not canonical source identity or evidence authenticity. The default renderer's acceptance of an invisible prefix is retained as a **known gap demonstration**, not asserted to be an actual executed spreadsheet formula.

## W2: real tenant-service synthetic proof

`tests/test_finding_export_unicode_service_20261011_w2.py` creates **disposable** real `DomainStore` clients, engagements and findings. Its four independent regressions confirm the existing authenticated tenant-scoped service produces a CSV cell with a retained invisible prefix, keeps A/B tenants apart, honours an exact engagement filter, leaves SQLite bytes unchanged, and that the opt-in projected checker refuses the same persisted synthetic finding **before calling the renderer**. This is not a spreadsheet exploit or a fix to the canonical production exporter. Trusted authentication and source ownership remain external.

## Stop line / integration ownership

- This wrapper is **not** wired to tenant selection, web downloads, CLI, or `render_findings_csv` default; app consumers remain unchanged.
- It does **not** verify sessions, tenant ownership, human disclosure approvals, evidence integrity or authenticity, CSV viewer compatibility, complete secret redaction, remediation results or retest outcomes.
- Source-owner coordination required with existing tenant/export and web PRs (#960–#965 and #1068). No promotion until default entrypoint is reviewed and integrated with ordinary passing tests, independent privacy/security review and exact-final-SHA hosted **and genuine permanent self-hosted LightUp VPS** acceptance. A queued or hosted-only CI run is not VPS proof.
- Never conduct external-model calls, network scans, target interaction, authority grants, actual fixes/retests, production DB writes, deployment or runner configuration changes for this proposal.
