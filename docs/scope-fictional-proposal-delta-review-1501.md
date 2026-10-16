# LightUp #1501 — strictly synthetic scope proposal change review

**Phase: INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD.** This is an isolated, source-unwired, in-memory review aid for *fictional* operator-facing scope proposals. It does not process, mint or validate an actual `Authorization`, `AuthorizationGrant`, `ExecutionPermit`, approval, consent or grant. It must NEVER be wired into production dispatch based on its output.

## Usage: local Python, no input/output side effects

```python
from datetime import datetime, timezone, timedelta
from lightup.fictional_scope_delta_review_1501 import FictionalScopeProposal, review_fictional_scope_delta

now = datetime(2026, 11, 1, tzinfo=timezone.utc)
prior = FictionalScopeProposal(
    assets=("alpha.example.test", "beta.example.test"),
    capabilities=("headers_view", "metadata_view"),
    exclusions=(), risk=3,
    valid_from=now, valid_until=now + timedelta(days=2),
)
later = FictionalScopeProposal(
    assets=("alpha.example.test",),
    capabilities=("headers_view",),
    exclusions=(), risk=2,
    valid_from=now, valid_until=now + timedelta(days=1),
)
result = review_fictional_scope_delta(prior, later)
assert result.status == "REVIEW_ONLY"  # NOT AUTHORIZED, still requires humans
assert not result.authorized and not result.dispatch_allowed
```

The helper validates **exact** built-in immutable proposal dataclasses, sorted/unique tuple fields, up to 16 single-label fictional `*.example.test` hosts, 4 nonactive review-only capability labels, 1–5 exact integer risk, at most 31-day second-precision UTC windows (years 2020–2100), exclusions confined to listed assets and no Unicode/case folding or string coercion. Bad or ambiguous records return generic `HOLD` without echoing identifiers. Expansion of assets/capabilities, removal of exclusions, higher risk, earlier start or later end also yields `HOLD` with only fixed dimension names. Narrowing or equality yields `REVIEW_ONLY`, never consent. Exclusions on assets removed in a later proposal intentionally cause `HOLD` for human reconciliation rather than guessing the desired change. If the producer uses real hosts, the helper must HOLD.

No network requests, DNS, subprocesses, filesystem reads/writes, database calls, target dispatch, active security scans or permissions are performed. Outputs have immutable four literal `False` flags. This is *not* a DLP scanner; input source and provenance are untrusted. A successful review does not prove either proposal was ever legitimately approved.

Run independent tests: `PYTHONPATH=src python -m unittest tests.test_fictional_scope_delta_review_1501 -v`. The isolated CI workflow runs only these synthetic tests on Python 3.11 and 3.14. The original full CI and truly registered permanent VPS runner are **separate gates**, not substituted by this workflow.

## Historical (A → B → A) widening guard

Use `review_fictional_scope_history((proposal_v1, proposal_v2, ...))` on a **fixed-size exact tuple of 2–16 wholly synthetic snapshots**. Merely comparing two endpoint records is insufficient: an intermediate scope expansion followed by rollback (A → B → A) must remain a HOLD for reviewer reconciliation. The history helper first validates every snapshot before evaluating a single transition, rejecting invalid later entries **atomically** with a generic HOLD and no partial metadata. It then checks *each adjacent step* for new assets/capabilities, removed exclusions, increased risk, earlier start or later end; any expansion leads to HOLD with only bounded fixed dimension names and the first 1-based transition index. No customer identifiers, provenance, raw values or interim approval claims appear in its result.

Even a fully monotonically narrowed chain produces only `REVIEW_ONLY`, NEVER approval; all four authorization, consent, dispatch and release flags remain literal false. History is caller-supplied and untrusted, not an audit log, trusted grant provenance, authenticated version chain or actual execution safety proof. No wall clock, file/DB/network/process activity, mutations or external integrations.

```python
from lightup.fictional_scope_delta_review_1501 import review_fictional_scope_history
widened_then_rolled_back = (prior, prior.__class__(
    assets=prior.assets, capabilities=prior.capabilities,
    exclusions=prior.exclusions, risk=4,
    valid_from=prior.valid_from, valid_until=prior.valid_until,
), prior)
assert review_fictional_scope_history(widened_then_rolled_back).status == "HOLD"
```

## Independent stdin-only reviewer (opt-in and non-authorizing)

A separate, wholly new `python -m lightup.fictional_scope_delta_cli_1501 --offline-review-only` entry point accepts **only** a bounded ASCII, key-sorted compact V1 JSON document from standard input. It intentionally does not read named files or trust any authorization or client record. Required top-level keys are `contract` (`FICTIONAL-SCOPE-HISTORY-1501-V1`) and `history` (two through sixteen exact fictional proposal snapshots with six exact keys). UTC times are second-precision `YYYY-MM-DDTHH:MM:SSZ`; tuples on the in-memory API are encoded as JSON arrays. Maximum complete input 32,768 bytes with zero or exactly one final LF. Duplicate keys, Unicode, unknown fields, credentials, forged approval labels, oversized input, floats/NaN, unsupported JSON serialization and real/noncanonical assets all produce generic HOLD. **Do not paste real hostnames, secrets or clients into this experimental CLI:** it is not a general DLP guarantee.

The only two process exit codes are **2 = REVIEW_ONLY** (syntactic fictional history review, NOT permission) or **3 = HOLD** (reconciliation needed). Exit zero is never success; strict JSON output has only fixed metadata, a bounded transition count/first hold step, fixed dimension names and four literal false fields (`authorized`, `consent_verified`, `dispatch_allowed`, `release_allowed`). No input hostnames, emails, raw source, scope grants, target secrets or pasted text are echoed in either output. Documentation and tests exercise a genuine subprocess on both Python versions, malformed JSON/Unicode/credentials, scope widening and A→B→A rollback. This command has **no authenticated provenance, release authority, I/O side channel assurance or production runtime bindings**.

## Ownership, limitations, handoff

This separate additive PR neither edits nor overrides source owners: real grant amendment and live monotonicity are already tracked by #951/#1433 and #346/#1240; operator-facing notice #1495 and privacy quarantine #1497 have other owners; source AST inventory #1499 has another owner. Any integration must be independently designed and reviewed by original scope-policy, security and privacy owners and must preserve genuine client **and** operator consent, trusted provenance, durable revocation-at-use, actual asset/capability/risk/time binding and absence of TOCTOU. Known original #301 expired fixture, full current hosted CI and canonical runner issue #1144 remain blockers.

**Do not merge, deploy, scan, issue real grants, execute handlers, assume consent or release** until full independent code/security/privacy approval, genuine permissions and revocation, verified complete original hosted and genuinely assigned registered VPS CI, and explicit human GO. All outcomes are DRAFT/HOLD.
