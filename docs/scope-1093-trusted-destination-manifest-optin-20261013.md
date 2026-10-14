# #1093 — independent opt-in destination role metadata preview

**INCUBATE M3/M7 — PLAN/LAB ONLY. DRAFT / HOLD / NO MERGE / NO DEPLOY.**

This additive, opt-in module addresses issue #1093 independently of the existing branch-only metadata reference. It binds a set of typed HOST, ENDPOINT, PORT and PORT_SET roles to an **exact registered ToolDefinition** and verifies the argument shape, role/kind pairings, ambiguous authorities, and registration snapshots. No other worker paths, production ToolExecutor, policy, registry or workflows are modified.

The preview always returns a frozen `status=hold` receipt with `authorization_verified=false`, `permit_issued=false`, `execution_enabled=false`, `release_approved=false`. It never dispatches a handler, resolves DNS, calls a policy or grant resolver, issues a grant, writes evidence, or contacts a target. The separate #1093 acceptance branch remains unchanged.

Real tool execution **must not** use this preview as approval. Actual source-owner integration still requires current trusted same-engagement/tenant grant, capability, risk, window, revocation, same-authorized-asset destination matching (including DNS and redirects), safe retries, target-scoped egress and pre-I/O revalidation. The optional shape review proves none of these. Optional module is not installed anywhere in the executable ingress.

Unit tests: `PYTHONPATH=src python -m unittest discover -s tests -v`. Require exact-head hosted Python 3.11/3.14 and independent registered permanent VPS Python 3.11/3.14 proofs, source/security/privacy review, latest-main composition and human release decision. CI green never grants execution authority. All test inputs are local/synthetic; no customer data, scanners, real targets, deployments or grant issuance.

## W2 drift hardening (independent follow-up)

After W1, four new adversarial synthetic cases were added: late destination-role mutation, destination-key mutation, registered definition interaction change, and full registry map replacement. The optional preview now pins all of these to its constructor snapshot and denies before issuing even a non-authorizing HOLD receipt. **29 test methods** are staged, but exact final GitHub head CI has not been run; no claim of full repository compatibility. Python reflection and concurrent race resistance are out of scope for this opt-in reference and remain production owner review requirements.

## W3 receipt authority sealing

A further fix makes the preview receipt's four authority flags and HOLD status `init=False` fixed defaults, so callers cannot construct `DestinationReview(..., permit_issued=True)`, `execution_enabled=True`, or `release_approved=True` using the normal constructor. A 30th ordinary test checks constructor rejection. This still is not an authorization decision; Python reflection/substitution outside the preview trust boundary and actual dispatch remain original source-owner concerns. No production activation or target I/O.


## W4 — lexical ambiguity, type-safety, and callback-free denial

The opt-in reviewer now refuses alternative numeric-host authorities (whole-number and `0x`-prefixed forms), duplicate HOST/PORT role declarations across different parameter names, and noncanonical mutable `ToolDefinition`/`ToolParameter` metadata. Exact `RiskLevel`, `ParamKind`, typed strings, bounded descriptions, and preserved captured schema and role/registry identities are required. A substituted parameter tuple is rejected *by identity before tuple equality*, preventing attacker-controlled `__eq__` callbacks from running through an untrusted schema element. This is an independently reproduced correctness bug in the optional reference, not evidence of exploitation of production ToolExecutor.

52 staged synthetic unit cases include opaque denial of mutated or polymorphic metadata, DNS/socket/subprocess/urlopen no-call assertions, bounded-host/URL pre-parse checks, both canonical IPv6 and localhost HOLD controls, and permanent false execution/grant/release fields. A local synthetic module replica test run passed 52/52 on Python 3.13; **not a full canonical-repository or GitHub Actions result**. The branch is deliberately not integrated with production registries, handlers, policies, target adapter, ingress or job queue; no execution authority is conveyed.

### Pending source-owner evidence

- Original #107 executor and #156 registry owners must define/consume trusted destination-role metadata and enforce exact live-authorized asset/destination identity, including egress/retries/redirects, before any I/O.
- Reconcile the independent earlier #1093 branch-only acceptance oracle; do not overwrite or merge that worker's work.
- Confirm a current exact-head repo checkout on Python 3.11 and 3.14, four hosted jobs and two permanent registered `[self-hosted,zcloud,vps]` jobs, matching SHA and logs. Branch-only local checks do not meet release requirements.
- Obtain independent source-owner/security/privacy review, latest-main composition and explicit human release authorization.

**INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY. No grant, target, scanner, DNS/network, production service or workflow dispatch.**


## W5 — canonical endpoint text and Unicode ambiguity

The optional shape review now rejects non-ASCII endpoint input *before* `urllib.parse.urlsplit`, including invisible marks and malformed lone-surrogate URI path text, requiring percent-encoded path bytes instead of parser-specific Unicode normalization. This is a conservative plan/lab reference constraint, **not** a deployed Unicode-path behavior change. Two new tests check rejection and a valid percent-encoded Unicode path that still yields only a HOLD receipt. The local synthetic module-replica run now passes 54/54 on Python 3.13; it is not equivalent to exact-GitHub-code Python3.11/3.14 CI.

The earlier numeric-host, hostile-equality, duplicate-role and non-I/O regressions remain. Exact-head full repository tests, durable authorization, authorized destination binding, registered self-hosted VPS runner evidence and separate independent review are still missing. DRAFT/HOLD, no PR, merge or deploy.


## W6 — exact lexical URL identity admission (2026-10-14)

**Concrete fix:** `urlsplit()` normalizes scheme case and can discard empty query/fragment delimiters. In this independent *non-authorizing* preview, that creates a discrepancy between the originally supplied address and the interpreted address. The opt-in `_endpoint()` now requires an original lowercase `http://` or `https://` scheme, rejects any fragment marker (even an empty one) or trailing empty query delimiter, and requires a byte-for-byte `p.geturl() == original` round trip after parser admission. Legitimate canonical ASCII URI / percent-encoded paths still return only `HOLD`.

**Tests:** Four additional synthetic scenarios exercise mixed-case schemes, empty `#`, empty `?` and canonical explicit query positive controls; another two verify a deliberately rewritten parser return is denied and canonical HTTP/HTTPS/IPv6 endpoints remain HOLD. Together with earlier tests this branch now contains **60 ordinary synthetic test methods**. An independently maintained local Python 3.13 *replica* of this module and lightweight orchestration stubs completed `compileall` and **60/60** `unittest` methods, including new W6 checks. This is a **local synthetic regression signal only, not proof of exact GitHub-file execution, official hosted matrix, source-owner test integration, or permanent VPS**.

### Authority and threat-model limitation

This API accepts a tuple of `DestinationField` declarations provided by its calling code; the preview **cannot prove those declarations originated from a trusted, registered source**. In production this would require a registry-owner review and binding to a canonical registered definition before use. Neither this reviewer nor a valid URL shape establishes tenant consent, live authorization, matching `call.asset`, DNS/redirect/egress confinement, safe dispatch, or a release token. **Never use a HOLD receipt as a permit**. Current integration is intentionally absent; no live targets, scan, grant, deployment or workflow dispatch.

### Unmet acceptance

Source-owner #107/#156 and policy owner #100 must integrate and validate real authority, existing separate #1093 metadata acceptance branch must be reconciled without overwriting it; exact-head hosted Python 3.11 and 3.14, registered permanent VPS CI, independent security/privacy, latest-main compatibility and explicit human authorization remain required. Project remains **INCUBATE M3/M7 · PLAN/LAB ONLY · DRAFT/HOLD/NO MERGE/NO DEPLOY**.
