# LightUp #1289 — strict lexical scope identity (opt-in, synthetic-only)

**Phase:** INCUBATE M3/M7 · PLAN/LAB ONLY. **DRAFT/HOLD, NO MERGE, NO DEPLOY.** No public targets, DNS, network listeners, scans, authorized real assets, customer data, accounts or changes to installed tools.

## Source-verified defect class

Legacy `src/lightup/scope.py::ScopePolicy.normalize_host` uses `urlparse` then `parsed.hostname` and ignores raw control characters, userinfo, URL scheme and `parsed.port`. `urllib.parse` silently **strips CR/LF/TAB**, so source input `http://lo\ncalhost` becomes host `localhost` and receives a LOOPBACK approval despite changing the submitted identity; the original policy also classifies `http://operator@localhost`, `http://localhost:notaport` and `http://localhost:65536` as LOOPBACK. `ActivationGate` relies on the returned scope decision to issue LAB_ONLY permits when explicitly enabled. This is a **potential parser-differential authorization boundary**, not a demonstrated exploit of a network adapter or incident involving real systems.

## Actual independent isolated fix

New optional `src/lightup/strict_target_scope_optin.py::StrictTargetScopePolicy` validates the complete **original target text** before calling the unmodified original `ScopePolicy.decide`. It performs **no** DNS/network I/O, assigns no grants and cannot independently issue a permit. The existing scope policy remains authoritative for all decisions.

**Admission rules:**

- Exact `Target` and exact original `ScopePolicy` types, length ≤ 2048, no surrounding/internal ASCII control/whitespace, DEL or backslash.
- Canonical IPv4 literals and **bracketed** IPv6 authorities only (raw unbracketed IPv6 remains denied, preserving legacy policy), strict ASCII hostname labels, simple `host[:port]` / bracketed IPv6 `[v6][:port]` authorities, or explicit HTTP(S) URL only. Bare host with path/query/fragment, arbitrary URI scheme and ambiguous protocol-relative authority refused.
- No userinfo, encoded authority, unknown/ignored IPv6 bracket tails, comma-separated or malformed Host, invalid/missing/zero/oversized port, percent escape or URL fragment. Syntax is checked **before** delegating to legacy normalization; no exceptions/partial acceptance.
- Valid HTTP(S) URL paths and queries may be passed in, but only **canonical hostname** is delegated to original scope matching. DNS names not listed remain out-of-scope; public explicit host/network still requires **current authorization**.
- Existing `ActivationGate` can be constructed with the optional policy object for synthetic future adapter validation, but this PR does **not** alter activation code, default factory, cli, network behavior or environment config.

## Real offline acceptance

New `tests/test_strict_target_scope_optin_1289.py` has **18 independent unit/regression test methods**; add-on `tests/test_strict_target_scope_differential_1289.py` adds **5 more independently seeded and cross-product tests**, including 2,700 reproducible malformed-authority proposals plus a 192-case canonical host/port/scheme matrix, and explicitly checks that every admission remains admitted by the original policy. No external addresses are accessed. They prove the current legacy acceptance of malformed newline/userinfo/invalid ports as negative controls, then prove denial by the optional gate; rejection of control chars, bracket tails, encoding, bad hostname labels, malformed scheme/authority, bad types and no widening from bare unbracketed IPv6; preserved real legacy loopback/private/out-of-scope/public explicit authorization, validity/expiry and no policy widening; and synthetic actual `ActivationGate` LAB_ONLY permit refusal before any target activity, while PLAN_ONLY remains off.

**Source ownership:** this is separate from #1275/#1276 risk-decision persisted lineage and #1284/#1285–#1288 browser response privacy. All existing source files/branches `scope.py`, `activation.py`, `execution_policy.py`, `engagements.py`, `domain.py`, `webapp/*`, `main` and deployment remain untouched. Only **4 new paths** on an isolated feature branch.

## Intentional limitations and gating

- The opt-in adapter does not resolve DNS, pin IPs against rebinding, validate TLS trust, stop SSRF inside independent HTTP clients or prove installed target execution matches normalized host. It also does not validate application-level URL paths. Policy decisions do not demonstrate ownership or constitute legal authorization.
- Public targets are NEVER tested in this PR. Any real deployment/use of active adapters requires separate review of canonical origin/port, resolved IPs, allowlists, current customer-specific grants, execution windows and manual permission.
- Before **any** merge or deployment: independent source-owner+scope/security review, exact-head GitHub-hosted unit/integrations (Python 3.11+3.14), separately registered permanent `[self-hosted,zcloud,vps]` CI on same SHA, composition with latest main, and explicit human release approval. The project remains **DRAFT/HOLD**; previous optional #1284 response work and its 2 unresolved expected failures are not involved here.
