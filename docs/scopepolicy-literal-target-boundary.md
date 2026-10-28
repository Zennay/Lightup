# ScopePolicy literal scope admission — DRAFT/HOLD

LightUp remains INCUBATE M3/M7 / PLAN-LAB ONLY. This is a **production-source security narrowing** candidate, not permission to activate a target, issue a grant, merge or deploy.

## Implemented product behavior

Original ScopePolicy treated Python `ipaddress.is_private` as implicitly lab-authorized, including certain reserved/special-use address space not actually designated as a private lab. The revised policy permits implicit lab decisions only for loopback by default; optional private-lab admission requires `allow_private_lab=True` and stays inside **RFC1918 + IPv6 ULA**: 10/8, 172.16/12, 192.168/16 and fc00::/7. Link-local (169.254/16, fe80::/10) is never automatically lab-trusted, even when the opt-in is set. Explicit network authorization remains separately available subject to the existing public authorization requirement; this patch does NOT authorize new public target identities.

Policy configuration now validates exact boolean switches and all network text before any target branch can be evaluated. Caller-owned built-in sets/lists are copied into immutable host/network collections at construction. Non-string network entries, malformed CIDR values, decorated explicit host identities, multiple DNS root dots and configuration polymorphism cannot silently alter scope membership.

Target host parsing now rejects percentage-encoded host aliases and IPv6 zone/interface suffixes, decorated double-root-dot aliases and the previously truncated bare IPv6 interpretation. Canonical bracketed IPv6 targets, valid one-terminal-root-dot DNS names and literal loopback/private lab targets retain their intentionally bounded semantics. This is purely in-memory syntax: no DNS, sockets or network calls.

## Integration constraints

Own new branch changes only `src/lightup/scope.py` and this document. Original source-owning draft PRs #165/#1290 and independent acceptance branches remain untouched. No QA, regressions or testsuites written or run. AST source syntax inspection is not security signoff. Evaluable source guards are **not** durable client approval, authenticated client/operator consent, action-time revocation, tenant-safe binding, scan authority or release. Existing original exact-head hosted and permanently registered named VPS CI, original #177/#673/#829 source owners, independent security/privacy and explicit HUMAN GO are mandatory before owner-reviewed integration. The PR must remain DRAFT/HOLD.

## Direct legacy authorization admission (second source change)

For an explicitly allowed public host/network, the policy now evaluates only a **canonical built-in** `Authorization` with actual nonempty owner/reference strings and either absent or exact built-in timezone-aware datetime bounds. Boolean, numeric, string or caller-defined datetime objects cannot impersonate an absent bound. Start-after-end fails closed. The policy computes a single UTC instant without calling any untrusted subclass `is_current()` method. This is a direct decision boundary only and NOT durable request/grant or revocation-at-use authentication.


## Critical correction — explicit ownership of a private lab

Previous default `allow_private_lab=True` still trusted every ordinary RFC1918/ULA
address in a generic ScopePolicy, which is inappropriate on cloud/VPC hosts:
private address class does not establish resource ownership. The source now
defaults the opt-in to **False**, excluding arbitrary private targets unless a
trusted caller explicitly constructs a private-lab policy. Also remove all
link-local ranges from implicit admission; unspecified, test-net, benchmarking,
broadcast and reserved addresses are not implicit lab targets. Explicit
network/host authorizations still require their existing separate access rules.
This follows the security goal from #103 and #1422 without granting authority.

## CLI opt-in and exact original authority parsing (product integration)

The generic CLI `scope-check` and `plan` no longer create a broad private-lab policy implicitly. `--allow-private-lab` must be explicitly provided to opt into RFC1918/IPv6 ULA, while the old `--no-private-lab` remains a compatible explicit-deny flag; contradictory flags and type-confused programmatic Namespace booleans are rejected. Existing `LabEvaluationHarness` already passes an explicit opt-in and needs no additional authority.

The original target authority is now inspected before `urlparse` can strip CR/LF/TAB or silently normalize an ambiguous authority. Reject unknown schemes, userinfo, percent escapes, backslashes, malformed/empty/out-of-range TCP ports, unbracketed IPv6, DNS labels outside canonical ASCII syntax, and double-root-dot aliases before assigning any scope. Proper HTTP(S), port/path/query and bracketed IPv6 representations remain accepted only after canonical parsing; none performs network I/O. Explicit CIDRs must carry the actual network address (`strict=True`) instead of expanding address-with-host-bits to a wider set.
